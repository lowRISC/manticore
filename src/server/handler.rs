// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A framework for building `manticore` servers in "handler" style.
//!
//! Servers are complicated. We'd like the server implementation code to only
//! handle the runtime representations of commands, with minimal boilerplate,
//! so that implementing new commands and understanding how the server is
//! implemented is simple.
//!
//! This module provides a fully `no_std` framework for writing such handlers,
//! using the `Handler` type. A sample use looks something like this:
//! ```text
//! let server = ...;  // Your "server context" type.
//! let req = ...;     // A `Read` with an incoming message.
//! let resp = ...;    // A `Write` to write a response to.
//! Handler::<Server>::new()
//!   .handle::<MyCommand, _>(|ctx| {
//!     // Do stuff...
//!     Ok(response)
//!   })
//!   // ...
//!   .run(server, req, resp)
//! ```
//! This defines a request handler; nothing happens until `run()` is called.
//! When called, `run()` performs the following steps:
//! - It parses a `protocol::net::Header` out of `req`, asserting that the header
//!   has the request bit set.
//! - It selects a `.handle<MyCommand, _>()` call, such that
//!   `MyCommand::Req::TYPE` matches the header's command type (if multiple
//!   handlers could match, an unspecified one is chosen).
//! - It parses the rest of `req` as a `MyCommand::Req`, and passes it and the
//!   server context into the closure.
//! - The closure executes, which returns
//!   `Result<MyCommand::Resp, protocol::Error<MyCommand::Error>>`.
//! - The resulting response or error is sent using `resp`.
//! - If no handler is chosen, an error is returned.
//!
//! This module is not part of `manticore`'s API.
//!
//! ## How it works
//!
//! Suppose we have types `A, B, C: Command<'req>` which we want to handle, so
//! we write the following code:
//! ```text
//! Handler::<Server>::new()
//!   .handle::<A, _>(...)
//!   .handle::<B, _>(...)
//!   .handle::<C, _>(...)
//! ```
//! `.handle()` is a combinator, implemented by both `Handler` and its return
//! type. The resulting type of this expression is something like
//! `Cons<Cons<Cons<Handler<Server>, A, ?0>, B, ?1> C, ?2>`,
//! where the `?n` types denote anonymous closure types. When we go ahead and
//! call `.run()`, this triggers parsing of the header, which is fed to the
//! outermost `Cons`. If the command type doesn't match `C::REQ_TYPE`, it
//! recurses into the inner `Cons`'s `run_with_handler()`.
//!
//! If execution ever reaches the inner `Handler<Server>`, which acts as the
//! "nil" for this linked list, we produce an error: this is our `_` case.
//!
//! In practice, this can be optimized very well by the compiler, reducing to
//! the obvious sequence of branch instructions. If two handlers have the
//! same command type for the request, latter one is picked. In practice, this
//! is irrelevant, because no two handlers can meaningfully have the same
//! command type.

use core::marker::PhantomData;

use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::net;
use crate::protocol;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire as _;
use crate::protocol::CommandType;
use crate::protocol::Request as _;
use crate::protocol::Response as _;

/// A `*`-importable prelude that pulls in only the names that are necessary
/// to make `Handler` work.
pub mod prelude {
    pub use super::Handler;
    pub use super::HandlerMethods;
}

/// An error returned by a request handler.
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Indicates an error originating from a network connection.
    Network(net::Error),

    /// Represents a failure during marshalling.
    Wire(wire::Error),

    /// Indicates that a request message was too long: after successful parse
    /// of a header and a body, we still had unread bytes remaining, indicating
    /// a message decoding problem.
    ///
    /// The error contains the number of superfluous bytes in the buffer.
    ReqTooLong(usize),

    /// Indicates that a request could not be handled, because no handler was
    /// provided for it.
    UnhandledCommand(CommandType),
}

impl From<wire::Error> for Error {
    fn from(e: wire::Error) -> Error {
        Error::Wire(e)
    }
}

impl From<net::Error> for Error {
    fn from(e: net::Error) -> Error {
        Error::Network(e)
    }
}

/// A request handler builder.
///
/// See the module documentation for more information.
///
/// Note: the type parameter on this type is only necessary to make type
/// inference work out. It can be left off, but rustc will complain about
/// missing type annotations.
pub struct Handler<Server> {
    _ph: PhantomData<fn(Server)>,
}

impl<Server> Handler<Server> {
    /// Creates a new, default `Handler`.
    pub fn new() -> Self {
        Self { _ph: PhantomData }
    }
}

/// A handler for a specific command type.
///
/// The name "handler cons" comes from the fact that the type that
/// `run()` is eventually called on looks like a linked list of
/// `HandlerMethods` implementations.
///
/// If `REQ_BUFFER` is true, this represents the output of
/// [`HandlerMethods::handle_buffered()`].
pub struct Cons<Prev, Command, F, const REQ_BUFFER: bool> {
    prev: Prev,
    handler: F,
    _ph: PhantomData<Command>,
}

mod sealed {
    /// A public-in-private trait, for ensuring outside users cannot
    /// accidentally implement `HandlerMethods`.
    pub trait Sealed {}
}

// Helpers for working with `for<'a> Command<'a>`.
//
// See the comment on the `where` clause of `HandlerMethods::handle`.
#[doc(hidden)]
pub type ReqOf<'a, C> = <C as protocol::Command<'a>>::Req;
#[doc(hidden)]
pub type RespOf<'a, C> = <C as protocol::Command<'a>>::Resp;
#[doc(hidden)]
pub type ErrOf<'a, C> = protocol::Error<<C as protocol::Command<'a>>::Error>;

/// Context for a request, i.e., all relevant variables for handling a request.
pub struct Context<'req, Buf, Req, Server> {
    pub req_buf: Buf,
    pub req: Req,
    pub server: Server,
    pub arena: &'req dyn Arena,
}

/// The core trait that makes handler building possible.
///
/// The lifetime `'req` represents the lifetime of the request. This lifetime
/// must be placed here to ensure that all inputs into a request handling
/// operation (including the `FromWire` and `Command` traits, which have
/// lifetimes in them) have a single, coherent lifetime.
pub trait HandlerMethods<'req, 'srv, Server: 'srv>:
    Sized + sealed::Sealed
{
    /// Attaches a new handler function to a `Handler`.
    ///
    /// This function should be called as `.handle::<Command, _>(...)` to make
    /// type inference work; the second type paramter can't be named, since
    /// it will be a closure type.
    fn handle<'out, C, F>(self, handler: F) -> Cons<Self, C, F, false>
    where
        // The following line is a workaround the fact that Rust does not allow
        // the syntax `type Assoc<'a>;` in traits (this feature is sometimes
        // called "Generalized Associated Types"). This feature is likely to
        // make it into the langauge at some point.
        //
        // What we would *like* to have is for `Command` to have no parameters,
        // and for the `Req` and `Resp` associated types to have lifetime
        // parameters, e.g., `type Req<'a>: Request<'a>;`. We would then write
        // `FnOnce(Server, C::Req<'req>) -> Result<C::Resp<'out>, Error>`.
        //
        // Since this is not possible today, we have the following workaround:
        // - `Command` has a lifetime parameter, and has associated types like
        //   `type Req: Request<'a>;`.
        // - We require that a `Command`-implementing type blanket-implement it
        //   for *all* lifetimes. Since `Command` implementations are just
        //   marker types, this is fine; they have no lifetimes in them, either.
        // - Given this, we can write `C: for<'c> Command<'c>` (i.e., `C`
        //   implements *every* Command<'c>), and, in lieu of `C::Req<'req>`,
        //   we can write `<C as Command<'c>>::Req` to access a particular
        //   implementation. `ReqOf<>` and `RespOf<>` are type-alias shortcuts
        //   for this syntax.
        //
        // The reason to want to do this in the first place is because we want
        // the output of the handler function to be potentially shorter than
        // the request lifetime: in particular, we want to allow for
        // `'req: 'srv`. The resulting response value doesn't need to live very
        // long at all, since it gets immediately serialized into the response
        // buffer.
        //
        // Once we have GATs, we can make a breaking change to eliminate this
        // kludge.
        C: for<'c> protocol::Command<'c>,
        F: FnOnce(
            Context<'req, (), ReqOf<'req, C>, Server>,
        ) -> Result<RespOf<'out, C>, ErrOf<'out, C>>,
        'srv: 'out,
        'req: 'out,
    {
        Cons {
            prev: self,
            handler,
            _ph: PhantomData,
        }
    }

    /// Like `handle()`, except it buffers the incoming command completely.
    fn handle_buffered<'out, C, F>(self, handler: F) -> Cons<Self, C, F, true>
    where
        // See above for an explanation of these bounds.
        C: for<'c> protocol::Command<'c>,
        F: FnOnce(
            Context<'req, &'req [u8], ReqOf<'req, C>, Server>,
        ) -> Result<RespOf<'out, C>, ErrOf<'out, C>>,
        'srv: 'out,
        'req: 'out,
    {
        Cons {
            prev: self,
            handler,
            _ph: PhantomData,
        }
    }

    /// The "real" run function.
    #[doc(hidden)]
    fn run_with_header(
        self,
        server: Server,
        header: net::Header,
        request: &mut dyn net::host::HostRequest<'req>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error>;

    /// Executes a `Handler` with the given context.
    ///
    /// See the module-level documentation for more information.
    #[inline]
    fn run(
        self,
        server: Server,
        host_port: &mut dyn net::host::HostPort<'req>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error> {
        let request = host_port.receive()?;
        let header = request.header()?;
        self.run_with_header(server, header, request, arena)
    }
}

impl<Prev, Command, F, const B: bool> Cons<Prev, Command, F, B>
where
    Command: for<'c> protocol::Command<'c>,
{
    #[inline]
    fn run_inner<'out, Ctx>(
        self,
        request: &mut dyn net::host::HostRequest,
        ctx: Ctx,
    ) -> Result<(), Error>
    where
        F: FnOnce(Ctx) -> Result<RespOf<'out, Command>, ErrOf<'out, Command>>,
    {
        match (self.handler)(ctx) {
            Ok(msg) => {
                let header = net::Header {
                    command: RespOf::<'out, Command>::TYPE,
                };

                let reply = request.reply(header)?;
                msg.to_wire(reply.sink()?)?;
                reply.finish()?;
                Ok(())
            }
            Err(err) => {
                let header = net::Header {
                    command: CommandType::Error,
                };

                let reply = request.reply(header)?;
                err.to_wire(reply.sink()?)?;
                reply.finish()?;
                Ok(())
            }
        }
    }
}

impl<'req, 'srv, 'out, Server, Prev, Command, F>
    HandlerMethods<'req, 'srv, Server> for Cons<Prev, Command, F, false>
where
    // See `HandlerMethods::handle` for an explanation of these
    // where-clauses.
    Server: 'srv,
    Prev: HandlerMethods<'req, 'srv, Server>,
    Command: for<'c> protocol::Command<'c>,
    F: FnOnce(
        Context<'req, (), ReqOf<'req, Command>, Server>,
    ) -> Result<RespOf<'out, Command>, ErrOf<'out, Command>>,
{
    #[inline]
    fn run_with_header(
        self,
        server: Server,
        header: net::Header,
        request: &mut dyn net::host::HostRequest<'req>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error> {
        if header.command != ReqOf::<'req, Command>::TYPE {
            // Recurse into the next handler case. Note that this cannot be
            // `run`, since that would re-parse the header incorrectly.
            return self.prev.run_with_header(server, header, request, arena);
        }

        let req = FromWire::from_wire(request.payload()?, arena)?;

        let ctx = Context {
            req_buf: (),
            req,
            server,
            arena,
        };
        self.run_inner(request, ctx)
    }
}

impl<'req, 'srv, 'out, Server, Prev, Command, F>
    HandlerMethods<'req, 'srv, Server> for Cons<Prev, Command, F, true>
where
    // See `HandlerMethods::handle` for an explanation of these
    // where-clauses.
    Server: 'srv,
    Prev: HandlerMethods<'req, 'srv, Server>,
    Command: for<'c> protocol::Command<'c>,
    F: FnOnce(
        Context<'req, &'req [u8], ReqOf<'req, Command>, Server>,
    ) -> Result<RespOf<'out, Command>, ErrOf<'out, Command>>,
{
    #[inline]
    fn run_with_header(
        self,
        server: Server,
        header: net::Header,
        request: &mut dyn net::host::HostRequest<'req>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error> {
        if header.command != ReqOf::<'req, Command>::TYPE {
            // Recurse into the next handler case. Note that this cannot be
            // `run`, since that would re-parse the header incorrectly.
            return self.prev.run_with_header(server, header, request, arena);
        }

        // Buffer the entire request payload; from_wire below will zero-copy
        // read it.
        let r = request.payload()?;
        let req_buf = arena
            .alloc_slice::<u8>(r.remaining_data())
            .map_err(wire::Error::from)?;
        r.read_bytes(req_buf).map_err(wire::Error::from)?;

        // Note: `{ req_buf }` produces a copy of req_buf, so that the from_wire
        // argument becomes an rvalue. Thus, `from_wire` does not mutate the
        // original `req_buf` that gets passed to `run_inner()`.
        let req_buf: &'req [u8] = req_buf;
        let req = FromWire::from_wire(&mut { req_buf }, arena)?;

        let ctx = Context {
            req_buf,
            req,
            server,
            arena,
        };
        self.run_inner(request, ctx)
    }
}

impl<'req, 'srv, Server: 'srv> HandlerMethods<'req, 'srv, Server>
    for Handler<Server>
{
    #[inline]
    fn run_with_header(
        self,
        _: Server,
        header: net::Header,
        _: &mut dyn net::host::HostRequest<'req>,
        _: &'req dyn Arena,
    ) -> Result<(), Error> {
        Err(Error::UnhandledCommand(header.command))
    }
}

impl<P, C, F, const B: bool> sealed::Sealed for Cons<P, C, F, B> {}
impl<S> sealed::Sealed for Handler<S> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::Cursor;
    use crate::mem::BumpArena;

    const VERSION1: &[u8; 32] = &[2; 32];
    const VERSION2: &[u8; 32] = &[5; 32];

    fn simulate_request<
        'a,
        C: protocol::Command<'a>,
        T: 'a,
        H: HandlerMethods<'a, 'a, T>,
    >(
        scratch_space: &'a mut [u8],
        port_out: &'a mut Option<net::host::InMemHost<'a>>,
        arena: &'a mut dyn Arena,
        server: (H, T),
        request: C::Req,
    ) -> Result<C::Resp, Error> {
        let len = scratch_space.len();
        let (req_scratch, port_scratch) = scratch_space.split_at_mut(len / 2);
        let mut cursor = Cursor::new(req_scratch);
        request
            .to_wire(&mut cursor)
            .expect("failed to write request");
        let request_bytes = cursor.take_consumed_bytes();

        *port_out = Some(net::host::InMemHost::new(port_scratch));
        let port = port_out.as_mut().unwrap();
        port.request(
            net::Header {
                command: <C::Req as protocol::Request<'a>>::TYPE,
            },
            request_bytes,
        );

        server.0.run(server.1, port, arena)?;

        let (_, mut resp) = port.response().unwrap();
        let resp_val = FromWire::from_wire(&mut resp, arena)
            .expect("failed to read response");
        assert_eq!(resp.len(), 0);
        Ok(resp_val)
    }

    #[test]
    fn empty_handler() {
        let handler = Handler::<()>::new();

        let mut scratch = [0; 1024];
        let mut port = None;
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 0 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            (handler, ()),
            req,
        );

        assert!(matches!(
            resp,
            Err(Error::UnhandledCommand(CommandType::FirmwareVersion))
        ));
    }

    #[test]
    fn single_handler() {
        let mut handler_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::FirmwareVersion, _>(|ctx| {
                handler_called = true;
                assert_eq!(ctx.server, "server state");
                assert_eq!(ctx.req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let mut port = None;
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            (handler, "server state"),
            req,
        );

        assert!(handler_called);
        assert!(resp.unwrap().version.starts_with(VERSION1));
    }

    #[test]
    fn single_handler_wrong() {
        let mut handler_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::FirmwareVersion, _>(|ctx| {
                handler_called = true;
                assert_eq!(ctx.server, "server state");
                assert_eq!(ctx.req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let mut port = None;
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);
        let req = protocol::device_id::DeviceIdRequest {};
        let resp = simulate_request::<protocol::DeviceId, _, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            (handler, "server state"),
            req,
        );

        assert!(matches!(
            resp,
            Err(Error::UnhandledCommand(CommandType::DeviceId))
        ));
        assert!(!handler_called);
    }

    #[test]
    fn double_handler() {
        let mut handler_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::FirmwareVersion, _>(|ctx| {
                handler_called = true;
                assert_eq!(ctx.server, "server state");
                assert_eq!(ctx.req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            })
            .handle::<protocol::DeviceId, _>(|_| {
                panic!("called the wrong handler")
            });

        let mut scratch = [0; 1024];
        let mut port = None;
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            (handler, "server state"),
            req,
        );

        assert!(handler_called);
        assert!(resp.unwrap().version.starts_with(VERSION1));
    }

    #[test]
    fn double_swapped() {
        let mut handler_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::DeviceId, _>(|_| {
                panic!("called the wrong handler")
            })
            .handle::<protocol::FirmwareVersion, _>(|ctx| {
                handler_called = true;
                assert_eq!(ctx.server, "server state");
                assert_eq!(ctx.req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let mut port = None;
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            (handler, "server state"),
            req,
        );

        assert!(handler_called);
        assert!(resp.unwrap().version.starts_with(VERSION1));
    }

    #[test]
    fn duplicate_handler() {
        let mut handler1_called = false;
        let mut handler2_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::FirmwareVersion, _>(|_| {
                handler1_called = true;

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            })
            .handle::<protocol::DeviceId, _>(|_| {
                panic!("called the wrong handler")
            })
            .handle::<protocol::FirmwareVersion, _>(|_| {
                handler2_called = true;

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION2,
                })
            });

        let mut scratch = [0; 1024];
        let mut port = None;
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            (handler, "server state"),
            req,
        );

        assert!(handler1_called || handler2_called);
        let version = resp.unwrap().version;
        assert!(version == VERSION1 || version == VERSION2);
    }
}
