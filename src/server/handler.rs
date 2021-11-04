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
//! Handler::<Server, Header>::new()
//!   .handle::<MyCommand, _>(|ctx| {
//!     // Do stuff...
//!     Ok(response)
//!   })
//!   // ...
//!   .run(server, req, resp)
//! ```
//! This defines a request handler; nothing happens until `run()` is called.
//! When called, `run()` performs the following steps:
//! - It parses a `Header` out of `req`, asserting that the header
//!   has the request bit set. `Header` can be any [`net::Header`] type, so
//!   long as `req` supports it.
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
//! Handler::<Server, Header>::new()
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
use crate::protocol::Message;

/// A `*`-importable prelude that pulls in only the names that are necessary
/// to make `Handler` work.
pub mod prelude {
    pub use super::Handler;
    pub use super::HandlerMethods;
}

/// An error returned by a request handler.
#[derive(Copy, Clone, Debug)]
pub enum Error<Header>
where
    Header: net::Header,
{
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
    UnhandledCommand(Header::CommandType),
}

impl<H: net::Header> From<wire::Error> for Error<H> {
    fn from(e: wire::Error) -> Self {
        Error::Wire(e)
    }
}

impl<H: net::Header> From<net::Error> for Error<H> {
    fn from(e: net::Error) -> Self {
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
pub struct Handler<Server, Header> {
    _ph: PhantomData<fn(Server, Header)>,
}

impl<Server, Header> Handler<Server, Header> {
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
pub trait HandlerMethods<'req, 'srv, Server: 'srv, Header>:
    Sized + sealed::Sealed
where
    Header: net::Header,
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
        // parameters, e.g., `type Req<'a>: Message<'a>;`. We would then write
        // `FnOnce(Server, C::Req<'req>) -> Result<C::Resp<'out>, Error>`.
        //
        // Since this is not possible today, we have the following workaround:
        // - `Command` has a lifetime parameter, and has associated types like
        //   `type Req: Message<'a>;`.
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
        for<'c> C: protocol::Command<'c>,
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
        for<'c> C: protocol::Command<'c>,
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
        header: Header,
        request: &mut dyn net::host::HostRequest<'req, Header>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error<Header>>;

    /// Executes a `Handler` with the given context.
    ///
    /// See the module-level documentation for more information.
    #[inline]
    fn run(
        self,
        server: Server,
        host_port: &mut dyn net::host::HostPort<'req, Header>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error<Header>> {
        let request = host_port.receive()?;
        let header = request.header()?;
        self.run_with_header(server, header, request, arena)
    }
}

impl<Prev, Command, F, const B: bool> Cons<Prev, Command, F, B> {
    #[inline]
    fn run_inner<'out, Ctx, Header>(
        self,
        request: &mut dyn net::host::HostRequest<'_, Header>,
        ctx: Ctx,
        original_header: Header,
    ) -> Result<(), Error<Header>>
    where
        for<'c> Command: protocol::Command<'c>,
        F: FnOnce(Ctx) -> Result<RespOf<'out, Command>, ErrOf<'out, Command>>,
        Header: net::Header,
        RespOf<'out, Command>: Message<'out, CommandType = Header::CommandType>,
    {
        match (self.handler)(ctx) {
            Ok(msg) => {
                let reply = request.reply(
                    original_header.reply_with(RespOf::<'out, Command>::TYPE),
                )?;
                msg.to_wire(reply.sink()?)?;
                reply.finish()?;
                Ok(())
            }
            Err(err) => {
                let reply =
                    request.reply(original_header.reply_with_error())?;
                err.to_wire(reply.sink()?)?;
                reply.finish()?;
                Ok(())
            }
        }
    }
}

impl<'req, 'srv, 'out, Server, Header, Prev, Command, F>
    HandlerMethods<'req, 'srv, Server, Header> for Cons<Prev, Command, F, false>
where
    // See `HandlerMethods::handle` for an explanation of these
    // where-clauses.
    Server: 'srv,
    Prev: HandlerMethods<'req, 'srv, Server, Header>,
    Command: for<'c> protocol::Command<'c>,
    Header: net::Header,
    Header::CommandType: PartialEq,
    F: FnOnce(
        Context<'req, (), ReqOf<'req, Command>, Server>,
    ) -> Result<RespOf<'out, Command>, ErrOf<'out, Command>>,
    ReqOf<'req, Command>: Message<'req, CommandType = Header::CommandType>,
    RespOf<'out, Command>: Message<'out, CommandType = Header::CommandType>,
{
    #[inline]
    fn run_with_header(
        self,
        server: Server,
        header: Header,
        request: &mut dyn net::host::HostRequest<'req, Header>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error<Header>> {
        if header.command() != ReqOf::<'req, Command>::TYPE {
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
        self.run_inner(request, ctx, header)
    }
}

impl<'req, 'srv, 'out, Server, Header, Prev, Command, F>
    HandlerMethods<'req, 'srv, Server, Header> for Cons<Prev, Command, F, true>
where
    // See `HandlerMethods::handle` for an explanation of these
    // where-clauses.
    Server: 'srv,
    Prev: HandlerMethods<'req, 'srv, Server, Header>,
    Command: for<'c> protocol::Command<'c>,
    Header: net::Header,
    Header::CommandType: PartialEq,
    F: FnOnce(
        Context<'req, &'req [u8], ReqOf<'req, Command>, Server>,
    ) -> Result<RespOf<'out, Command>, ErrOf<'out, Command>>,
    ReqOf<'req, Command>: Message<'req, CommandType = Header::CommandType>,
    RespOf<'out, Command>: Message<'out, CommandType = Header::CommandType>,
{
    #[inline]
    fn run_with_header(
        self,
        server: Server,
        header: Header,
        request: &mut dyn net::host::HostRequest<'req, Header>,
        arena: &'req dyn Arena,
    ) -> Result<(), Error<Header>> {
        if header.command() != ReqOf::<'req, Command>::TYPE {
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
        self.run_inner(request, ctx, header)
    }
}

impl<'req, 'srv, Server: 'srv, Header>
    HandlerMethods<'req, 'srv, Server, Header> for Handler<Server, Header>
where
    Header: net::Header,
{
    #[inline]
    fn run_with_header(
        self,
        _: Server,
        header: Header,
        _: &mut dyn net::host::HostRequest<'req, Header>,
        _: &'req dyn Arena,
    ) -> Result<(), Error<Header>> {
        Err(Error::UnhandledCommand(header.command()))
    }
}

impl<P, C, F, const B: bool> sealed::Sealed for Cons<P, C, F, B> {}
impl<S, H> sealed::Sealed for Handler<S, H> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::Cursor;
    use crate::mem::BumpArena;
    use crate::protocol::CommandType;

    const VERSION1: &[u8; 32] = &[2; 32];
    const VERSION2: &[u8; 32] = &[5; 32];

    type Handler<S> = super::Handler<S, net::CerberusHeader>;

    fn simulate_request<
        'a,
        C: protocol::Command<'a>,
        T: 'a,
        H: HandlerMethods<'a, 'a, T, net::CerberusHeader>,
    >(
        scratch_space: &'a mut [u8],
        port_out: &'a mut Option<net::host::InMemHost<'a, net::CerberusHeader>>,
        arena: &'a mut dyn Arena,
        server: (H, T),
        request: C::Req,
    ) -> Result<C::Resp, Error<net::CerberusHeader>>
    where
        ReqOf<'a, C>: Message<'a, CommandType = CommandType>,
    {
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
            net::CerberusHeader {
                command: <C::Req as protocol::Message<'a>>::TYPE,
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
