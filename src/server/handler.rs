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
//!   .handle::<MyCommand, _>(|server, req| {
//!     // Do stuff...
//!     Ok(response)
//!   })
//!   // ...
//!   .run(server, req, resp)
//! ```
//! This defines a request handler; nothing happens until `run()` is called.
//! When called, `run()` performs the following steps:
//! - It parses a `protocol::Header` out of `req`, asserting that the header
//!   has the request bit set.
//! - It selects a `.handle<MyCommand, _>()` call, such that
//!   `MyCommand::Req::TYPE` matches the header's command type (if multiple
//!   handlers could match, an unspecified one is chosen).
//! - It parses the rest of `req` as a `MyCommand::Req`, and passes it and the
//!   server context into the closure.
//! - The closure executes, which returns
//!   `Result<MyCommand::Resp, protocol::Error>`.
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

use crate::io;
use crate::protocol;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::FromWireError;
use crate::protocol::wire::ToWire as _;
use crate::protocol::wire::ToWireError;
use crate::protocol::CommandType;
use crate::protocol::Header;
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
    /// Represents a failure during deserialization.
    FromWireError(FromWireError),
    /// Represents a failure during serialization.
    ToWireError(ToWireError),

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

impl From<FromWireError> for Error {
    fn from(e: FromWireError) -> Error {
        Error::FromWireError(e)
    }
}

impl From<ToWireError> for Error {
    fn from(e: ToWireError) -> Error {
        Error::ToWireError(e)
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
pub struct Cons<Prev, Command, F> {
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
    fn handle<'out, C, F>(self, handler: F) -> Cons<Self, C, F>
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
            Server,
            ReqOf<'req, C>,
        ) -> Result<RespOf<'out, C>, protocol::Error>,
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
    fn run_with_header<R: io::Read<'req>, W: io::Write>(
        self,
        req_header: Header,
        server: Server,
        req: R,
        resp: W,
    ) -> Result<(), Error>;

    /// Executes a `Handler` with the given context.
    ///
    /// See the module-level documentation for more information.
    #[inline]
    fn run<R: io::Read<'req>, W: io::Write>(
        self,
        server: Server,
        mut req: R,
        resp: W,
    ) -> Result<(), Error> {
        let req_header = Header::from_wire(&mut req)?;
        if !req_header.is_request {
            return Err(FromWireError::OutOfRange.into());
        }
        self.run_with_header(req_header, server, req, resp)
    }
}

impl<'req, 'srv, 'out, Server, Prev, Command, F>
    HandlerMethods<'req, 'srv, Server> for Cons<Prev, Command, F>
where
    // See `HandlerMethods::handle` for an explanation of these
    // where-clauses.
    Server: 'srv,
    Prev: HandlerMethods<'req, 'srv, Server>,
    Command: for<'c> protocol::Command<'c>,
    F: FnOnce(
        Server,
        ReqOf<'req, Command>,
    ) -> Result<RespOf<'out, Command>, protocol::Error>,
{
    #[inline]
    fn run_with_header<R: io::Read<'req>, W: io::Write>(
        self,
        req_header: Header,
        server: Server,
        mut req: R,
        mut resp: W,
    ) -> Result<(), Error> {
        if req_header.command != ReqOf::<'req, Command>::TYPE {
            // Recurse into the next handler case. Note that this cannot be
            // `run`, since that would re-parse the header incorrectly.
            return self.prev.run_with_header(req_header, server, req, resp);
        }

        let msg = FromWire::from_wire(&mut req)?;
        // Ensure that we used up the whole buffer!
        let remains = req.remaining_data();
        if remains != 0 {
            return Err(Error::ReqTooLong(remains));
        }

        match (self.handler)(server, msg) {
            Ok(msg) => {
                let header = Header {
                    is_request: false,
                    command: RespOf::<'out, Command>::TYPE,
                };

                header.to_wire(&mut resp)?;
                msg.to_wire(&mut resp)?;
                Ok(())
            }
            Err(err) => {
                let header = Header {
                    is_request: false,
                    command: CommandType::Error,
                };

                header.to_wire(&mut resp)?;
                err.to_wire(&mut resp)?;
                Ok(())
            }
        }
    }
}

impl<'req, 'srv, Server: 'srv> HandlerMethods<'req, 'srv, Server>
    for Handler<Server>
{
    #[inline]
    fn run_with_header<R: io::Read<'req>, W: io::Write>(
        self,
        header: Header,
        _: Server,
        _: R,
        _: W,
    ) -> Result<(), Error> {
        Err(Error::UnhandledCommand(header.command))
    }
}

impl<P, C, F> sealed::Sealed for Cons<P, C, F> {}
impl<Server> sealed::Sealed for Handler<Server> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::io::Cursor;

    const VERSION1: &[u8; 32] = &[2; 32];
    const VERSION2: &[u8; 32] = &[5; 32];

    fn simulate_request<
        'a,
        C: protocol::Command<'a>,
        T: 'a,
        H: HandlerMethods<'a, 'a, T>,
    >(
        scratch_space: &'a mut [u8],
        server: (H, T),
        request: C::Req,
    ) -> Result<C::Resp, Error> {
        let mut cursor = Cursor::new(scratch_space);

        let header = Header {
            is_request: true,
            command: <C::Req as protocol::Request<'a>>::TYPE,
        };
        header.to_wire(&mut cursor).expect("failed to write header");
        request
            .to_wire(&mut cursor)
            .expect("failed to write request");

        let req = cursor.take_consumed_bytes();
        server.0.run(server.1, req, &mut cursor)?;
        let mut resp = cursor.take_consumed_bytes();

        let header =
            Header::from_wire(&mut resp).expect("failed to read header");
        assert!(!header.is_request);
        let resp_val =
            FromWire::from_wire(&mut resp).expect("failed to read response");
        assert_eq!(resp.len(), 0);
        Ok(resp_val)
    }

    #[test]
    fn empty_handler() {
        let handler = Handler::<()>::new();

        let mut scratch = [0; 1024];
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 0 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
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
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
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
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_request::<protocol::DeviceId, _, _>(
            &mut scratch,
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
    fn single_handler_too_long() {
        let mut handler_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let mut cursor = Cursor::new(&mut scratch);

        let header = Header {
            is_request: true,
            command: CommandType::FirmwareVersion,
        };
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        header.to_wire(&mut cursor).unwrap();
        req.to_wire(&mut cursor).unwrap();
        cursor.consume(5);

        let req = cursor.take_consumed_bytes();
        assert!(matches!(
            handler.run("server state", req, cursor),
            Err(Error::ReqTooLong(5))
        ));
        assert!(!handler_called);
    }

    #[test]
    fn double_handler() {
        let mut handler_called = false;
        let handler = Handler::<&str>::new()
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            })
            .handle::<protocol::DeviceId, _>(|_, _| {
                panic!("called the wrong handler")
            });

        let mut scratch = [0; 1024];
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
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
            .handle::<protocol::DeviceId, _>(|_, _| {
                panic!("called the wrong handler")
            })
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut scratch = [0; 1024];
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
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
            .handle::<protocol::FirmwareVersion, _>(|_, _| {
                handler1_called = true;

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            })
            .handle::<protocol::DeviceId, _>(|_, _| {
                panic!("called the wrong handler")
            })
            .handle::<protocol::FirmwareVersion, _>(|_, _| {
                handler2_called = true;

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION2,
                })
            });

        let mut scratch = [0; 1024];
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 42 };
        let resp = simulate_request::<protocol::FirmwareVersion, _, _>(
            &mut scratch,
            (handler, "server state"),
            req,
        );

        assert!(handler1_called || handler2_called);
        let version = resp.unwrap().version;
        assert!(version == VERSION1 || version == VERSION2);
    }
}
