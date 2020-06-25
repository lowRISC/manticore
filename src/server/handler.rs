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
use crate::protocol::CommandType;
use crate::protocol::Deserialize;
use crate::protocol::DeserializeError;
use crate::protocol::Header;
use crate::protocol::Request as _;
use crate::protocol::Response as _;
use crate::protocol::Serialize;
use crate::protocol::SerializeError;

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
    DeserializeError(DeserializeError),
    /// Represents a failure during serialization.
    SerializeError(SerializeError),

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

impl From<DeserializeError> for Error {
    fn from(e: DeserializeError) -> Error {
        Error::DeserializeError(e)
    }
}

impl From<SerializeError> for Error {
    fn from(e: SerializeError) -> Error {
        Error::SerializeError(e)
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

/// The core trait that makes handler building possible.
///
/// The lifetime `'req` represents the lifetime of the request. This lifetime
/// must be placed here to ensure that all inputs into a request handling
/// operation (including the `Deserialize` and `Command` traits, which have
/// lifetimes in them) have a single, coherent lifetime.
pub trait HandlerMethods<'req, Server>: Sized + sealed::Sealed {
    /// Attaches a new handler function to a `Handler`.
    ///
    /// This function should be called as `.handle::<Command, _>(...)` to make
    /// type inference work; the second type paramter can't be named, since
    /// it will be a closure type.
    fn handle<C, F>(self, handler: F) -> Cons<Self, C, F>
    where
        C: protocol::Command<'req>,
        F: FnOnce(&mut Server, C::Req) -> Result<C::Resp, protocol::Error>,
    {
        Cons {
            prev: self,
            handler,
            _ph: PhantomData,
        }
    }

    /// The "real" run function.
    #[doc(hidden)]
    fn run_with_header<Read, Write>(
        self,
        req_header: Header,
        server: &mut Server,
        req: &mut Read,
        resp: &mut Write,
    ) -> Result<(), Error>
    where
        Read: io::Read<'req>,
        Write: io::Write;

    /// Executes a `Handler` with the given context.
    ///
    /// See the module-level documentation for more information.
    #[inline]
    fn run<Read, Write>(
        self,
        server: &mut Server,
        req: &mut Read,
        resp: &mut Write,
    ) -> Result<(), Error>
    where
        Read: io::Read<'req>,
        Write: io::Write,
    {
        let req_header = Header::deserialize(req)?;
        if !req_header.is_request {
            return Err(DeserializeError::OutOfRange.into());
        }
        self.run_with_header(req_header, server, req, resp)
    }
}

impl<'req, Server, Prev, Command, F> HandlerMethods<'req, Server>
    for Cons<Prev, Command, F>
where
    Prev: HandlerMethods<'req, Server>,
    Command: protocol::Command<'req>,
    F: FnOnce(
        &mut Server,
        Command::Req,
    ) -> Result<Command::Resp, protocol::Error>,
{
    #[inline]
    fn run_with_header<Read, Write>(
        self,
        req_header: Header,
        server: &mut Server,
        req: &mut Read,
        resp: &mut Write,
    ) -> Result<(), Error>
    where
        Read: io::Read<'req>,
        Write: io::Write,
    {
        if req_header.command != Command::Req::TYPE {
            // Recurse into the next handler case. Note that this cannot be
            // `run`, since that would re-parse the header incorrectly.
            return self.prev.run_with_header(req_header, server, req, resp);
        }

        let msg = Deserialize::deserialize(req)?;
        // Ensure that we used up the whole buffer!
        let remains = req.remaining_data();
        if remains != 0 {
            return Err(Error::ReqTooLong(remains));
        }

        match (self.handler)(server, msg) {
            Ok(msg) => {
                let header = Header {
                    is_request: false,
                    command: Command::Resp::TYPE,
                };

                Serialize::serialize(&header, resp)?;
                Serialize::serialize(&msg, resp)?;
                Ok(())
            }
            Err(err) => {
                let header = Header {
                    is_request: false,
                    command: CommandType::Error,
                };

                Serialize::serialize(&header, resp)?;
                Serialize::serialize(&err, resp)?;
                Ok(())
            }
        }
    }
}

impl<'req, Server> HandlerMethods<'req, Server> for Handler<Server> {
    #[inline]
    fn run_with_header<Read, Write>(
        self,
        header: Header,
        _: &mut Server,
        _: &mut Read,
        _: &mut Write,
    ) -> Result<(), Error>
    where
        Read: io::Read<'req>,
        Write: io::Write,
    {
        Err(Error::UnhandledCommand(header.command))
    }
}

impl<P, C, F> sealed::Sealed for Cons<P, C, F> {}
impl<Server> sealed::Sealed for Handler<Server> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::test_util;

    const VERSION1: &[u8; 32] = &[2; 32];
    const VERSION2: &[u8; 32] = &[5; 32];

    #[test]
    fn empty_handler() {
        let handler = Handler::new();

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let mut req = test_util::write_req(
            protocol::firmware_version::FirmwareVersionRequest { index: 0 },
            &mut read_buf,
        );

        assert!(matches!(
            handler.run(&mut (), &mut req, &mut &mut write_buf[..]),
            Err(Error::UnhandledCommand(CommandType::FirmwareVersion))
        ));
    }

    #[test]
    fn single_handler() {
        let mut handler_called = false;
        let handler = Handler::new().handle::<protocol::FirmwareVersion, _>(
            |zelf, req| {
                handler_called = true;
                assert_eq!(*zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            },
        );

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let mut req = test_util::write_req(
            protocol::firmware_version::FirmwareVersionRequest { index: 42 },
            &mut read_buf,
        );

        let resp = test_util::with_buf(&mut write_buf, |resp| {
            handler.run(&mut "server state", &mut req, resp).unwrap();
        });
        assert!(handler_called);
        let resp = test_util::read_resp::<
            protocol::firmware_version::FirmwareVersionResponse,
        >(resp);
        assert!(resp.version.starts_with(VERSION1));
    }

    #[test]
    fn single_handler_wrong() {
        let mut handler_called = false;
        let handler = Handler::new().handle::<protocol::FirmwareVersion, _>(
            |zelf, req| {
                handler_called = true;
                assert_eq!(*zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            },
        );

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let mut req = test_util::write_req(
            protocol::device_id::DeviceIdRequest,
            &mut read_buf,
        );

        assert!(matches!(
            handler.run(&mut "server state", &mut req, &mut &mut write_buf[..]),
            Err(Error::UnhandledCommand(CommandType::DeviceId))
        ));
        assert!(!handler_called);
    }

    #[test]
    fn single_handler_too_long() {
        let mut handler_called = false;
        let handler = Handler::new().handle::<protocol::FirmwareVersion, _>(
            |zelf, req| {
                handler_called = true;
                assert_eq!(*zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            },
        );

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let correct_len = test_util::write_req(
            protocol::firmware_version::FirmwareVersionRequest { index: 42 },
            &mut read_buf,
        )
        .len();
        let mut req = &read_buf[..correct_len + 5];

        assert!(matches!(
            handler.run(&mut "server state", &mut req, &mut &mut write_buf[..]),
            Err(Error::ReqTooLong(5))
        ));
        assert!(!handler_called);
    }

    #[test]
    fn double_handler() {
        let mut handler_called = false;
        let handler = Handler::new()
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(*zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            })
            .handle::<protocol::DeviceId, _>(|_, _| {
                panic!("called the wrong handler")
            });

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let mut req = test_util::write_req(
            protocol::firmware_version::FirmwareVersionRequest { index: 42 },
            &mut read_buf,
        );

        let resp = test_util::with_buf(&mut write_buf, |resp| {
            handler.run(&mut "server state", &mut req, resp).unwrap();
        });
        assert!(handler_called);
        let resp = test_util::read_resp::<
            protocol::firmware_version::FirmwareVersionResponse,
        >(resp);
        assert!(resp.version.starts_with(VERSION1));
    }

    #[test]
    fn double_swapped() {
        let mut handler_called = false;
        let handler = Handler::new()
            .handle::<protocol::DeviceId, _>(|_, _| {
                panic!("called the wrong handler")
            })
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                handler_called = true;
                assert_eq!(*zelf, "server state");
                assert_eq!(req.index, 42);

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: VERSION1,
                })
            });

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let mut req = test_util::write_req(
            protocol::firmware_version::FirmwareVersionRequest { index: 42 },
            &mut read_buf,
        );

        let resp = test_util::with_buf(&mut write_buf, |resp| {
            handler.run(&mut "server state", &mut req, resp).unwrap();
        });
        assert!(handler_called);
        let resp = test_util::read_resp::<
            protocol::firmware_version::FirmwareVersionResponse,
        >(resp);
        assert!(resp.version.starts_with(VERSION1));
    }

    #[test]
    fn duplicate_handler() {
        let mut handler1_called = false;
        let mut handler2_called = false;
        let handler = Handler::new()
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

        let mut read_buf = [0; 1024];
        let mut write_buf = [0; 1024];

        let mut req = test_util::write_req(
            protocol::firmware_version::FirmwareVersionRequest { index: 42 },
            &mut read_buf,
        );

        let resp = test_util::with_buf(&mut write_buf, |resp| {
            handler.run(&mut "server state", &mut req, resp).unwrap();
        });
        assert!(handler1_called || handler2_called);
        let resp = test_util::read_resp::<
            protocol::firmware_version::FirmwareVersionResponse,
        >(resp);
        assert!(resp.version == VERSION1 || resp.version == VERSION2);
    }
}
