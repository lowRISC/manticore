// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Manticore protocol messages.
//!
//! # Cerberus
//!
//! Manticore provides parsers for the Cerberus Challenge Protocol's messages.
//!
//! A Cerberus protocol message (also called a "command") consists of two
//! parts:
//! - A *command type*, representing the type of command this is.
//! - A *body*, which is a buffer that is interpreted according to the
//!   command type.
//!
//! There is also a special "error" response, with no corresponding request,
//! which is used both to indicate an error, and as an ACK-type response for
//! requests that do not otherwise have data to respond with.
//!
//! This module provides a way to convert a parsed Manticore header
//! (consisting, at minimum, of a command type and a request bit) and a buffer
//! into a request or response, and, also, to reverse that process.
//!
//! If a message type contains a large buffer, the message type will have an
//! appropriate lifetime attached to it.
//!
//! In addition to providing (de)serialization to and from the Cerberus wire
//! format (via the [`wire`] module), the `serde` feature will provide relevant
//! implementations of [`serde`] traits, for (de)serialization to and from
//! human-readable formats, like JSON.
//!
//! ## Manticore-specific details.
//!
//! Manticore also provides some additional protocol messages not specified
//! by Cerberus, encoded using command type bytes not allocated by Cerberus.
//!
//! Also, unlike Cerberus, Manticore does not require that a session be
//! spoken over MCTP, and, as such, does not use the same header as Cerberus.

// This is required due to the make_fuzz_safe! macro.
#![allow(unused_parens)]

#[macro_use]
mod macros;

#[macro_use]
pub mod borrowed;

#[macro_use]
pub mod template;

#[macro_use]
pub mod wire;

#[macro_use]
mod error;
pub use error::*;

mod cerberus;
pub use cerberus::*;

pub mod spdm;

/// A Manticore command.
///
/// A Manticore command is identified by two types, each of which has a
/// corresponding [`CommandType`]:
/// - A unique request type.
/// - A response type, which may be [`Ack`].
///
/// This trait is not implemented by any of the request or response types, but
/// is intead implemented by uninhabited types that represent pairs of requests
/// and responses, for use in generic programming.
pub trait Command<'wire> {
    /// The unique request type for this `Command`.
    type Req: Message<'wire>;
    /// The response type for this `Command`, which will either be unique or
    /// [`Ack`].
    type Resp: Message<'wire>;

    /// The message-specific errors for this `Command`.
    ///
    /// In general, this will just be [`NoSpecificError`].
    type Error: error::SpecificError;
}

/// A Manticore message type, which makes up part of a `Command`.
pub trait Message<'wire>: wire::FromWire<'wire> + wire::ToWire {
    /// The enum of command types this `Message` draws its type from.
    type CommandType;

    /// The unique [`CommandType`] for this `Request`.
    const TYPE: Self::CommandType;
}
