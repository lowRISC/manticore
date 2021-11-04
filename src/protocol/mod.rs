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

use core::fmt::Debug;

#[macro_use]
mod macros;

#[macro_use]
pub mod borrowed;

#[macro_use]
pub mod template;

#[macro_use]
pub mod wire;

#[macro_use]
pub mod error;
#[cfg(doc)]
use error::{Ack, NoSpecificError};

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
///
/// This trait is often used via a bound like `C: for<'a> Command<'a>`, allowing
/// its members to be used as a sort of faux-generalized associated type. However,
/// the current syntax for going from `C` to `Req` is somewhat painful, so the
/// aliases [`Req`], [`Resp`], and [`Error`] are provided to alleviate this.
pub trait Command<'wire> {
    /// The enum of command types this `Command` draws its types from.
    type CommandType: Copy + Debug + Eq;

    /// The unique request type for this `Command`.
    type Req: Message<'wire, CommandType = Self::CommandType>;
    /// The response type for this `Command`, which will either be unique or
    /// [`Ack`].
    type Resp: Message<'wire, CommandType = Self::CommandType>;

    /// The message-specific errors for this `Command`.
    ///
    /// In general, this will just be [`NoSpecificError`].
    type Error: error::SpecificError;
}

/// Extracts the request type with lifetime `'a` from `C: for<'a> Command<'a>`.
///
/// See [`Command`].
pub type Req<'a, C> = <C as Command<'a>>::Req;

/// Extracts the response type with lifetime `'a` from `C: for<'a> Command<'a>`.
///
/// See [`Command`].
pub type Resp<'a, C> = <C as Command<'a>>::Resp;

/// Extracts the error type with lifetime `'a` from `C: for<'a> Command<'a>`.
///
/// See [`Command`].
pub type Error<'a, C> = error::Error<<C as Command<'a>>::Error>;

/// A Manticore message type, which makes up part of a `Command`.
pub trait Message<'wire>: wire::FromWire<'wire> + wire::ToWire {
    /// The enum of command types this `Message` draws its type from.
    type CommandType: Copy + Debug + Eq;

    /// The unique [`CommandType`] for this `Request`.
    const TYPE: Self::CommandType;
}
