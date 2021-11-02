// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus protocol messages.
//!
//! A Cerberus protocol message (also called a "command") consists of three
//! parts:
//! - A *command type*, representing the type of command this is.
//! - A *request bit*, indicating whether this message is a request or a
//!   response.
//! - A *body*, which is a buffer that is interpreted according to the
//!   command type.
//!
//! There is also a special "error" response, with no corresponding request,
//! which is used both to indicate an error, and as an ACK-type response for
//! requests that do not otherwise have data to respond with.
//!
//! This module provides a way to convert a parsed `manticore` header
//! (consisting, at minimum, of a command type and a request bit) and a buffer
//! into a request or response, and, also, to reverse that process.
//!
//! If a message type contains a large buffer, the message type will have an
//! appropriate lifetime attached to it.
//!
//! In addition to providing (de)serialization to and from the Cerberus wire
//! format (via the [`wire` module]), the `serde` feature will provide relevant
//! implementations of [`serde`] traits, for (de)serialization to and from
//! human-readable formats, like JSON.
//!
//! ---
//!
//! This module provides a subset of required and optional commands specified
//! by Cerberus. In particular, `manticore` does not yet implement
//! authentication or secure channel negotiation.
//!
//! `manticore` also provides some additional protocol messages not specified
//! by Cerberus, encoded using command type bytes not allocated by Cerberus.
//!
//! Also, unlike Cerberus, `manticore` does not require that a session be
//! spoken over MCTP, and, as such, does not use the same header as Cerberus.
//!
//! [`wire` module]: wire/index.html

// This is required due to the make_fuzz_safe! macro.
#![allow(unused_parens)]

use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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

pub mod device_id;
pub use device_id::DeviceId;

pub mod device_info;
pub use device_info::DeviceInfo;

pub mod device_uptime;
pub use device_uptime::DeviceUptime;

pub mod capabilities;
pub use capabilities::DeviceCapabilities;

pub mod firmware_version;
pub use firmware_version::FirmwareVersion;

pub mod get_digests;
pub use get_digests::GetDigests;

pub mod get_cert;
pub use get_cert::GetCert;

pub mod get_host_state;
pub use get_host_state::GetHostState;

pub mod challenge;
pub use challenge::Challenge;

pub mod key_exchange;
pub use key_exchange::KeyExchange;

pub mod reset_counter;
pub use reset_counter::ResetCounter;

pub mod request_counter;
pub use request_counter::RequestCounter;

/// A Cerberus command.
///
/// A Cerberus command is identified by two types, each of which has a
/// corresponding [`CommandType`]:
/// - A unique request type.
/// - A response type, which may be [`Ack`].
///
/// This trait is not implemented by any of the request or response types, but
/// is intead implemented by uninhabited types that represent pairs of requests
/// and responses, for use in generic programming.
pub trait Command<'req> {
    /// The unique request type for this `Command`.
    type Req: Request<'req>;
    /// The response type for this `Command`, which will either be unique or
    /// [`Ack`].
    type Resp: Response<'req>;

    /// The message-specific errors for this `Command`.
    ///
    /// In general, this will just be [`NoSpecificError`].
    type Error: error::SpecificError;
}

/// A Cerberus request.
///
/// See [`Command`].
pub trait Request<'req>: FromWire<'req> + ToWire {
    /// The unique [`CommandType`] for this `Request`.
    const TYPE: CommandType;
}

/// A Cerberus response.
///
/// See [`Command`].
pub trait Response<'req>: FromWire<'req> + ToWire {
    /// The unique [`CommandType`] for this `Response`.
    const TYPE: CommandType;
}

wire_enum! {
    /// A Cerberus command type.
    ///
    /// This enum represents all command types implemented by `manticore`,
    /// including any `manticore`-specific messages not defined by Cerberus.
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum CommandType: u8 {
        /// An error message (or a trivial command ACK).
        ///
        /// See [`Ack`] and [`RawError`].
        Error = 0x7f,
        /// A request for the RoT's firmware version.
        ///
        /// See [`FirmwareVersion`].
        FirmwareVersion = 0x01,
        /// A request to negotiate device capabilities.
        ///
        /// See [`DeviceCapabilities`].
        DeviceCapabilities = 0x02,
        /// A request for this device's identity.
        ///
        /// See [`DeviceId`].
        DeviceId = 0x03,
        /// A request for information about this device.
        ///
        /// See [`DeviceInfo`].
        DeviceInfo = 0x04,
        /// A request for hashes of a certificate chain.
        ///
        /// See [`GetDigests`].
        GetDigests = 0x81,
        /// A request for a chunk of a certificate.
        ///
        /// See [`GetCert`].
        GetCert = 0x82,
        /// A Cerberus challenge.
        ///
        /// See [`Challenge`].
        Challenge = 0x83,
        /// The key-exchange handshake.
        ///
        /// See [`KeyExchange`].
        KeyExchange = 0x84,
        /// A request for the rest state of the host processor.
        ///
        /// See [`GetHostState`].
        GetHostState = 0x40,
        /// A request for the number of times the device has been reset since
        /// POR.
        ///
        /// See [`ResetCounter`].
        ResetCounter = 0x87,
        /// A request for the uptime of the device since last reset.
        ///
        /// Note that this command is a Manticore extension.
        ///
        /// See [`DeviceUptime`].
        DeviceUptime = 0xa0,
        /// A request for an approximate number of requests the device has
        /// handled since last reset.
        ///
        /// Note that this command is a Manticore extension.
        ///
        /// See [`RequestCounter`].
        RequestCounter = 0xa1,
    }
}

impl CommandType {
    /// Returns `true` when `self` represents a `manticore` extension to the
    /// protocol.
    pub fn is_manticore_extension(self) -> bool {
        matches!(self, Self::DeviceUptime)
    }
}

impl From<u8> for CommandType {
    fn from(num: u8) -> CommandType {
        match num {
            0x01 => CommandType::FirmwareVersion,
            0x02 => CommandType::DeviceCapabilities,
            0x03 => CommandType::DeviceId,
            0x04 => CommandType::DeviceInfo,
            0x81 => CommandType::GetDigests,
            0x82 => CommandType::GetCert,
            0x83 => CommandType::Challenge,
            0x40 => CommandType::GetHostState,
            0x87 => CommandType::ResetCounter,
            0xa0 => CommandType::DeviceUptime,
            0xa1 => CommandType::RequestCounter,
            _ => CommandType::Error,
        }
    }
}
