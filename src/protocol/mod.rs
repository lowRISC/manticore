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

use crate::io::Read;
use crate::io::Write;
use crate::mem::Arena;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::FromWireError;
use crate::protocol::wire::ToWire;
use crate::protocol::wire::ToWireError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[macro_use]
mod macros;
#[cfg(feature = "arbitrary-derive")]
pub use macros::FuzzSafe;

#[macro_use]
pub mod wire;

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

pub mod reset_counter;
pub use reset_counter::ResetCounter;

pub mod request_counter;
pub use request_counter::RequestCounter;

/// A Cerberus command.
///
/// A Cerberus command is identified by two types, each of which has a
/// corresponding [`CommandType`]:
/// - A unique request type.
/// - A response type, which may be [`Error`].
///
/// This trait is not implemented by any of the request or response types, but
/// is intead implemented by uninhabited types that represent pairs of requests
/// and responses, for use in generic programming.
pub trait Command<'req> {
    /// The unique request type for this `Command`.
    type Req: Request<'req>;
    /// The response type for this `Command`, which will either be unique or
    /// [`Error`].
    type Resp: Response<'req>;
}

/// A Cerberus request.
///
/// See [`Command`](trait.Command.html).
pub trait Request<'req>: FromWire<'req> + ToWire {
    /// The unique [`CommandType`] for this `Request`.
    const TYPE: CommandType;
}

/// A Cerberus response.
///
/// See [`Command`](trait.Command.html).
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
        /// See [`Error`].
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
        GetDigests = 0x82,
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
            0x87 => CommandType::ResetCounter,
            0xa0 => CommandType::DeviceUptime,
            0xa1 => CommandType::RequestCounter,
            _ => CommandType::Error,
        }
    }
}

/// A parsed `manticore` header.
///
/// This struct represents all of the meaningful fields from a `manticore`
/// header; the actual format of the header is left up to an integration of
/// this library.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Header {
    /// The [`CommandType`] for a request.
    pub command: CommandType,
    /// The "request bit", for interpreting whether the body is the
    /// request or response variant of a command.
    pub is_request: bool,
}

/// The length of a `manticore` header on the wire, in bytes.
pub const HEADER_LEN: usize = 5;

/// A magic number required at the start of each `manticore` header.
const HEADER_MAGIC: &[u8] = &[0b01111110, 0x14, 0x14];

impl<'a> FromWire<'a> for Header {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        a: &'a A,
    ) -> Result<Self, FromWireError> {
        let mut magic = [0; 3];
        r.read_bytes(&mut magic)?;
        if magic != HEADER_MAGIC {
            return Err(FromWireError::OutOfRange);
        }

        let request_byte = r.read_le::<u8>()?;
        let is_request = match request_byte {
            0b0000_0000 => false,
            0b1000_0000 => true,
            _ => return Err(FromWireError::OutOfRange),
        };

        let command = CommandType::from_wire(r, a)?;
        Ok(Self {
            command,
            is_request,
        })
    }
}

impl ToWire for Header {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
        w.write_bytes(HEADER_MAGIC)?;
        w.write_le((self.is_request as u8) << 7)?;
        self.command.to_wire(w)?;
        Ok(())
    }
}

wire_enum! {
    /// A Cerberus error.
    ///
    /// This enum represents all error types implemented by `manticore`.
    /// Because `manticore` does not mandate running the connection over MCTP,
    /// the MCTP-specific error codes are omited.
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum ErrorCode: u8 {
        /// Represents a successful operation; this "error" code is used to
        /// turn an [`Error`] into an ACK.
        Ok = 0x00,
        /// Indicates that the device is "busy", usually meaning that other
        /// commands are being serviced.
        Busy = 0x03,
        /// Indicates an unspecified, vendor-defined error, which may include
        /// extra data in an [`Error`].
        Unspecified = 0x04,
    }
}

/// A generic error response.
///
/// This message is used to indicate that a request resulted in an error, or
/// as an ACK for commands that otherwise have no response message.
///
/// This command corresponds to [`CommandType::Error`] and does not have a
/// request counterpart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Error {
    /// What kind of error this is (or, it's merely an ACK).
    pub code: ErrorCode,
    /// A fixed array of "extra data" that can come with an error code.
    pub data: [u8; 4],
}

impl Error {
    /// Creates an "ACK" response, consisting of an `Error` with an
    /// [`ErrorCode::Ok`] code.
    pub fn new_ack() -> Self {
        Self {
            code: ErrorCode::Ok,
            data: [0; 4],
        }
    }
}

impl Response<'_> for Error {
    const TYPE: CommandType = CommandType::Error;
}

impl<'a> FromWire<'a> for Error {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        a: &'a A,
    ) -> Result<Self, FromWireError> {
        let code = ErrorCode::from_wire(&mut r, a)?;
        let mut data = [0; 4];
        r.read_bytes(&mut data)?;

        Ok(Self { code, data })
    }
}

impl ToWire for Error {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
        self.code.to_wire(&mut w)?;
        w.write_bytes(&self.data[..])?;
        Ok(())
    }
}
