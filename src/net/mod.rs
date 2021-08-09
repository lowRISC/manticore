// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Networking interfaces.
//!
//! This module provides generic, abstract networking interfaces for sending
//! buffers over a "network". The term "network" is used very loosely: for
//! our purposes, a network is an object upon which we can transact encoded
//! buffers along with the bits necessary to encode a Cerberus header.
//!
//! For example, if an integration wished to receive requests from a "host"
//! device over a SPI line, it should tie up all the necessary implementation
//! details into a [`HostPort`] implementation.

use core::fmt::Debug;

use crate::io;
use crate::protocol::cerberus;
use crate::protocol::spdm;

pub mod device;
pub mod host;

#[cfg(doc)]
use host::HostPort;

/// A networking error.
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Indicates an underlying I/O error.
    Io(io::Error),
    /// Indicates an error constructing (or interpreting) an abstract Manticore
    /// header.
    BadHeader,
    /// Indicates that the other end of a connection is "disconnected". This
    /// can mean anything from a connection being explicitly terminated, to
    /// some internal timeout expiring.
    Disconnected,
    /// Indicates that some operation was done out of order, such as attempting
    /// to reference part of the request once a reply has begun.
    OutOfOrder,
    /// The operation timed out.
    Timeout,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

debug_from!(Error => io::Error);

/// A header type, which represents a protocol over the wire.
pub trait Header: Copy {
    /// The command type enum associated with this header.
    type CommandType: Copy + Debug + Eq;

    /// Returns the [`Self::CommandType`] contained within `self`.
    fn command(&self) -> Self::CommandType;

    /// Constructs a new header for replying to a request that used this header,
    /// but with the given `command_type` in the response.
    fn reply_with(&self, command: Self::CommandType) -> Self;

    /// Constructs a new header for replying to a request that used this header,
    /// indicating that the reply contains an error.
    fn reply_with_error(&self) -> Self;
}

/// An abstract Cerberus message header.
///
/// This type records fields extracted out of an incoming Cerberus message's
/// header, which Manticore's machinery requires to further parse and process
/// the message.
///
/// The serialization of this type is dependent on a [`HostPort`]
/// implementation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
pub struct CerberusHeader {
    pub command: cerberus::CommandType,
}

impl Header for CerberusHeader {
    type CommandType = cerberus::CommandType;

    fn command(&self) -> cerberus::CommandType {
        self.command
    }
    fn reply_with(&self, command: cerberus::CommandType) -> Self {
        Self { command }
    }

    fn reply_with_error(&self) -> Self {
        self.reply_with(cerberus::CommandType::Error)
    }
}

/// An abstract SPDM message header.
///
/// This type corresponds to the prefix of an SPDM message consisting of the
/// version, whether it is a request, and the command:
/// ```text
/// struct {
///   minor: u4,
///   major: u4,
///   command: u7,
///   is_request: bool,
/// }
/// ```
///
/// The precise serialization of this type is dependent on a [`HostPort`]
/// implementation, though the above is normative per the SPDM spec.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
pub struct SpdmHeader {
    pub version: spdm::Version,
    pub command: spdm::CommandType,
    pub is_request: bool,
}

impl Header for SpdmHeader {
    type CommandType = spdm::CommandType;

    fn command(&self) -> spdm::CommandType {
        self.command
    }
    fn reply_with(&self, command: spdm::CommandType) -> Self {
        Self {
            version: spdm::Version::MANTICORE,
            command,
            is_request: false,
        }
    }

    fn reply_with_error(&self) -> Self {
        self.reply_with(spdm::CommandType::Error)
    }
}
