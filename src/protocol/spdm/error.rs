// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Error definitions for SPDM messages.

use crate::crypto;
use crate::io::read::ReadZeroExt as _;
use crate::io::ReadInt as _;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::mem::OutOfMemory;
use crate::protocol::spdm::CommandType;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::wire::WireEnum as _;
use crate::protocol::Message;
use crate::session;

#[cfg(doc)]
use crate::protocol;

/// An uninterpreted SPDM error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RawError<'wire> {
    /// What kind of error this is.
    pub code: u8,
    /// Data describing the error.
    pub data: u8,
    /// "Extra data" that can come with an error code.
    pub extra: &'wire [u8],
}

impl<'wire> FromWire<'wire> for RawError<'wire> {
    fn from_wire<R: ReadZero<'wire> + ?Sized>(
        r: &mut R,
        a: &'wire dyn Arena,
    ) -> Result<Self, wire::Error> {
        let code = r.read_le()?;
        let data = r.read_le()?;

        let len = r.remaining_data();
        let extra = r.read_slice::<u8>(len, a)?;

        Ok(Self { code, data, extra })
    }
}

impl ToWire for RawError<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.code)?;
        w.write_le(self.data)?;
        w.write_bytes(self.extra)?;
        Ok(())
    }
}

/// A SPDM error.
///
/// We only implement a subset of SPDM's error surface; errors we do not
/// recognize are punted to their own variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum Error<'wire> {
    /// Indicates that a request failed to parse.
    InvalidRequest,

    /// Indicates that the device is "busy", usually meaning that other
    /// commands are being serviced.
    Busy,

    /// Indicates that the incoming request violated the SPDM state
    /// machine ordering.
    UnexpectedRequest,

    /// Indicates that an otherwise unspecified error occured.
    Unspecified,

    /// Indicates that a decryption operation failed.
    DecryptionFailed,

    /// Indicates that the given request type was unsupported.
    Unsupported {
        /// The request type in question.
        command: CommandType,
    },

    // We don't parse InFlight and friends.
    /// Indicates that there are too many active sessions outstanding.
    SessionLimitExceeded,

    /// Indicates that a request is required to complete an operation.
    ResetRequired,

    /// Indicates that the response that would be sent is larger than the
    /// host can handle.
    ResponseTooLarge,

    /// Indicates that the host send a message that was too large.
    RequestTooLarge,

    /// Indicates that a request was dropped for unspecified reasons.
    MessageLost,

    /// Indicates that the requested SPDM version is not supported, or
    /// is different from the selected version.
    VersionMismatch,

    /// Indicates that the device wishes to re-negotiate capabilities
    /// (such as after reset or an update).
    ResyncRequired,

    /// An error that Manticore does not understand.
    Unknown(RawError<'wire>),
}

impl<'wire> Message<'wire> for Error<'wire> {
    type CommandType = CommandType;
    const TYPE: CommandType = CommandType::Error;
}

impl<'wire> FromWire<'wire> for Error<'wire> {
    fn from_wire<R: ReadZero<'wire> + ?Sized>(
        r: &mut R,
        a: &'wire dyn Arena,
    ) -> Result<Self, wire::Error> {
        let error = RawError::from_wire(r, a)?;
        let if_trivial = move |code: Error<'wire>| {
            if error.data == 0 && error.extra.is_empty() {
                Ok(code)
            } else {
                Err(wire::Error::OutOfRange)
            }
        };

        match error.code {
            0x01 => if_trivial(Self::InvalidRequest),
            0x03 => if_trivial(Self::Busy),
            0x04 => if_trivial(Self::UnexpectedRequest),
            0x05 => if_trivial(Self::Unspecified),
            0x06 => if_trivial(Self::DecryptionFailed),
            0x07 => {
                if error.data & 0x80 == 0 || !error.extra.is_empty() {
                    return Err(wire::Error::OutOfRange);
                }
                Ok(Self::Unsupported {
                    command: CommandType::from_wire_value(error.data & 0x7f)
                        .ok_or(wire::Error::OutOfRange)?,
                })
            }
            0x0b => if_trivial(Self::SessionLimitExceeded),
            0x0c => if_trivial(Self::ResetRequired),
            0x0d => if_trivial(Self::ResponseTooLarge),
            0x0e => if_trivial(Self::RequestTooLarge),
            0x10 => if_trivial(Self::MessageLost),
            0x41 => if_trivial(Self::VersionMismatch),
            0x43 => if_trivial(Self::ResyncRequired),
            _ => Ok(Self::Unknown(error)),
        }
    }
}

impl ToWire for Error<'_> {
    fn to_wire<W: Write>(&self, w: W) -> Result<(), wire::Error> {
        let raw = match self {
            Self::InvalidRequest => RawError {
                code: 0x01,
                data: 0x00,
                extra: &[],
            },
            Self::Busy => RawError {
                code: 0x03,
                data: 0x00,
                extra: &[],
            },
            Self::UnexpectedRequest => RawError {
                code: 0x04,
                data: 0x00,
                extra: &[],
            },
            Self::Unspecified => RawError {
                code: 0x05,
                data: 0x00,
                extra: &[],
            },
            Self::DecryptionFailed => RawError {
                code: 0x06,
                data: 0x00,
                extra: &[],
            },
            Self::Unsupported { command } => RawError {
                code: 0x07,
                data: 0x80 | command.to_wire_value(),
                extra: &[],
            },
            Self::SessionLimitExceeded => RawError {
                code: 0x0b,
                data: 0x00,
                extra: &[],
            },
            Self::ResetRequired => RawError {
                code: 0x0c,
                data: 0x00,
                extra: &[],
            },
            Self::ResponseTooLarge => RawError {
                code: 0x0d,
                data: 0x00,
                extra: &[],
            },
            Self::RequestTooLarge => RawError {
                code: 0x0e,
                data: 0x00,
                extra: &[],
            },
            Self::MessageLost => RawError {
                code: 0x10,
                data: 0x00,
                extra: &[],
            },
            Self::VersionMismatch => RawError {
                code: 0x41,
                data: 0x00,
                extra: &[],
            },
            Self::ResyncRequired => RawError {
                code: 0x43,
                data: 0x00,
                extra: &[],
            },
            Self::Unknown(e) => *e,
        };

        raw.to_wire(w)
    }
}

impl From<OutOfMemory> for Error<'_> {
    fn from(_: OutOfMemory) -> Self {
        Self::Unspecified
    }
}

impl From<crypto::csrng::Error> for Error<'_> {
    fn from(_: crypto::csrng::Error) -> Self {
        Self::Unspecified
    }
}

impl From<crypto::hash::Error> for Error<'_> {
    fn from(_: crypto::hash::Error) -> Self {
        Self::Unspecified
    }
}

impl From<crypto::sig::Error> for Error<'_> {
    fn from(_: crypto::sig::Error) -> Self {
        Self::DecryptionFailed
    }
}

impl From<session::Error> for Error<'_> {
    fn from(_: session::Error) -> Self {
        Self::Unspecified
    }
}
