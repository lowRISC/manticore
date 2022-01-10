// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Error definitions for Cerberus messages.

use core::convert::TryFrom;
use core::convert::TryInto;

use crate::crypto;
use crate::io::ReadInt as _;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::mem::OutOfMemory;
use crate::protocol::cerberus::CommandType;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::Message;
use crate::session;
use crate::Result;

#[cfg(doc)]
use crate::protocol;

/// An uninterpreted Cerberus Error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RawError {
    /// What kind of error this is.
    pub code: u8,
    /// A fixed array of "extra data" that can come with an error code.
    pub data: [u8; 4],
}

impl<'wire> FromWire<'wire> for RawError {
    fn from_wire<R: ReadZero<'wire> + ?Sized>(
        r: &mut R,
        _: &'wire dyn Arena,
    ) -> Result<Self, wire::Error> {
        let code = r.read_le()?;
        let mut data = [0; 4];
        r.read_bytes(&mut data)?;

        Ok(Self { code, data })
    }
}

impl ToWire for RawError {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.code)?;
        w.write_bytes(&self.data[..])?;
        Ok(())
    }
}

/// An "empty" response, indicating only that a request was executed
/// successfully.
///
/// At the Cerberus wire level, this is actually a [`RawError`] with code `0`.
///
/// This command corresponds to [`CommandType::Error`] and does not have a
/// request counterpart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ack;

impl Message<'_> for Ack {
    type CommandType = CommandType;
    const TYPE: CommandType = CommandType::Error;
}

impl<'wire> FromWire<'wire> for Ack {
    fn from_wire<R: ReadZero<'wire> + ?Sized>(
        r: &mut R,
        a: &'wire dyn Arena,
    ) -> Result<Self, wire::Error> {
        RawError::from_wire(r, a)?.try_into().map_err(|e| fail!(e))
    }
}

impl ToWire for Ack {
    fn to_wire<W: Write>(&self, w: W) -> Result<(), wire::Error> {
        RawError::from(*self).to_wire(w)
    }
}

impl From<Ack> for RawError {
    fn from(_: Ack) -> RawError {
        RawError {
            code: 0,
            data: [0; 4],
        }
    }
}

impl TryFrom<RawError> for Ack {
    type Error = wire::Error;
    fn try_from(e: RawError) -> core::result::Result<Ack, wire::Error> {
        match e {
            RawError {
                code: 0,
                data: [0, 0, 0, 0],
            } => Ok(Ack),
            _ => Err(wire::Error::OutOfRange),
        }
    }
}

/// A Cerberus error.
///
/// Currently, Cerberus only provides a handful of errors; for the sake of
/// specificity, we include some vendor-specific errors until we can get
/// them into Cerberus proper.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Error {
    /// Indicates that the device is "busy", usually meaning that other
    /// commands are being serviced.
    Busy,

    /// Indicates that resources were exhausted during processing of a
    /// request. This can include memory exhaustion.
    ///
    /// This is a Manticore-specific error.
    ResourceLimit,

    /// Indicates that a request's structure was malformed.
    ///
    /// This is a Manticore-specific error.
    Malformed,

    /// Indicates that the request included an index (such as a certificate
    /// slot, a PMR index, or a port) which was out of range.
    ///
    /// This is a Manticore-specific error.
    OutOfRange,

    /// Indicates that some kind of internal error occured; this likely
    /// indicates a bug in the implementation.
    ///
    /// All `manticore::crypto` errors get folded into this error by default.
    ///
    /// This is a Manticore-specific error.
    Internal,

    /// The requested certificate chain does not exist.
    ///
    /// This is a Manticore-specific error.
    UnknownChain,

    /// Indicates an unspecified, vendor-defined error, which may include
    /// extra unformatted data.
    Unspecified([u8; 4]),

    /// An error that Manticore does not understand.
    Unknown(RawError),
}

impl Message<'_> for Error {
    type CommandType = CommandType;
    const TYPE: CommandType = CommandType::Error;
}

impl<'wire> FromWire<'wire> for Error {
    fn from_wire<R: ReadZero<'wire> + ?Sized>(
        r: &mut R,
        a: &'wire dyn Arena,
    ) -> Result<Self, wire::Error> {
        match RawError::from_wire(r, a)? {
            RawError {
                code: 3,
                data: [0, 0, 0, 0],
            } => Ok(Self::Busy),
            RawError {
                code: 4,
                data: [b, 0, 0, 0],
            } => match b {
                1 => Ok(Self::ResourceLimit),
                2 => Ok(Self::Malformed),
                3 => Ok(Self::OutOfRange),
                4 => Ok(Self::Internal),
                5 => Ok(Self::UnknownChain),
                _ => Err(fail!(wire::Error::OutOfRange)),
            },
            RawError { code: 4, data } => Ok(Self::Unspecified(data)),
            error => Ok(Self::Unknown(error)),
        }
    }
}

impl ToWire for Error {
    fn to_wire<W: Write>(&self, w: W) -> Result<(), wire::Error> {
        let raw = match self {
            Self::Busy => RawError {
                code: 3,
                data: [0; 4],
            },
            Self::ResourceLimit => RawError {
                code: 4,
                data: [1, 0, 0, 0],
            },
            Self::Malformed => RawError {
                code: 4,
                data: [2, 0, 0, 0],
            },
            Self::OutOfRange => RawError {
                code: 4,
                data: [3, 0, 0, 0],
            },
            Self::Internal => RawError {
                code: 4,
                data: [4, 0, 0, 0],
            },
            Self::UnknownChain => RawError {
                code: 4,
                data: [5, 0, 0, 0],
            },
            Self::Unspecified(data) => RawError {
                code: 4,
                data: *data,
            },
            Self::Unknown(e) => *e,
        };

        raw.to_wire(w)
    }
}

impl From<OutOfMemory> for Error {
    fn from(_: OutOfMemory) -> Self {
        Self::ResourceLimit
    }
}

impl From<crypto::csrng::Error> for Error {
    fn from(_: crypto::csrng::Error) -> Self {
        Self::Internal
    }
}

impl From<crypto::hash::Error> for Error {
    fn from(_: crypto::hash::Error) -> Self {
        Self::Internal
    }
}

impl From<crypto::sig::Error> for Error {
    fn from(_: crypto::sig::Error) -> Self {
        Self::Internal
    }
}

impl From<session::Error> for Error {
    fn from(_: session::Error) -> Self {
        Self::Internal
    }
}

debug_from!(Error => OutOfMemory, crypto::csrng::Error, crypto::hash::Error, crypto::sig::Error, session::Error);
