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

use crate::io;

pub use crate::protocol::Header;

pub mod device;
pub mod host;

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
