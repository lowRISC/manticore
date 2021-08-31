// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetDigests` request and response.
//!
//! This module provides a Cerberus command for extracting hashes of certs
//! in a chain.

use core::convert::TryInto as _;

use zerocopy::AsBytes as _;

use crate::crypto::sha256;
use crate::io::ReadInt as _;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::Request;
use crate::protocol::Response;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A command for requesting certificate hashes.
///
/// Corresponds to [`CommandType::GetDigests`].
pub enum GetDigests {}

impl<'wire> Command<'wire> for GetDigests {
    type Req = GetDigestsRequest;
    type Resp = GetDigestsResponse<'wire>;
}

wire_enum! {
    /// A key exchange algorithm.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum KeyExchangeAlgo: u8 {
        /// No key exchange.
        None = 0b00,
        /// Elliptic-curve Diffe-Hellman.
        Ecdh = 0b01,
    }
}

/// The [`GetDigests`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GetDigestsRequest {
    /// The slot number of the chain to read from.
    pub slot: u8,
    /// The key exchange algorithm to eventually use.
    ///
    /// Manticore currently ignores this field.
    pub key_exchange: KeyExchangeAlgo,
}
make_fuzz_safe!(GetDigestsRequest);

impl Request<'_> for GetDigestsRequest {
    const TYPE: CommandType = CommandType::GetDigests;
}

impl<'wire> FromWire<'wire> for GetDigestsRequest {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        a: &'wire A,
    ) -> Result<Self, wire::Error> {
        let slot = r.read_le()?;
        let key_exchange = KeyExchangeAlgo::from_wire(r, a)?;
        Ok(Self { slot, key_exchange })
    }
}

impl ToWire for GetDigestsRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.slot)?;
        self.key_exchange.to_wire(w)?;
        Ok(())
    }
}

make_fuzz_safe! {
    /// The [`GetDigests`] response.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct GetDigestsResponse<'wire> {
        /// The digests of each certificate in the chain, starting from the
        /// root.
        #[cfg_attr(feature = "serde",
                   serde(deserialize_with = "crate::serde::de_slice_of_u8_arrays"))]
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub digests: &'wire [sha256::Digest],
    }
}

impl<'wire> Response<'wire> for GetDigestsResponse<'wire> {
    const TYPE: CommandType = CommandType::GetDigests;
}

impl<'wire> FromWire<'wire> for GetDigestsResponse<'wire> {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        arena: &'wire A,
    ) -> Result<Self, wire::Error> {
        let capabilities = r.read_le::<u8>()?;
        if capabilities != 1 {
            return Err(wire::Error::OutOfRange);
        }

        let digests =
            arena.alloc_slice::<sha256::Digest>(r.read_le::<u8>()? as usize)?;
        r.read_bytes(digests.as_bytes_mut())?;
        Ok(Self { digests })
    }
}

impl ToWire for GetDigestsResponse<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(1u8)?; // "Capabilities" byte; must be one.

        let digests_len: u8 = self
            .digests
            .len()
            .try_into()
            .map_err(|_| wire::Error::OutOfRange)?;
        w.write_le(digests_len)?;
        w.write_bytes(self.digests.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x01, 0x00],
            value: GetDigestsRequest { slot: 1, key_exchange: KeyExchangeAlgo::None },
        },
        request_round_trip2: {
            bytes: &[0x05, 0x01],
            value: GetDigestsRequest { slot: 5, key_exchange: KeyExchangeAlgo::Ecdh },
        },
        response_round_trip: {
            bytes: &[
                0x01, 0x02, // Capabilities, digest #

                // Digest #1.
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,

                // Digest #2.
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            ],
            value: GetDigestsResponse { digests: &[[0xaa; 32], [0x11; 32]], },
        },
    }
}
