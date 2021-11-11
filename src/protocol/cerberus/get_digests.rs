// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetDigests` request and response.
//!
//! This module provides a Cerberus command for extracting hashes of certs
//! in a chain.

use core::convert::TryInto as _;

use zerocopy::AsBytes as _;

use crate::crypto::hash;
use crate::io::ReadInt as _;
use crate::mem::ArenaExt as _;
use crate::protocol::cerberus::CommandType;

protocol_struct! {
    /// A command for requesting certificate hashes.
    type GetDigests;
    const TYPE: CommandType = GetDigests;

    struct Request {
        /// The slot number of the chain to read from.
        pub slot: u8,
        /// The key exchange algorithm to eventually use.
        ///
        /// Manticore currently ignores this field.
        pub key_exchange: KeyExchangeAlgo,
    }

    fn Request::from_wire(r, a) {
        let slot = r.read_le()?;
        let key_exchange = KeyExchangeAlgo::from_wire(r, a)?;
        Ok(Self { slot, key_exchange })
    }

    fn Request::to_wire(&self, w) {
        w.write_le(self.slot)?;
        self.key_exchange.to_wire(w)?;
        Ok(())
    }

    struct Response<'wire> {
        /// The digests of each certificate in the chain, starting from the
        /// root.
        #[cfg_attr(feature = "serde", serde(
            serialize_with = "crate::serde::se_hexstrings",
        ))]
        #[@static(cfg_attr(feature = "serde", serde(
            deserialize_with = "crate::serde::de_hexstrings",
        )))]
        pub digests: &'wire [[u8; hash::Algo::Sha256.bytes()]],
    }

    fn Response::from_wire(r, arena) {
        let capabilities = r.read_le::<u8>()?;
        if capabilities != 1 {
            return Err(wire::Error::OutOfRange);
        }

        let digests = arena.alloc_slice(r.read_le::<u8>()? as usize)?;
        r.read_bytes(digests.as_bytes_mut())?;
        Ok(Self { digests })
    }

    fn Response::to_wire(&self, w) {
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

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

wire_enum! {
    /// A key exchange algorithm.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum KeyExchangeAlgo: u8 {
        /// No key exchange.
        None = 0b00,
        /// Elliptic-curve Diffe-Hellman.
        Ecdh = 0b01,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x01, 0x00],
            json: r#"{
                "slot": 1,
                "key_exchange": "None"
            }"#,
            value: GetDigestsRequest {
                slot: 1,
                key_exchange: KeyExchangeAlgo::None,
            },
        },
        request_round_trip2: {
            bytes: &[0x05, 0x01],
            json: r#"{
                "slot": 5,
                "key_exchange": "Ecdh"
            }"#,
            value: GetDigestsRequest {
                slot: 5,
                key_exchange: KeyExchangeAlgo::Ecdh,
            },
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
            json: r#"{
                "digests": [
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "1111111111111111111111111111111111111111111111111111111111111111"
                ]
            }"#,
            value: GetDigestsResponse {
                digests: &[[0xaa; 32], [0x11; 32]],
            },
        },
    }
}
