// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `Challenge` request and response.
//!
//! This module provides the Cerberus challenge command.

use core::convert::TryInto as _;

use crate::io;
use crate::io::Read;
use crate::io::ReadInt as _;
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

/// A command for challenging an RoT.
///
/// Corresponds to [`CommandType::Challenge`].
pub enum Challenge {}

impl<'a> Command<'a> for Challenge {
    type Req = ChallengeRequest<'a>;
    type Resp = ChallengeResponse<'a>;
}

make_fuzz_safe! {
    /// The [`Challenge`] request.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct ChallengeRequest<'a> as CRWrap {
        /// The slot number of the chain to read from.
        pub slot: u8,
        /// A requester-chosen random nonce.
        #[cfg_attr(feature = "serde",
                   serde(deserialize_with = "crate::serde::de_u8_array_ref"))]
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub nonce: (&'a [u8; 32]),
    }
}

impl<'a> Request<'a> for ChallengeRequest<'a> {
    const TYPE: CommandType = CommandType::Challenge;
}

impl<'a> FromWire<'a> for ChallengeRequest<'a> {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        arena: &'a A,
    ) -> Result<Self, wire::Error> {
        let slot = r.read_le()?;
        let _: u8 = r.read_le()?;
        let nonce = arena.alloc::<[u8; 32]>()?;
        r.read_bytes(nonce)?;
        Ok(Self { slot, nonce })
    }
}

impl ToWire for ChallengeRequest<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.slot)?;
        w.write_le(0u8)?;
        w.write_bytes(self.nonce)?;
        Ok(())
    }
}

make_fuzz_safe! {
    /// The [`Challenge`] response.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct ChallengeResponse<'a> as CR2Wrap {
        /// The slot number of the chain to read from.
        pub slot: u8,
        /// The "certificate slot mask" (Cerberus does not elaborate further).
        ///
        /// Manticore ignores this value.
        pub slot_mask: u8,
        /// The minimum and maximum versions of Cerberus supported.
        ///
        /// Manticore ignores this value.
        pub protocol_range: (u8, u8),
        /// A responder-chosen random nonce.
        #[cfg_attr(feature = "serde",
                   serde(deserialize_with = "crate::serde::de_u8_array_ref"))]
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub nonce: (&'a [u8; 32]),
        /// The number of "components" used to generate PMR0.
        pub pmr0_components: u8,
        /// The value of the PMR0 measurement.
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub pmr0: (&'a [u8]),
        /// The challenge signature.
        ///
        /// This is a signature over the concatenation of the corresponding
        /// request and the response up to the signature.
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub signature: (&'a [u8]),
    }
}

impl<'a> Response<'a> for ChallengeResponse<'a> {
    const TYPE: CommandType = CommandType::Challenge;
}

impl<'a> FromWire<'a> for ChallengeResponse<'a> {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        arena: &'a A,
    ) -> Result<Self, wire::Error> {
        let slot = r.read_le()?;
        let slot_mask = r.read_le()?;
        let min_version = r.read_le()?;
        let max_version = r.read_le()?;
        let _: u16 = r.read_le()?;

        let nonce = arena.alloc::<[u8; 32]>()?;
        r.read_bytes(nonce)?;

        let pmr0_components = r.read_le()?;
        let pmr0 = arena.alloc_slice::<u8>(r.read_le::<u8>()? as usize)?;
        r.read_bytes(pmr0)?;

        let signature = arena.alloc_slice::<u8>(r.remaining_data())?;
        r.read_bytes(signature)?;
        Ok(Self {
            slot,
            slot_mask,
            protocol_range: (min_version, max_version),
            nonce,
            pmr0_components,
            pmr0,
            signature,
        })
    }
}

impl ToWire for ChallengeResponse<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        w.write_le(self.slot)?;
        w.write_le(self.slot_mask)?;
        w.write_le(self.protocol_range.0)?;
        w.write_le(self.protocol_range.1)?;
        w.write_le(0u16)?;
        w.write_bytes(self.nonce)?;
        w.write_le(self.pmr0_components)?;
        w.write_le::<u8>(
            self.pmr0
                .len()
                .try_into()
                .map_err(|_| wire::Error::Io(io::Error::BufferExhausted))?,
        )?;
        w.write_bytes(self.pmr0)?;
        w.write_bytes(self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[
                0x01, 0x00,  // Slot #, reserved.

                // Nonce.
                0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
            ],
            value: ChallengeRequest { slot: 1, nonce: &[0x77; 32] },
        },
        response_round_trup: {
            bytes: &[
                0x01, 0xff, 0x05, 0x07,  // Slot #, slot mask, min, max.
                0x00, 0x00,              // Reserved.

                // Nonce.
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,

                0x0a, 0x04,  // Component #, PMR len.
                b'p', b'm', b'r', b'0',

                // Signature.
                b'e', b'c', b'd', b's', b'a',
            ],
            value: ChallengeResponse {
                slot: 1,
                slot_mask: 255,
                protocol_range: (5, 7),
                nonce: &[0xdd; 32],
                pmr0_components: 10,
                pmr0: b"pmr0",
                signature: b"ecdsa",
            },
        },
    }
}
