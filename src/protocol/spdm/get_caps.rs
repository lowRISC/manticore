// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetCaps` request and response.
//!
//! This module provides a SPDM command for negotiating protocol capabilities.

use core::mem;
use core::time::Duration;

use enumflags2::bitflags;
use enumflags2::BitFlags;

use crate::io::ReadInt as _;
use crate::protocol::spdm;
use crate::protocol::spdm::CommandType;

protocol_struct! {
    /// A command for negotiating protocol capabilities.
    type GetCaps;
    type Error<'wire> = spdm::Error<'wire>;
    const TYPE: CommandType = GetCaps;

    // NOTE: Because BitFlags does not implement Arbitrary, we're forced to
    // skip using the derives, which is what this attribute achieves.
    #![fuzz_derives_if = any()]
    struct Request {
        /// The timeout for operations involving cryptoraphy.
        pub crypto_timeout: Duration,
        /// The advertised capabilities.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde::bitflags"))]
        pub caps: BitFlags<Caps>,
        /// The maximum packet size, in bytes.
        pub max_packet_size: u32,
        /// The maximum message size, in bytes.
        pub max_message_size: u32,
    }

    fn Request::from_wire(r, a) {
        spdm::expect_zeros(r, 3)?;

        let ct_exp = r.read_le::<u8>()?;
        let crypto_timeout = Duration::from_micros(1u64 << ct_exp);
        spdm::expect_zeros(r, 2)?;

        let caps = BitFlags::<Caps>::from_wire(r, a)?;

        let max_packet_size = r.read_le::<u32>()?;
        let max_message_size = r.read_le::<u32>()?;

        Ok(Self { crypto_timeout, caps, max_packet_size, max_message_size })
    }

    fn Request::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 3)?;

        let ct_micros = self.crypto_timeout.as_micros();
        check!(ct_micros.is_power_of_two(), wire::Error::OutOfRange);
        let ct_exp = 8 * mem::size_of_val(&ct_micros) as u32 - ct_micros.leading_zeros() - 1;
        w.write_le(ct_exp as u8)?;

        spdm::write_zeros(&mut w, 2)?;

        self.caps.to_wire(&mut w)?;
        w.write_le(self.max_packet_size)?;
        w.write_le(self.max_message_size)?;
        Ok(())
    }

    // Ideally this would be a typedef of Request, but the macro currently doesn't
    // cleanly support that.
    #![fuzz_derives_if = any()]
    struct Response {
        /// The timeout for operations involving cryptoraphy.
        pub crypto_timeout: Duration,
        /// The advertised capabilities.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde::bitflags"))]
        pub caps: BitFlags<Caps>,
        /// The maximum packet size, in bytes.
        pub max_packet_size: u32,
        /// The maximum message size, in bytes.
        pub max_message_size: u32,
    }

    fn Response::from_wire(r, a) {
        spdm::expect_zeros(r, 3)?;

        let ct_exp = r.read_le::<u8>()?;
        let crypto_timeout = Duration::from_micros(1u64 << ct_exp);
        spdm::expect_zeros(r, 2)?;

        let caps = BitFlags::<Caps>::from_wire(r, a)?;

        let max_packet_size = r.read_le::<u32>()?;
        let max_message_size = r.read_le::<u32>()?;

        Ok(Self { crypto_timeout, caps, max_packet_size, max_message_size })
    }

    fn Response::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 3)?;

        let ct_micros = self.crypto_timeout.as_micros();
        check!(ct_micros.is_power_of_two(), wire::Error::OutOfRange);
        let ct_exp = 8 * mem::size_of_val(&ct_micros) as u32 - ct_micros.leading_zeros() - 1;
        w.write_le(ct_exp as u8)?;

        spdm::write_zeros(&mut w, 2)?;

        self.caps.to_wire(&mut w)?;
        w.write_le(self.max_packet_size)?;
        w.write_le(self.max_message_size)?;
        Ok(())
    }
}

#[cfg(feature = "arbitrary-derive")]
use {
    crate::protocol::arbitrary_bitflags,
    libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured},
};

#[cfg(feature = "arbitrary-derive")]
impl Arbitrary for GetCapsRequest {
    fn arbitrary(u: &mut Unstructured) -> arbitrary::Result<Self> {
        Ok(Self {
            crypto_timeout: u.arbitrary()?,
            caps: arbitrary_bitflags(u)?,
            max_packet_size: u.arbitrary()?,
            max_message_size: u.arbitrary()?,
        })
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        let size = mem::size_of::<Duration>()
            + mem::size_of::<BitFlags<Caps>>()
            + mem::size_of::<u32>() * 2;
        (size, Some(size))
    }
}

#[cfg(feature = "arbitrary-derive")]
impl Arbitrary for GetCapsResponse {
    fn arbitrary(u: &mut Unstructured) -> arbitrary::Result<Self> {
        Ok(Self {
            crypto_timeout: u.arbitrary()?,
            caps: arbitrary_bitflags(u)?,
            max_packet_size: u.arbitrary()?,
            max_message_size: u.arbitrary()?,
        })
    }

    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        let size = mem::size_of::<Duration>()
            + mem::size_of::<BitFlags<Caps>>()
            + mem::size_of::<u32>() * 2;
        (size, Some(size))
    }
}

/// SPDM protocol capability flags.
#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Caps {
    /// Whether negotiation information can be cached past a reset.
    Cache = 1 << 0,
    /// Whether certificates are supported.
    Certs = 1 << 1,
    /// Whether challenges are supported.
    Challenge = 1 << 2,
    /// Whether unsigned measurements are supported.
    UnsignedMeasurements = 1 << 3,
    /// Whether signed measurements are supported.
    SignedMeasurements = 1 << 4,
    /// Whether measurements will be recomputed on reset.
    FreshMeasurements = 1 << 5,
    /// Whether sessions will be encrypted.
    SessionEncryption = 1 << 6,
    /// Whether sessions will be authenticated with MACs.
    SessionAuth = 1 << 7,
    /// Whether mutual authentication is supported.
    MutualAuth = 1 << 8,
    /// Whether key exchange is supported.
    KeyExchange = 1 << 9,
    /// Whether pre-shared keys without context are supported.
    PskWithoutContext = 1 << 10,
    /// Whether pre-shared keys with context are supported.
    PskWithContext = 1 << 11,
    /// Whether heartbeat messages are supported.
    Heartbeat = 1 << 13,
    /// Whether mid-session key updates are supported.
    KeyUpdate = 1 << 14,
    /// Whether messages other than those needed to set up a session can
    /// be sent in the clear, this is set when *only* the handshake can be
    /// sent in the clear.
    HandshakeInTheClear = 1 << 15,
    /// Whether the requester's public key was provisioned to the device.
    PubKeyProvisioned = 1 << 16,
    /// Whether chunked messages are supported.
    Chunking = 1 << 17,
    /// Whether the alias certificate model is supported.
    AliasCert = 1 << 18,
}

impl Caps {
    /// Returns the set of capabilities a Manticore-based SPDM server will negotiate.
    pub fn manticore() -> enumflags2::BitFlags<Self> {
        Self::Certs
            | Self::Challenge
            | Self::SignedMeasurements
            | Self::FreshMeasurements
            | Self::SessionEncryption
            | Self::KeyExchange
            | Self::Heartbeat
            | Self::AliasCert
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[
                0x00, 0x00, 0x00, 0x0c, //
                0x00, 0x00, //
                0b01110110, 0b00100010, 0b00000100, 0b00000000, //
                0x00, 0x01, 0x00, 0x00, //
                0x00, 0x04, 0x00, 0x00, //
            ],
            json: r#"{
                "crypto_timeout": { "nanos": 4096000, "secs": 0 },
                "caps": [
                    "Certs",
                    "Challenge",
                    "SignedMeasurements",
                    "FreshMeasurements",
                    "SessionEncryption",
                    "KeyExchange",
                    "Heartbeat",
                    "AliasCert"
                ],
                "max_packet_size": 256,
                "max_message_size": 1024
            }"#,
            value: GetCapsRequest {
                crypto_timeout: Duration::from_micros(4096),
                caps: Caps::manticore(),
                max_packet_size: 256,
                max_message_size: 1024,
            },
        },
        response_round_trip: {
            bytes: &[
                0x00, 0x00, 0x00, 0x0c, //
                0x00, 0x00, //
                0b01110110, 0b00100010, 0b00000100, 0b00000000, //
                0x00, 0x01, 0x00, 0x00, //
                0x00, 0x04, 0x00, 0x00, //
            ],
            json: r#"{
                "crypto_timeout": { "nanos": 4096000, "secs": 0 },
                "caps": [
                    "Certs",
                    "Challenge",
                    "SignedMeasurements",
                    "FreshMeasurements",
                    "SessionEncryption",
                    "KeyExchange",
                    "Heartbeat",
                    "AliasCert"
                ],
                "max_packet_size": 256,
                "max_message_size": 1024
            }"#,
            value: GetCapsResponse {
                crypto_timeout: Duration::from_micros(4096),
                caps: Caps::manticore(),
                max_packet_size: 256,
                max_message_size: 1024,
            },
        },
    }
}
