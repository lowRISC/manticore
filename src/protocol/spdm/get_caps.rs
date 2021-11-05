// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetCaps` request and response.
//!
//! This module provides a SPDM command for negotiating protocol capabilities.

use core::mem;
use core::time::Duration;

use bitflags::bitflags;

use crate::io::ReadInt as _;
use crate::protocol::spdm;
use crate::protocol::spdm::CommandType;

protocol_struct! {
    /// A command for negotiating protocol capabilities.
    type GetCaps;
    const TYPE: CommandType = GetCaps;

    struct Request {
        /// The timeout for operations involving cryptoraphy.
        pub crypto_timeout: Duration,
        /// The advertised capabilities.
        pub caps: Capabilities,
        /// The maximum packet size, in bytes.
        pub max_packet_size: u32,
        /// The maximum message size, in bytes.
        pub max_message_size: u32,
    }

    fn Request::from_wire(r, _) {
        spdm::expect_zeros(r, 3)?;

        let ct_exp = r.read_le::<u8>()?;
        let crypto_timeout = Duration::from_micros(1u64 << ct_exp);
        spdm::expect_zeros(r, 2)?;

        let caps = Capabilities::from_bits_truncate(r.read_le()?);

        let max_packet_size = r.read_le::<u32>()?;
        let max_message_size = r.read_le::<u32>()?;

        Ok(Self { crypto_timeout, caps, max_packet_size, max_message_size })
    }

    fn Request::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 3)?;

        let ct_micros = self.crypto_timeout.as_micros();
        if !ct_micros.is_power_of_two() {
            return Err(wire::Error::OutOfRange);
        }
        let ct_exp = 8 * mem::size_of_val(&ct_micros) as u32 - ct_micros.leading_zeros() - 1;
        w.write_le(ct_exp as u8)?;

        spdm::write_zeros(&mut w, 2)?;

        w.write_le(self.caps.bits())?;
        w.write_le(self.max_packet_size)?;
        w.write_le(self.max_message_size)?;
        Ok(())
    }

    // Ideally this would be a typedef of Request, but the macro currently doesn't
    // cleanly support that.
    struct Response {
        /// The timeout for operations involving cryptoraphy.
        pub crypto_timeout: Duration,
        /// The advertised capabilities.
        pub caps: Capabilities,
        /// The maximum packet size, in bytes.
        pub max_packet_size: u32,
        /// The maximum message size, in bytes.
        pub max_message_size: u32,
    }

    fn Response::from_wire(r, _) {
        spdm::expect_zeros(r, 3)?;

        let ct_exp = r.read_le::<u8>()?;
        let crypto_timeout = Duration::from_micros(1u64 << ct_exp);
        spdm::expect_zeros(r, 2)?;

        let caps = Capabilities::from_bits_truncate(r.read_le()?);

        let max_packet_size = r.read_le::<u32>()?;
        let max_message_size = r.read_le::<u32>()?;

        Ok(Self { crypto_timeout, caps, max_packet_size, max_message_size })
    }

    fn Response::to_wire(&self, w) {
        spdm::write_zeros(&mut w, 3)?;

        let ct_micros = self.crypto_timeout.as_micros();
        if !ct_micros.is_power_of_two() {
            return Err(wire::Error::OutOfRange);
        }
        let ct_exp = 8 * mem::size_of_val(&ct_micros) as u32 - ct_micros.leading_zeros() - 1;
        w.write_le(ct_exp as u8)?;

        spdm::write_zeros(&mut w, 2)?;

        w.write_le(self.caps.bits())?;
        w.write_le(self.max_packet_size)?;
        w.write_le(self.max_message_size)?;
        Ok(())
    }
}

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};

bitflags! {
    /// SPDM protocol capability flags.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Capabilities: u32 {
        /// Whether negotiation information can be cached past a reset.
        const CACHE = 1 << 0;
        /// Whether certificates are supported.
        const CERTS = 1 << 1;
        /// Whether challenges are supported.
        const CHALLENGE = 1 << 2;
        /// Whether unsigned measurements are supported.
        const UNSIGNED_MEASUREMENTS = 1 << 3;
        /// Whether signed measurements are supported.
        const SIGNED_MEASUREMENTS = 1 << 4;
        /// Whether measurements will be recomputed on reset.
        const FRESH_MEASUREMENTS = 1 << 5;
        /// Whether sessions will be encrypted.
        const SESSION_ENCRYPTION = 1 << 6;
        /// Whether sessions will be authenticated with MACs.
        const SESSION_AUTH = 1 << 7;
        /// Whether mutual authentication is supported.
        const MUTUAL_AUTH = 1 << 8;
        /// Whether key exchange is supported.
        const KEY_EXCHANGE = 1 << 9;
        /// Whether pre-shared keys without context are supported.
        const PSK_WITHOUT_CONTEXT = 1 << 10;
        /// Whether pre-shared keys with context are supported.
        const PSK_WITH_CONTEXT = 1 << 11;
        /// Whether heartbeat messages are supported.
        const HEARTBEAT = 1 << 13;
        /// Whether mid-session key updates are supported.
        const KEY_UPDATE = 1 << 14;
        /// Whether messages other than those needed to set up a session can
        /// be sent in the clear; this is set when *only* the handshake can be
        /// sent in the clear.
        const HANDSHAKE_IN_THE_CLEAR = 1 << 15;
        /// Whether the requester's public key was provisioned to the device.
        const PUB_KEY_PROVISIONED = 1 << 16;
        /// Whether chunked messages are supported.
        const CHUNKING = 1 << 17;
        /// Whether the alias certificate model is supported.
        const ALIAS_CERT = 1 << 18;

    }
}

impl Capabilities {
    /// Returns the set of capabilities a Manticore-based SPDM server will negotiate.
    pub fn manticore() -> Self {
        Self::CERTS
            | Self::CHALLENGE
            | Self::SIGNED_MEASUREMENTS
            | Self::FRESH_MEASUREMENTS
            | Self::SESSION_ENCRYPTION
            | Self::KEY_EXCHANGE
            | Self::HEARTBEAT
            | Self::ALIAS_CERT
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
                "caps": { "bits": 270966 },
                "max_packet_size": 256,
                "max_message_size": 1024
            }"#,
            value: GetCapsRequest {
                crypto_timeout: Duration::from_micros(4096),
                caps: Capabilities::manticore(),
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
                "caps": { "bits": 270966 },
                "max_packet_size": 256,
                "max_message_size": 1024
            }"#,
            value: GetCapsResponse {
                crypto_timeout: Duration::from_micros(4096),
                caps: Capabilities::manticore(),
                max_packet_size: 256,
                max_message_size: 1024,
            },
        },
    }
}
