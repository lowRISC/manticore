// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetCert` request and response.
//!
//! This module provides a Cerberus command for requesting certificates.

use crate::io::ReadInt as _;
use crate::mem::ArenaExt as _;
use crate::protocol::ChallengeError;
use crate::protocol::CommandType;

protocol_struct! {
    /// A command for requesting a chunk of a certificate.
    type GetCert;
    type Error = ChallengeError;
    const TYPE: CommandType = GetCert;

    struct Request {
        /// The slot number of the chain to read from.
        pub slot: u8,
        /// The number of the cert to request, indexed from the root.
        pub cert_number: u8,
        /// The offset in bytes from the start of the certificate to read from.
        pub offset: u16,
        /// The number of bytes to read.
        pub len: u16,
    }

    fn Request::from_wire(r, _) {
        let slot = r.read_le()?;
        let cert_number = r.read_le()?;
        let offset = r.read_le()?;
        let len = r.read_le()?;
        Ok(Self {
            slot,
            cert_number,
            offset,
            len,
        })
    }

    fn Request::to_wire(&self, w) {
        w.write_le(self.slot)?;
        w.write_le(self.cert_number)?;
        w.write_le(self.offset)?;
        w.write_le(self.len)?;
        Ok(())
    }

    struct Response<'wire> {
        /// The slot number of the chain to read from.
        pub slot: u8,
        /// The number of the cert to request, indexed from the root.
        pub cert_number: u8,
        /// The data read from the certificate.
        #[cfg_attr(feature = "serde", serde(
            serialize_with = "crate::serde::se_hexstring",
        ))]
        #[@static(cfg_attr(feature = "serde", serde(
            deserialize_with = "crate::serde::de_hexstring",
        )))]
        pub data: &'wire [u8],
    }

    fn Response::from_wire(r, arena) {
        let slot = r.read_le()?;
        let cert_number = r.read_le()?;

        let data_len = r.remaining_data();
        let data = arena.alloc_slice::<u8>(data_len)?;
        r.read_bytes(data)?;
        Ok(Self {
            slot,
            cert_number,
            data,
        })
    }

    fn Response::to_wire(&self, w) {
        w.write_le(self.slot)?;
        w.write_le(self.cert_number)?;
        w.write_bytes(self.data)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x01, 0x02, 0x01, 0x01, 0xff, 0x00],
            json: r#"{
                "slot": 1,
                "cert_number": 2,
                "offset": 257,
                "len": 255
            }"#,
            value: GetCertRequest {
                slot: 1,
                cert_number: 2,
                offset: 257,
                len: 255,
            },
        },
        response_round_trip: {
            bytes: &[0x01, 0x02, b'x', b'.', b'5', b'0', b'9'],
            json: r#"{
                "slot": 1,
                "cert_number": 2,
                "data": "782e353039"
            }"#,
            value: GetCertResponse {
                slot: 1,
                cert_number: 2,
                data: b"x.509",
            },
        },
    }
}
