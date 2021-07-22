// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetCert` request and response.
//!
//! This module provides a Cerberus command for requesting certificates.

use crate::io::Read;
use crate::io::Write;
use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::FromWireError;
use crate::protocol::wire::ToWire;
use crate::protocol::wire::ToWireError;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::Request;
use crate::protocol::Response;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A command for requesting a chunk of a certificate.
///
/// Corresponds to [`CommandType::GetCert`].
pub enum GetCert {}

impl<'a> Command<'a> for GetCert {
    type Req = GetCertRequest;
    type Resp = GetCertResponse<'a>;
}

/// The [`GetCert`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GetCertRequest {
    /// The slot number of the chain to read from.
    pub slot: u8,
    /// The number of the cert to request, indexed from the root.
    pub cert_number: u8,
    /// The offset in bytes from the start of the certificate to read from.
    pub offset: u16,
    /// The number of bytes to read.
    pub len: u16,
}
make_fuzz_safe!(GetCertRequest);

impl Request<'_> for GetCertRequest {
    const TYPE: CommandType = CommandType::GetCert;
}

impl<'a> FromWire<'a> for GetCertRequest {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        _: &'a A,
    ) -> Result<Self, FromWireError> {
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
}

impl<'a> ToWire for GetCertRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
        w.write_le(self.slot)?;
        w.write_le(self.cert_number)?;
        w.write_le(self.offset)?;
        w.write_le(self.len)?;
        Ok(())
    }
}

make_fuzz_safe! {
    /// The [`GetCert`] response.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct GetCertResponse<'a> as GCRWrap {
        /// The slot number of the chain to read from.
        pub slot: u8,
        /// The number of the cert to request, indexed from the root.
        pub cert_number: u8,
        /// The data read from the certificate.
        #[cfg_attr(feature = "serde", serde(borrow))]
        pub data: (&'a [u8]),
    }
}

impl<'a> Response<'a> for GetCertResponse<'a> {
    const TYPE: CommandType = CommandType::GetCert;
}

impl<'a> FromWire<'a> for GetCertResponse<'a> {
    fn from_wire<R: Read, A: Arena>(
        mut r: R,
        arena: &'a A,
    ) -> Result<Self, FromWireError> {
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
}

impl ToWire for GetCertResponse<'_> {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), ToWireError> {
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
            value: GetCertRequest { slot: 1, cert_number: 2, offset: 257, len: 255 },
        },
        response_round_trip: {
            bytes: &[0x01, 0x02, b'x', b'.', b'5', b'0', b'9'],
            value: GetCertResponse { slot: 1, cert_number: 2, data: b"x.509" },
        },
    }
}
