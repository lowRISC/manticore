// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `GetPfmId` request and response.
//!
//! This module provides a Cerberus command that allows the querying of the reset state of the host
//! processor protected by Cerberus.

use crate::io::read::ReadZeroExt as _;
use crate::io::ReadInt as _;
use crate::protocol::cerberus::CommandType;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

protocol_struct! {
    /// A command for requesting the PFM Version or Platform ID.
    ///
    /// The encoding of the response structure diverges from that of the
    /// specification. The spec requires that we know the original request in
    /// order to parse the response. As of now, we will be diverging from that.
    /// Instead, we encode and decode this with an extra byte that indicates
    /// whether the response contains an `IdentifierType::Version` or
    /// `IdentifierType::Platform` and the encoding of this follows that of the
    /// request.
    ///
    /// The encoding is as follows:
    ///
    /// 1 - PfmValidity (0 or 1)
    /// 2 - IdentifierType (as encoded in the request)
    /// 3:N - Identifier
    ///       - If `Version` this will be exactly 4 bytes
    ///       - If `Platform` this will be an ASCII string (not null terminated).
    type GetPfmId;
    const TYPE: CommandType = GetPfmId;

    struct Request {
        /// The port of the device whose PFM Id is being looked up.
        #[cfg_attr(feature = "serde", serde(with = "crate::serde::hex"))]
        pub port_id: u8,
        /// The PFM Region (Active or Pending).
        pub pfm_region: PfmRegion,
        /// The ID Type (Version or Platform).
        pub identifier: IdentifierType,
    }

    fn Request::from_wire(r, arena) {
        let port_id = r.read_le()?;
        let pfm_region = PfmRegion::from_wire(r, arena)?;
        let identifier = if r.remaining_data() > 0 {
            IdentifierType::from_wire(r, arena)?
        } else {
            // If missing, default identifier is `Version`
            IdentifierType::Version
        };
        Ok(Self {
            port_id,
            pfm_region,
            identifier,
        })
    }

    fn Request::to_wire(&self, w) {
        w.write_le(self.port_id)?;
        self.pfm_region.to_wire(&mut w)?;
        // TODO(#153): If `IdentifierType::Version` do we skip to save bytes?
        self.identifier.to_wire(&mut w)?;
        Ok(())
    }

    struct Response<'wire> {
        /// PFM validity.
        pub pfm_valid: PfmValidity,
        /// PFM Identifier (either Version or Platform).
        pub pfm_id: Identifier<'wire>,
    }

    fn Response::from_wire(r, arena) {
        let pfm_valid = PfmValidity::from_wire(r, arena)?;
        let identifier = IdentifierType::from_wire(r, arena)?;
        let pfm_id = match identifier {
            IdentifierType::Version => {
                let version: u32 = r.read_le()?;
                Identifier::Version {id: version}
            }
            IdentifierType::Platform => {
                let bytes = r.read_slice(r.remaining_data(), arena)?;
                Identifier::Platform{id: bytes}
            }
        };
        Ok(Self { pfm_valid, pfm_id })
    }

    fn Response::to_wire(&self, w) {
        self.pfm_valid.to_wire(&mut w)?;
        match self.pfm_id {
            Identifier::Version{id} => {
                IdentifierType::Version.to_wire(&mut w)?;
                w.write_le(id)?;
            }
            Identifier::Platform{id} => {
                IdentifierType::Platform.to_wire(&mut w)?;
                w.write_bytes(id)?;
            }
        }
        Ok(())
    }
}

wire_enum! {
    /// PFM Region.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum PfmRegion: u8 {
        /// PFM Region Active
        Active = 0x00,
        /// PFM Region Pending
        Pending = 0x01,
    }
}

wire_enum! {
    /// The id type requested.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum IdentifierType: u8 {
        /// PFM Version ID
        Version = 0x00,
        /// PFM Platform ID
        Platform = 0x01,
    }
}

wire_enum! {
    /// The id type requested.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum PfmValidity: u8 {
        /// PFM is valid
        Valid = 0x00,
        /// PFM is invalid
        Invalid = 0x01,
    }
}

derive_borrowed!(PfmValidity);

derive_borrowed! {
    /// The PFM Identifier (either platform or version).
    // #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize))]
    #[@static(
        derive(Clone, PartialEq, Eq, Debug),
        cfg_attr(feature = "serde", derive(serde::Deserialize)),
        cfg_attr(feature = "arbitrary-derive", derive(Arbitrary)),
    )]
    // TODO(#151): Change to tuple variants.
    pub enum Identifier<'a> {
        /// Identifier of type Version. Set when `IdentifierType::Version` is set
        /// in request. Uses a 4-byte identifier.
        Version {
            /// The ID.
            id: u32,
        },
        /// Identifier of type Platform. Set when `IdentifierType::Platform` is set
        /// in request. Uses an ASCII delimited String.
        Platform {
            /// The ID.
            id: &'a [u8],
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[0x7f, 0x01, 0x00],
            json: r#"{
                "port_id": "0x7f",
                "pfm_region": "Pending",
                "identifier": "Version"
            }"#,
            value: GetPfmIdRequest {
                port_id: 0x7f,
                pfm_region: PfmRegion::Pending,
                identifier: IdentifierType::Version
            },
        },
        response_round_trip: {
            bytes: &[0x00, 0x01, 0x01, 0x02, 0x03],
            json: r#"{
                "pfm_valid": "Valid",
                "pfm_id": {
                    "Platform": { "id": [1, 2, 3] }
                }
            }"#,
            value: GetPfmIdResponse {
                pfm_valid:  PfmValidity::Valid,
                pfm_id: Identifier::Platform{id: &[0x01, 0x02, 0x03]}
            },
        },
    }
}
