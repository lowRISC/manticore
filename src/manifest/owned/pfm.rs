// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! PFM element structures.
//!
//! See [`owned::Pfm`](../type.Pfm.html).

use core::convert::TryInto;

use crate::crypto::sha256;
use crate::hardware::flash::Region;
use crate::io::Read as _;
use crate::manifest::container::HashType;
use crate::manifest::owned;
use crate::manifest::pfm::ElementType;
use crate::manifest::Error;
use crate::manifest::ManifestType;
use crate::mem::misalign_of;

use crate::protocol::wire::WireEnum as _;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

///
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum Element {
    FlashDevice {
        #[cfg_attr(
            feature = "serde",
            serde(
                deserialize_with = "crate::serde::de_radix",
                serialize_with = "crate::serde::se_hex",
            )
        )]
        blank_byte: u8,
    },
    AllowableFw {
        #[cfg_attr(
            feature = "serde",
            serde(deserialize_with = "crate::serde::de_radix")
        )]
        version_count: u8,
        #[cfg_attr(
            feature = "serde",
            serde(
                deserialize_with = "crate::serde::de_bytestring",
                serialize_with = "crate::serde::se_bytestring",
            )
        )]
        firmware_id: Vec<u8>,
        #[cfg_attr(
            feature = "serde",
            serde(
                deserialize_with = "crate::serde::de_radix",
                serialize_with = "crate::serde::se_bin",
            )
        )]
        flags: u8,
    },
    FwVersion {
        #[cfg_attr(
            feature = "serde",
            serde(
                deserialize_with = "crate::serde::de_radix",
                serialize_with = "crate::serde::se_hex",
            )
        )]
        version_addr: u32,
        #[cfg_attr(
            feature = "serde",
            serde(
                deserialize_with = "crate::serde::de_bytestring",
                serialize_with = "crate::serde::se_bytestring",
            )
        )]
        version_str: Vec<u8>,
        rw_regions: Vec<Rw>,
        image_regions: Vec<Image>,
    },
    PlatformId {
        #[cfg_attr(
            feature = "serde",
            serde(
                deserialize_with = "crate::serde::de_bytestring",
                serialize_with = "crate::serde::se_bytestring",
            )
        )]
        platform_id: Vec<u8>,
    },
}

///
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Rw {
    #[cfg_attr(
        feature = "serde",
        serde(
            deserialize_with = "crate::serde::de_radix",
            serialize_with = "crate::serde::se_bin",
        )
    )]
    pub flags: u8,
    pub region: Region,
}

///
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Image {
    #[cfg_attr(
        feature = "serde",
        serde(
            deserialize_with = "crate::serde::de_radix",
            serialize_with = "crate::serde::se_bin",
        )
    )]
    pub flags: u8,
    pub hash_type: HashType,
    pub hash: sha256::Digest,
    pub regions: Vec<Region>,
}

impl owned::Element for Element {
    type ElementType = ElementType;
    const TYPE: ManifestType = ManifestType::Pfm;

    fn element_type(&self) -> ElementType {
        match self {
            Self::FlashDevice { .. } => ElementType::FlashDevice,
            Self::AllowableFw { .. } => ElementType::AllowableFw,
            Self::FwVersion { .. } => ElementType::FwVersion,
            Self::PlatformId { .. } => ElementType::PlatformId,
        }
    }

    fn from_bytes(ty: ElementType, mut bytes: &[u8]) -> Result<Self, Error> {
        match ty {
            ElementType::FlashDevice => {
                let blank_byte = bytes.read_le::<u8>()?;
                Ok(Self::FlashDevice { blank_byte })
            }
            ElementType::AllowableFw => {
                let version_count = bytes.read_le::<u8>()?;
                let id_len = bytes.read_le::<u8>()? as usize;
                let flags = bytes.read_le::<u8>()?;
                let _ = bytes.read_le::<u8>()?;

                let mut firmware_id = vec![0; id_len];
                bytes.read_bytes(&mut firmware_id)?;

                Ok(Self::AllowableFw {
                    version_count,
                    firmware_id,
                    flags,
                })
            }
            ElementType::FwVersion => {
                let img_count = bytes.read_le::<u8>()?;
                let rw_count = bytes.read_le::<u8>()?;
                let version_len = bytes.read_le::<u8>()? as usize;
                let _ = bytes.read_le::<u8>()?;
                let version_addr = bytes.read_le::<u32>()?;

                let mut version_str = vec![0; version_len];
                bytes.read_bytes(&mut version_str)?;

                let misalign = misalign_of(version_str.len(), 4);
                bytes = &bytes[misalign..];

                let mut rw_regions = Vec::with_capacity(rw_count as usize);
                for _ in 0..rw_count {
                    let flags = bytes.read_le::<u8>()?;
                    let _ = bytes.read_le::<u8>()?;
                    let _ = bytes.read_le::<u8>()?;
                    let _ = bytes.read_le::<u8>()?;

                    let start_addr = bytes.read_le::<u32>()?;
                    let end_addr = bytes.read_le::<u32>()?;
                    if start_addr > end_addr {
                        return Err(Error::OutOfRange);
                    }
                    let region = Region::new(start_addr, end_addr - start_addr);

                    rw_regions.push(Rw { flags, region });
                }

                let mut image_regions = Vec::with_capacity(img_count as usize);
                for _ in 0..img_count {
                    let hash_type =
                        HashType::from_wire_value(bytes.read_le::<u8>()?)
                            .ok_or(Error::OutOfRange)?;
                    let region_count = bytes.read_le::<u8>()?;
                    let flags = bytes.read_le::<u8>()?;
                    let _ = bytes.read_le::<u8>()?;

                    let mut hash = [0; 32];
                    bytes.read_bytes(&mut hash)?;

                    let mut regions = Vec::with_capacity(region_count as usize);
                    for _ in 0..region_count {
                        let start_addr = bytes.read_le::<u32>()?;
                        let end_addr = bytes.read_le::<u32>()?;
                        if start_addr > end_addr {
                            return Err(Error::OutOfRange);
                        }

                        let region =
                            Region::new(start_addr, end_addr - start_addr);
                        regions.push(region);
                    }

                    image_regions.push(Image {
                        flags,
                        hash_type,
                        hash,
                        regions,
                    });
                }

                Ok(Self::FwVersion {
                    version_addr,
                    version_str,
                    rw_regions,
                    image_regions,
                })
            }
            ElementType::PlatformId => {
                let id_len = bytes.read_le::<u8>()? as usize;
                let _ = bytes.read_le::<u8>()?;
                let _ = bytes.read_le::<u8>()?;
                let _ = bytes.read_le::<u8>()?;

                let mut id = vec![0; id_len];
                bytes.read_bytes(&mut id)?;
                Ok(Self::PlatformId { platform_id: id })
            }
        }
    }

    fn to_bytes(&self, padding_byte: u8) -> Result<Vec<u8>, Error> {
        match self {
            Self::FlashDevice { blank_byte } => {
                let mut bytes = vec![padding_byte; 4];
                bytes[0] = *blank_byte;
                Ok(bytes)
            }
            Self::AllowableFw {
                version_count,
                firmware_id,
                flags,
            } => {
                let id_len: u8 = firmware_id
                    .len()
                    .try_into()
                    .map_err(|_| Error::OutOfRange)?;
                let mut bytes =
                    vec![*version_count, id_len, *flags, padding_byte];

                bytes.extend_from_slice(&firmware_id);
                for _ in 0..misalign_of(bytes.len(), 4) {
                    bytes.push(padding_byte);
                }

                Ok(bytes)
            }
            Self::FwVersion {
                version_addr,
                version_str,
                rw_regions,
                image_regions,
            } => {
                let rw_len: u8 = rw_regions
                    .len()
                    .try_into()
                    .map_err(|_| Error::OutOfRange)?;
                let img_len: u8 = image_regions
                    .len()
                    .try_into()
                    .map_err(|_| Error::OutOfRange)?;
                let version_len: u8 = version_str
                    .len()
                    .try_into()
                    .map_err(|_| Error::OutOfRange)?;
                let mut bytes =
                    vec![img_len, rw_len, version_len, padding_byte];
                bytes.extend_from_slice(&version_addr.to_le_bytes());

                bytes.extend_from_slice(&version_str);
                for _ in 0..misalign_of(bytes.len(), 4) {
                    bytes.push(padding_byte);
                }

                for rw in rw_regions {
                    let mut header = [padding_byte; 4];
                    header[0] = rw.flags;
                    bytes.extend_from_slice(&header);

                    bytes.extend_from_slice(&rw.region.offset.to_le_bytes());
                    let end = rw.region.offset + rw.region.len;
                    bytes.extend_from_slice(&end.to_le_bytes());
                }

                for image in image_regions {
                    let reg_len: u8 = image
                        .regions
                        .len()
                        .try_into()
                        .map_err(|_| Error::OutOfRange)?;
                    bytes.extend_from_slice(&[
                        image.hash_type.to_wire_value(),
                        reg_len,
                        image.flags,
                        padding_byte,
                    ]);
                    bytes.extend_from_slice(&image.hash);
                    for region in &image.regions {
                        bytes.extend_from_slice(&region.offset.to_le_bytes());
                        let end = region.offset + region.len;
                        bytes.extend_from_slice(&end.to_le_bytes());
                    }
                }

                Ok(bytes)
            }
            Self::PlatformId { platform_id: id } => {
                let id_len: u8 =
                    id.len().try_into().map_err(|_| Error::OutOfRange)?;
                let mut bytes = vec![padding_byte; 4];
                bytes[0] = id_len;

                bytes.extend_from_slice(&id);
                for _ in 0..misalign_of(bytes.len(), 4) {
                    bytes.push(padding_byte);
                }

                Ok(bytes)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::crypto::ring::sha256;
    use crate::manifest::container::test::make_rsa_engine;
    use crate::manifest::container::Metadata;
    use crate::manifest::owned;
    use crate::manifest::owned::Pfm;

    use pretty_assertions::assert_eq;
    use serde_json::from_str;

    #[test]
    fn parse_empty() {
        #[rustfmt::skip]
        let pfm: Pfm = from_str(r#"{
            "version_id": 42,
            "elements": []
        }"#).unwrap();

        assert_eq!(
            pfm,
            owned::Container {
                metadata: Metadata { version_id: 42 },
                elements: vec![],
            }
        );
    }

    #[test]
    fn parse_platform_id() {
        #[rustfmt::skip]
        let pfm: Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [{
                "platform_id": "my cool platform"
            }]
        }"#).unwrap();

        assert_eq!(
            pfm,
            owned::Container {
                metadata: Metadata { version_id: 42 },
                elements: vec![owned::Node {
                    element: Element::PlatformId {
                        platform_id: b"my cool platform".to_vec(),
                    },
                    children: vec![],
                    hashed: true,
                }],
            }
        );
    }

    #[test]
    fn parse_firmwares() {
        #[rustfmt::skip]
        let pfm: Pfm = from_str(r#"{
            "version_id": 42,
            "elements": [
                { "blank_byte": "0xff" },
                {
                    "version_count": 1,
                    "firmware_id": "my cool firmware",
                    "flags": "0b10101010",
                    "hashed": false,
                    "children": [{
                        "version_addr": "0x12345678",
                        "version_str": "ver-1.2.2",
                        "rw_regions": [{
                            "flags": "0b00110011",
                            "region": {
                                "offset": "0x00008000",
                                "len": "0x8000"
                            }
                        }],
                        "image_regions": [
                            {
                                "flags": "0o7",
                                "hash_type": "Sha256",
                                "hash": [
                                    42, 42, 42, 42, 42, 42, 42, 42,
                                    42, 42, 42, 42, 42, 42, 42, 42,
                                    42, 42, 42, 42, 42, 42, 42, 42,
                                    42, 42, 42, 42, 42, 42, 42, 42
                                ],
                                "regions": [
                                    { "offset": "0x10000", "len": "0x1000" },
                                    { "offset": "0x18000", "len": "0x800" }
                                ]
                            },
                            {
                                "flags": 0,
                                "hash_type": "Sha256",
                                "hash": [
                                    77, 77, 77, 77, 77, 77, 77, 77,
                                    77, 77, 77, 77, 77, 77, 77, 77,
                                    77, 77, 77, 77, 77, 77, 77, 77,
                                    77, 77, 77, 77, 77, 77, 77, 77
                                ],
                                "regions": [
                                    { "offset": "0x20000", "len": "0x800" },
                                    { "offset": "0x28000", "len": "0x1000" }
                                ]
                            }
                        ]
                    }]
                }
            ]
        }"#).unwrap();

        assert_eq!(
            pfm,
            owned::Container {
                metadata: Metadata { version_id: 42 },
                elements: vec![
                    owned::Node {
                        element: Element::FlashDevice { blank_byte: 0xff },
                        children: vec![],
                        hashed: true,
                    },
                    owned::Node {
                        element: Element::AllowableFw {
                            version_count: 1,
                            firmware_id: b"my cool firmware".to_vec(),
                            flags: 0xaa,
                        },
                        children: vec![owned::Node {
                            element: Element::FwVersion {
                                version_addr: 0x12345678,
                                version_str: b"ver-1.2.2".to_vec(),
                                rw_regions: vec![Rw {
                                    flags: 0b00110011,
                                    region: Region::new(0x8000, 0x8000),
                                }],
                                image_regions: vec![
                                    Image {
                                        flags: 0o7,
                                        hash_type: HashType::Sha256,
                                        hash: [42; 32],
                                        regions: vec![
                                            Region::new(0x10000, 0x1000),
                                            Region::new(0x18000, 0x800),
                                        ],
                                    },
                                    Image {
                                        flags: 0,
                                        hash_type: HashType::Sha256,
                                        hash: [77; 32],
                                        regions: vec![
                                            Region::new(0x20000, 0x800),
                                            Region::new(0x28000, 0x1000),
                                        ],
                                    },
                                ],
                            },
                            children: vec![],
                            hashed: true,
                        }],
                        hashed: false,
                    },
                ],
            }
        );
    }

    #[test]
    fn round_trip() {
        let pfm = owned::Container {
            metadata: Metadata { version_id: 42 },
            elements: vec![
                owned::Node {
                    element: Element::PlatformId {
                        platform_id: b"abcdfg".to_vec(),
                    },
                    children: vec![],
                    hashed: false,
                },
                owned::Node {
                    element: Element::FlashDevice { blank_byte: 0xff },
                    children: vec![],
                    hashed: true,
                },
                owned::Node {
                    element: Element::AllowableFw {
                        version_count: 1,
                        firmware_id: b"my cool firmware".to_vec(),
                        flags: 0xaa,
                    },
                    children: vec![owned::Node {
                        element: Element::FwVersion {
                            version_addr: 0x12345678,
                            version_str: b"ver-1.2.2".to_vec(),
                            rw_regions: vec![Rw {
                                flags: 0b00110011,
                                region: Region::new(0x8000, 0x8000),
                            }],
                            image_regions: vec![
                                Image {
                                    flags: 0o7,
                                    hash_type: HashType::Sha256,
                                    hash: [42; 32],
                                    regions: vec![
                                        Region::new(0x10000, 0x1000),
                                        Region::new(0x18000, 0x800),
                                    ],
                                },
                                Image {
                                    flags: 0,
                                    hash_type: HashType::Sha256,
                                    hash: [77; 32],
                                    regions: vec![
                                        Region::new(0x20000, 0x800),
                                        Region::new(0x28000, 0x1000),
                                    ],
                                },
                            ],
                        },
                        children: vec![],
                        hashed: true,
                    }],
                    hashed: false,
                },
            ],
        };
        let sha = sha256::Builder::new();
        let (mut rsa, mut signer) = make_rsa_engine();

        let bytes = pfm.sign(0x00, &sha, &mut signer).unwrap();
        let pfm2 = owned::Container::parse(&bytes, &sha, &mut rsa).unwrap();
        assert!(!pfm2.bad_signature);
        assert!(!pfm2.bad_toc_hash);
        assert!(pfm2.bad_hashes.is_empty());
        assert_eq!(pfm, pfm2.container);
    }
}
