// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! PFM element structures.
//!
//! See [`owned::Pfm`](../type.Pfm.html).

// TODO(#60): Provide a more ergonomic way of specifying flags bytes.

use core::convert::TryInto;

use crate::crypto::ring::sha256::Builder as RingSha;
use crate::crypto::sha256;
use crate::hardware::flash::Flash;
use crate::hardware::flash::Region;
use crate::manifest;
use crate::manifest::owned;
use crate::manifest::owned::EncodingError;
use crate::manifest::pfm::ElementType;
use crate::manifest::provenance;
use crate::manifest::Error;
use crate::manifest::HashType;
use crate::manifest::ManifestType;
use crate::mem::misalign_of;
use crate::mem::Arena as _;
use crate::mem::BumpArena;

use crate::protocol::wire::WireEnum as _;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An owned PFM element.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[allow(missing_docs)]
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

/// A read-write region.
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

/// An image region.
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

    fn to_bytes(&self, padding_byte: u8) -> Result<Vec<u8>, EncodingError> {
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
                let id_len: u8 =
                    firmware_id.len().try_into().map_err(|_| {
                        EncodingError::StringTooLong(firmware_id.clone())
                    })?;
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
                    .map_err(|_| EncodingError::TooManyElements)?;
                let img_len: u8 = image_regions
                    .len()
                    .try_into()
                    .map_err(|_| EncodingError::TooManyElements)?;
                let version_len: u8 =
                    version_str.len().try_into().map_err(|_| {
                        EncodingError::StringTooLong(version_str.clone())
                    })?;
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

                    let (start, end) = rw
                        .region
                        .start_and_limit()
                        .ok_or(EncodingError::EmptyRegion)?;
                    bytes.extend_from_slice(&start.to_le_bytes());
                    bytes.extend_from_slice(&end.to_le_bytes());
                }

                for image in image_regions {
                    let reg_len: u8 = image
                        .regions
                        .len()
                        .try_into()
                        .map_err(|_| EncodingError::TooManyElements)?;
                    bytes.extend_from_slice(&[
                        image.hash_type.to_wire_value(),
                        reg_len,
                        image.flags,
                        padding_byte,
                    ]);
                    bytes.extend_from_slice(&image.hash);
                    for region in &image.regions {
                        let (start, end) = region
                            .start_and_limit()
                            .ok_or(EncodingError::EmptyRegion)?;
                        bytes.extend_from_slice(&start.to_le_bytes());
                        bytes.extend_from_slice(&end.to_le_bytes());
                    }
                }

                Ok(bytes)
            }
            Self::PlatformId { platform_id: id } => {
                let id_len: u8 = id
                    .len()
                    .try_into()
                    .map_err(|_| EncodingError::StringTooLong(id.clone()))?;
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

impl<'f, F: 'f + Flash> owned::FromUnowned<'f, F> for Element {
    type Unowned = manifest::pfm::Pfm<'f, F, provenance::Adhoc>;

    fn from_container(
        container: manifest::Container<'f, Self::Unowned, F, provenance::Adhoc>,
    ) -> Result<Vec<owned::Node<Self>>, Error> {
        let mut arena = vec![0; 2048];
        let mut arena = BumpArena::new(&mut arena);
        let pfm = manifest::pfm::Pfm::new(container);
        let sha = RingSha::new();
        let mut nodes = Vec::new();

        if let Some(id) = pfm.platform_id(&sha, &arena)? {
            nodes.push(owned::Node {
                element: Element::PlatformId {
                    platform_id: id.id_string().to_vec(),
                },
                hashed: id.entry().hash().is_some(),
                children: Vec::new(),
            })
        }
        arena.reset();

        if let Some(info) = pfm.flash_device_info(&sha, &arena)? {
            nodes.push(owned::Node {
                element: Element::FlashDevice {
                    blank_byte: info.blank_byte(),
                },
                hashed: info.entry().hash().is_some(),
                children: Vec::new(),
            })
        }
        arena.reset();

        for allowable_fw in pfm.allowable_fws() {
            let allowable_fw = allowable_fw.read(&sha, &arena)?;

            let mut node = owned::Node {
                element: Element::AllowableFw {
                    version_count: allowable_fw.firmware_count() as u8,
                    firmware_id: allowable_fw.firmware_id().to_vec(),
                    flags: allowable_fw.raw_flags(),
                },
                hashed: allowable_fw.entry().hash().is_some(),
                children: Vec::new(),
            };

            for fw in allowable_fw.firmware_versions() {
                let fw = fw.read(&sha, &arena)?;

                let mut rw_regions = Vec::new();
                for rw in fw.rw_regions() {
                    rw_regions.push(Rw {
                        flags: rw.raw_flags(),
                        region: rw.region(),
                    });
                }

                let mut image_regions = Vec::new();
                for image in fw.image_regions() {
                    image_regions.push(Image {
                        flags: image.raw_flags(),
                        hash_type: HashType::Sha256,
                        hash: *image.image_hash(),
                        regions: image.regions().collect(),
                    });
                }

                let (version_region, version_str) = fw.version();
                node.children.push(owned::Node {
                    element: Element::FwVersion {
                        version_addr: version_region.offset,
                        version_str: version_str.to_vec(),
                        rw_regions,
                        image_regions,
                    },
                    hashed: fw.entry().hash().is_some(),
                    children: Vec::new(),
                });
            }

            nodes.push(node);
            arena.reset();
        }

        Ok(nodes)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::crypto::ring::sha256;
    use crate::crypto::testdata;
    use crate::manifest::owned;
    use crate::manifest::owned::Pfm;
    use crate::manifest::Metadata;

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
        let (mut rsa, mut signer) = testdata::rsa();

        let bytes = pfm.sign(0x00, &sha, &mut signer).unwrap();
        let pfm2 =
            owned::Container::parse(&bytes, &sha, Some(&mut rsa)).unwrap();
        assert!(!pfm2.bad_signature);
        assert!(!pfm2.bad_toc_hash);
        assert!(pfm2.bad_hashes.is_empty());
        assert_eq!(pfm, pfm2.container);
    }
}
