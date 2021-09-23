// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `DeviceCapabilities` request and response
//!
//! This module provides types that describe "device capabilities", such as
//! a device's ability to buffer messages or to perform cryptography, used
//! to negotiate a common ground between a Cerberus device and its client.

use core::time::Duration;
use core::{u32, u8};

use bitflags::bitflags;

use crate::io::bit_buf::BitBuf;
use crate::io::ReadInt as _;
use crate::io::ReadZero;
use crate::io::Write;
use crate::mem::Arena;
use crate::protocol::wire;
use crate::protocol::wire::FromWire;
use crate::protocol::wire::ToWire;
use crate::protocol::wire::WireEnum;
use crate::protocol::Command;
use crate::protocol::CommandType;
use crate::protocol::NoSpecificError;
use crate::protocol::Request;
use crate::protocol::Response;

#[cfg(feature = "arbitrary-derive")]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A command for negotiating shared device capabilities.
///
/// Corresponds to [`CommandType::DeviceCapabilities`].
pub enum DeviceCapabilities {}

impl Command<'_> for DeviceCapabilities {
    type Req = DeviceCapabilitiesRequest;
    type Resp = DeviceCapabilitiesResponse;
    type Error = NoSpecificError;
}

/// The [`DeviceCapabilities`] request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceCapabilitiesRequest {
    /// The advertised capabilities of the client.
    pub capabilities: Capabilities,
}
make_fuzz_safe!(DeviceCapabilitiesRequest);

impl Request<'_> for DeviceCapabilitiesRequest {
    const TYPE: CommandType = CommandType::DeviceCapabilities;
}

impl<'wire> FromWire<'wire> for DeviceCapabilitiesRequest {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        a: &'wire A,
    ) -> Result<Self, wire::Error> {
        let capabilities = Capabilities::from_wire(r, a)?;
        Ok(Self { capabilities })
    }
}

impl ToWire for DeviceCapabilitiesRequest {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        self.capabilities.to_wire(&mut w)
    }
}

/// The [`DeviceCapabilities`] response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceCapabilitiesResponse {
    /// Capabilities negotiated based on the request.
    pub capabilities: Capabilities,
    /// Timeouts that this device expects the client to observe.
    pub timeouts: Timeouts,
}
make_fuzz_safe!(DeviceCapabilitiesResponse);

impl Response<'_> for DeviceCapabilitiesResponse {
    const TYPE: CommandType = CommandType::DeviceCapabilities;
}

impl<'wire> FromWire<'wire> for DeviceCapabilitiesResponse {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        a: &'wire A,
    ) -> Result<Self, wire::Error> {
        let capabilities = Capabilities::from_wire(r, a)?;
        let response_timeout =
            Duration::from_millis((10 * (r.read_le::<u8>()? as u32)) as _);
        let crypto_timeout =
            Duration::from_millis((100 * (r.read_le::<u8>()? as u32)) as _);
        Ok(Self {
            capabilities,
            timeouts: Timeouts {
                regular: response_timeout,
                crypto: crypto_timeout,
            },
        })
    }
}

impl ToWire for DeviceCapabilitiesResponse {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        self.capabilities.to_wire(&mut w)?;
        // Carefully compress the millisecond cound (which is a u128!) down
        // to a byte, saturating when possible, and avoiding expensive
        // division operations.
        let response_time =
            self.timeouts.regular.as_millis().min(u32::MAX as _) as u32;
        let crypto_time =
            self.timeouts.crypto.as_millis().min(u32::MAX as _) as u32;

        let response_byte = (response_time / 10).min(u8::MAX as _) as u8;
        let crypto_byte = (crypto_time / 100).min(u8::MAX as _) as u8;
        w.write_le(response_byte)?;
        w.write_le(crypto_byte)?;

        Ok(())
    }
}

wire_enum! {
    /// A "mode" for a Cerberus RoT: "active" or "platform".
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub enum RotMode: u8 {
        /// Represents an "AC-RoT" or "Active Root of Trust", an RoT chip which
        /// protects some kind of peripheral hardware.
        Active = 0b00,
        /// Represents a "PA-RoT", or "Platform Root of Trust", an RoT chip
        /// which protects the overall platform, and the RoTs on peripheral
        /// hardware. That is, the "root of roots of trust".
        Platform = 0b01,
    }
}

bitflags! {
    /// The role of this device on a shared bus.
    ///
    /// (Cerberus refers to these capabilities as master/slave.)
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct BusRole: u8 {
        /// This device can act as a "host".
        const HOST = 0b01;
        /// This device can act as a "target".
        const TARGET = 0b10;
    }
}

bitflags! {
    /// Represents a "security capability".
    ///
    /// I.e, this enum describes different security primitives the device might
    /// support.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct Security: u8 {
        /// This device has hash and key derivation capabilities.
        const HASH_AND_KDF = 0b001;
        /// This device has authentication capabilities, using some kind of
        /// PKI mechanism.
        const AUTHENTICATION = 0b010;
        /// This device can send and recieve confidential messages over a
        /// secured channel, using AES.
        const CONFIDENTIALITY = 0b100;
    }
}

bitflags! {
    /// Represents a supported elliptic curve cryptography key strength.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct EccKeyStrength: u8 {
        /// A key strength of 160 bits.
        const BITS_160 = 0b001;
        /// A key strength of 256 bits.
        const BITS_256 = 0b010;
    }
}

bitflags! {
    /// Represents a supported RSA key strength.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct RsaKeyStrength: u8 {
        /// A key strength of 2048 bits.
        const BITS_2048 = 0b001;
        /// A key strength of 3072 bits.
        const BITS_3072 = 0b010;
        /// A key strength of 4096 bits.
        const BITS_4096 = 0b100;
    }
}

bitflags! {
    /// Represents a supported AES key strength.
    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct AesKeyStrength: u8 {
        /// A key strength of 128 bits.
        const BITS_128 = 0b001;
        /// A key strength of 256 bits.
        const BITS_256 = 0b010;
    }
}

/// Network-related capabilities for a device.
///
/// A value of this type needs to be provided to `manticore` by an integration,
/// so that it can faithfully report it during capabilities negotiation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Networking {
    /// The maximum message size this device can buffer, in bytes.
    ///
    /// This number can be used after capabilities negotiation to limit the size
    /// of a complete message (before it is packetized). It is typically derived
    /// from the size of the message assembly buffers in a network stack.
    pub max_message_size: u16,
    /// The maximum packet size this device can accept, in bytes.
    ///
    /// This number can be used after capabilities negotiation to limit the
    /// size of a single packet (as opposed to a message, which might need to
    /// be packetized). It is typically derived from the size of underlying
    /// buffers in, say, a SPI or I2C hardware IP.
    ///
    /// (Note: the packetization strategy is not provided by `manticore`
    /// itself.)
    pub max_packet_size: u16,

    /// The type of RoT this device is.
    pub mode: RotMode,
    /// Valid "bus roles" of this device: is a host, a target, or both?
    pub roles: BusRole,
}

/// Cryptographic device capabilities.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Crypto {
    /// Whether this device supports ECDSA.
    pub has_ecdsa: bool,
    /// Whether this device supports ECC.
    pub has_ecc: bool,
    /// Whether this device supports RSA.
    pub has_rsa: bool,
    /// Whether this device supports AES.
    pub has_aes: bool,

    /// ECC key strengths supported by this device.
    pub ecc_strength: EccKeyStrength,
    /// RSA key strengths supported by this device.
    pub rsa_strength: RsaKeyStrength,
    /// AES key strengths supported by this device.
    pub aes_strength: AesKeyStrength,
}

/// A description of device capabilities.
///
/// This struct describes all of the device capabilities used in capability
/// negotiation in a Cerberus session.
///
/// Some fields in this struct may apear unused or redundant. This struct is
/// meant to be a strict reflection of the wire format specified by Cerberus.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Capabilities {
    /// Integration-provided information on the device's networking
    /// capabilities.
    pub networking: Networking,

    /// Security primitives supported by this device.
    pub security: Security,
    /// Whether this primitive "supports PFMs".
    ///
    /// The meaning of this field is unspecified by Cerberus.
    pub has_pfm_support: bool,
    /// Whether this primitive "supports policies".
    ///
    /// The meaning of this field is unspecified by Cerberus.
    pub has_policy_support: bool,
    /// Whether this primitive "has firmware protection enabled".
    ///
    /// The meaning of this field is unspecified by Cerberus.
    pub has_firmware_protection: bool,

    /// Cryptographic capabilities supported by this device.
    pub crypto: Crypto,
}

/// Constants relevant to parsing `Capabilities`.
mod consts {
    pub const MODE_SIZE: usize = 2;
    pub const BUS_SIZE: usize = 2;
    pub const SEC_SIZE: usize = 3;

    pub const RSA_SIZE: usize = 3;
    pub const ECC_SIZE: usize = 3;
    pub const AES_SIZE: usize = 3;
}

impl<'wire> FromWire<'wire> for Capabilities {
    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
        r: &mut R,
        _: &'wire A,
    ) -> Result<Capabilities, wire::Error> {
        use consts::*;
        let max_message_size = r.read_le::<u16>()?;
        let max_packet_size = r.read_le::<u16>()?;

        // The fifth byte contains the security capabilities, a reserved bit,
        // the bus role, and the RoT mode, in that order.
        let mut byte_five = BitBuf::from_bits(r.read_le::<u8>()?);
        let mode_bits = byte_five.read_bits(MODE_SIZE)?;
        let bus_bits = byte_five.read_bits(BUS_SIZE)?;
        let _ = byte_five.read_bits(1)?;
        let security_bits = byte_five.read_bits(SEC_SIZE)?;

        let mode = RotMode::from_wire_value(mode_bits)
            .ok_or(wire::Error::OutOfRange)?;
        let roles =
            BusRole::from_bits(bus_bits).ok_or(wire::Error::OutOfRange)?;
        let networking = Networking {
            max_message_size,
            max_packet_size,
            mode,
            roles,
        };

        let security = Security::from_bits(security_bits)
            .ok_or(wire::Error::OutOfRange)?;

        // The sixth byte consists of five reserved bits, and the PFM, policy,
        // and firmware protection bits.
        let mut byte_six = BitBuf::from_bits(r.read_le::<u8>()?);
        let has_pfm_support = byte_six.read_bit()?;
        let has_policy_support = byte_six.read_bit()?;
        let has_firmware_protection = byte_six.read_bit()?;
        let _ = byte_six.read_bits(5)?;

        // The seventh byte consists of the rsa strength, the ecc strength, and
        // the ecdsa and rsa bits.
        let mut byte_seven = BitBuf::from_bits(r.read_le::<u8>()?);
        let has_rsa = byte_seven.read_bit()?;
        let has_ecdsa = byte_seven.read_bit()?;
        let ecc_bits = byte_seven.read_bits(ECC_SIZE)?;
        let rsa_bits = byte_seven.read_bits(RSA_SIZE)?;

        let rsa_strength = RsaKeyStrength::from_bits(rsa_bits)
            .ok_or(wire::Error::OutOfRange)?;
        let ecc_strength = EccKeyStrength::from_bits(ecc_bits)
            .ok_or(wire::Error::OutOfRange)?;

        // The eighth byte consists of the aes strength, four reserved bits,
        // and the ecc bit.
        let mut byte_eight = BitBuf::from_bits(r.read_le::<u8>()?);
        let has_ecc = byte_eight.read_bit()?;
        let _ = byte_eight.read_bits(4)?;
        let aes_bits = byte_eight.read_bits(AES_SIZE)?;

        let aes_strength = AesKeyStrength::from_bits(aes_bits)
            .ok_or(wire::Error::OutOfRange)?;

        Ok(Capabilities {
            networking,

            security,
            has_pfm_support,
            has_policy_support,
            has_firmware_protection,

            crypto: Crypto {
                has_ecdsa,
                has_ecc,
                has_rsa,
                has_aes: false,

                ecc_strength,
                rsa_strength,
                aes_strength,
            },
        })
    }
}

impl ToWire for Capabilities {
    fn to_wire<W: Write>(&self, mut w: W) -> Result<(), wire::Error> {
        use consts::*;
        w.write_le(self.networking.max_message_size)?;
        w.write_le(self.networking.max_packet_size)?;

        // See `deserialize_capabilities` for the description of each byte.
        let mut fifth_byte = BitBuf::new();
        fifth_byte
            .write_bits(MODE_SIZE, self.networking.mode.to_wire_value())?;
        fifth_byte.write_bits(BUS_SIZE, self.networking.roles.bits())?;
        fifth_byte.write_zero_bits(1)?;
        fifth_byte.write_bits(SEC_SIZE, self.security.bits())?;
        w.write_le(fifth_byte.bits())?;

        let mut sixth_byte = BitBuf::new();
        sixth_byte.write_bit(self.has_pfm_support)?;
        sixth_byte.write_bit(self.has_policy_support)?;
        sixth_byte.write_bit(self.has_firmware_protection)?;
        sixth_byte.write_zero_bits(5)?;
        w.write_le(sixth_byte.bits())?;

        let mut seventh_byte = BitBuf::new();
        seventh_byte.write_bit(self.crypto.has_rsa)?;
        seventh_byte.write_bit(self.crypto.has_ecdsa)?;
        seventh_byte.write_bits(ECC_SIZE, self.crypto.ecc_strength.bits())?;
        seventh_byte.write_bits(RSA_SIZE, self.crypto.rsa_strength.bits())?;
        w.write_le(seventh_byte.bits())?;

        let mut eighth_byte = BitBuf::new();
        eighth_byte.write_bit(self.crypto.has_ecc)?;
        eighth_byte.write_zero_bits(4)?;
        eighth_byte.write_bits(AES_SIZE, self.crypto.aes_strength.bits())?;
        w.write_le(eighth_byte.bits())?;

        Ok(())
    }
}

/// Timeout "capabilities", that is, how long a client should expect a device
/// to take to respond to a request before it decides that the device is
/// unreachable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Timeouts {
    /// The timeout for a "regular" request, that is, one which does not
    /// perform expensive cryptography.
    ///
    /// This value may range between 0 and 2560 milliseconds: over the wire,
    /// it is encoded as a byte with units of 10 ms.
    pub regular: Duration,
    /// The timeout for a "cryptographic" request, one which may need to
    /// perform an expensive cryptographic operation, such as a signature
    /// verification.
    ///
    /// This value may range between 0 and 25600 milliseconds: over the wire,
    /// it is encoded as a byte with units of 100 ms (not 10 ms, as
    /// `response_timeout` would suggest).
    pub crypto: Duration,
}

#[cfg(test)]
mod test {
    use super::*;

    round_trip_test! {
        request_round_trip: {
            bytes: &[
                0x00, 0x01,  // Message size.
                0x80, 0x00,  // Packet size.
                0b01_11_0_011,  // PA-RoT, Host + Target, KDF + Auth
                0b1_0_0_00000,  // PFM support.
                0b1_0_000_001,  // RSA-2048 only.
                0b0_0000_011,  // AES-128 and -256
            ],
            value: DeviceCapabilitiesRequest {
                capabilities: Capabilities {
                    networking: Networking {
                        max_message_size: 0x100,
                        max_packet_size: 0x80,
                        mode: RotMode::Platform,
                        roles: BusRole::HOST | BusRole::TARGET,
                    },
                    security: Security::HASH_AND_KDF | Security::AUTHENTICATION,
                    has_pfm_support: true,
                    has_policy_support: false,
                    has_firmware_protection: false,
                    crypto: Crypto {
                        has_ecdsa: false,
                        has_ecc: false,
                        has_rsa: true,
                        has_aes: false,
                        ecc_strength: EccKeyStrength::empty(),
                        rsa_strength: RsaKeyStrength::BITS_2048,
                        aes_strength: AesKeyStrength::BITS_128 | AesKeyStrength::BITS_256,
                    },
                },
            },
        },
        response_round_trip: {
            bytes: &[
                0x00, 0x01,  // Message size.
                0x80, 0x00,  // Packet size.
                0b01_11_0_011,  // PA-RoT, Host + Target, KDF + Auth
                0b1_0_0_00000,  // PFM support.
                0b1_0_000_001,  // RSA-2048 only.
                0b0_0000_011,  // AES-128 and -256
                50,  // 500ms normal timeout.
                2,  // 200ms crypto timeout.
            ],
            value: DeviceCapabilitiesResponse {
                capabilities: Capabilities {
                    networking: Networking {
                        max_message_size: 0x100,
                        max_packet_size: 0x80,
                        mode: RotMode::Platform,
                        roles: BusRole::HOST | BusRole::TARGET,
                    },
                    security: Security::HASH_AND_KDF | Security::AUTHENTICATION,
                    has_pfm_support: true,
                    has_policy_support: false,
                    has_firmware_protection: false,
                    crypto: Crypto {
                        has_ecdsa: false,
                        has_ecc: false,
                        has_rsa: true,
                        has_aes: false,
                        ecc_strength: EccKeyStrength::empty(),
                        rsa_strength: RsaKeyStrength::BITS_2048,
                        aes_strength: AesKeyStrength::BITS_128 | AesKeyStrength::BITS_256,
                    },
                },
                timeouts: Timeouts {
                    regular: Duration::from_millis(500),
                    crypto: Duration::from_millis(200),
                }
            },
        },
    }
}
