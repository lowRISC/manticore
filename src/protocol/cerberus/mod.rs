// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus protocol messages.

pub mod device_id;
pub use device_id::DeviceId;

pub mod device_info;
pub use device_info::DeviceInfo;

pub mod device_uptime;
pub use device_uptime::DeviceUptime;

pub mod capabilities;
pub use capabilities::DeviceCapabilities;

pub mod firmware_version;
pub use firmware_version::FirmwareVersion;

pub mod get_digests;
pub use get_digests::GetDigests;

pub mod get_cert;
pub use get_cert::GetCert;

pub mod get_host_state;
pub use get_host_state::GetHostState;

pub mod get_pfm_id;
pub use get_pfm_id::GetPfmId;

pub mod challenge;
pub use challenge::Challenge;

pub mod key_exchange;
pub use key_exchange::KeyExchange;

pub mod reset_counter;
pub use reset_counter::ResetCounter;

pub mod request_counter;
pub use request_counter::RequestCounter;

mod error;
pub use error::*;

wire_enum! {
    /// A Cerberus command type.
    ///
    /// This enum represents all command types implemented by `manticore`,
    /// including any `manticore`-specific messages not defined by Cerberus.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum CommandType: u8 {
        /// An error message (or a trivial command ACK).
        ///
        /// See [`Ack`] and [`RawError`].
        Error = 0x7f,
        /// A request for the RoT's firmware version.
        ///
        /// See [`FirmwareVersion`].
        FirmwareVersion = 0x01,
        /// A request to negotiate device capabilities.
        ///
        /// See [`DeviceCapabilities`].
        DeviceCapabilities = 0x02,
        /// A request for this device's identity.
        ///
        /// See [`DeviceId`].
        DeviceId = 0x03,
        /// A request for information about this device.
        ///
        /// See [`DeviceInfo`].
        DeviceInfo = 0x04,
        /// A request for hashes of a certificate chain.
        ///
        /// See [`GetDigests`].
        GetDigests = 0x81,
        /// A request for a chunk of a certificate.
        ///
        /// See [`GetCert`].
        GetCert = 0x82,
        /// A Cerberus challenge.
        ///
        /// See [`Challenge`].
        Challenge = 0x83,
        /// The key-exchange handshake.
        ///
        /// See [`KeyExchange`].
        KeyExchange = 0x84,
        /// A request for the rest state of the host processor.
        ///
        /// See [`GetHostState`].
        GetHostState = 0x40,
        /// A request for the Platform Firmware Manifest ID.
        ///
        /// See [`GetPfmId`]
        GetPfmId = 0x59,
        /// A request for the number of times the device has been reset since
        /// POR.
        ///
        /// See [`ResetCounter`].
        ResetCounter = 0x87,
        /// A request for the uptime of the device since last reset.
        ///
        /// Note that this command is a Manticore extension.
        ///
        /// See [`DeviceUptime`].
        DeviceUptime = 0xa0,
        /// A request for an approximate number of requests the device has
        /// handled since last reset.
        ///
        /// Note that this command is a Manticore extension.
        ///
        /// See [`RequestCounter`].
        RequestCounter = 0xa1,
    }
}

impl CommandType {
    /// Returns `true` when `self` represents a `manticore` extension to the
    /// protocol.
    pub fn is_manticore_extension(self) -> bool {
        matches!(self, Self::DeviceUptime)
    }
}

impl From<u8> for CommandType {
    fn from(num: u8) -> CommandType {
        match num {
            0x01 => CommandType::FirmwareVersion,
            0x02 => CommandType::DeviceCapabilities,
            0x03 => CommandType::DeviceId,
            0x04 => CommandType::DeviceInfo,
            0x81 => CommandType::GetDigests,
            0x82 => CommandType::GetCert,
            0x83 => CommandType::Challenge,
            0x40 => CommandType::GetHostState,
            0x59 => CommandType::GetPfmId,
            0x87 => CommandType::ResetCounter,
            0xa0 => CommandType::DeviceUptime,
            0xa1 => CommandType::RequestCounter,
            _ => CommandType::Error,
        }
    }
}
