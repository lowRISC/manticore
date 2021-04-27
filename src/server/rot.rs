// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A `manticore` "server" AC and PR RoTs.
//!
//! This module provides structures for serving responses to a host making
//! requests to a PA-RoT and AC-RoT.

use crate::crypto::rsa;
use crate::hardware;
use crate::mem::Arena;
use crate::net;
use crate::protocol;
use crate::server::options::Options;
use crate::server::Error;

use crate::server::handler::prelude::*;

/// A RoT, or "Root of Trust", server.
///
/// This type implements the request -> response "business logic" of the
/// host <-> PA-RoT interaction or the PA-RoT <-> AC-RoT. That is, it accepts
/// input and output buffers, and from those, parses incoming requests and
/// processes them into responses.
///
/// This is a generic RoT type that can be used as either a AC-RoT or a PA-RoT.
pub(crate) struct Rot<'a, Identity, Reset, Rsa> {
    opts: Options<'a, Identity, Reset, Rsa>,
    ok_count: u16,
    err_count: u16,
}

impl<'a, Identity, Reset, Rsa> Rot<'a, Identity, Reset, Rsa>
where
    Identity: hardware::Identity,
    Reset: hardware::Reset,
    Rsa: rsa::Builder,
{
    /// Create a new `Rot` with the given `Options`.
    pub fn new(opts: Options<'a, Identity, Reset, Rsa>) -> Self {
        Self {
            opts,
            ok_count: 0,
            err_count: 0,
        }
    }

    /// Process a single incoming request.
    ///
    /// The request message will be read from `req`, while the response
    /// message will be written to `resp`.
    pub fn process_request<'req>(
        &mut self,
        host_port: &mut dyn net::HostPort,
        arena: &'req impl Arena,
    ) -> Result<(), Error> {
        let result = Handler::<&mut Self>::new()
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                use protocol::firmware_version::FirmwareVersionResponse;
                if req.index == 0 {
                    return Ok(FirmwareVersionResponse {
                        version: zelf.opts.identity.firmware_version(),
                    });
                }

                match zelf.opts.identity.vendor_firmware_version(req.index) {
                    Some(version) => Ok(FirmwareVersionResponse { version }),
                    None => Err(protocol::Error {
                        code: protocol::ErrorCode::Unspecified,
                        data: [0; 4],
                    }),
                }
            })
            .handle::<protocol::DeviceCapabilities, _>(|zelf, req| {
                use protocol::capabilities::*;
                // For now, we drop the client's capabilities on the ground.
                // Eventually, these should be used for negotiation of crypto
                // use.
                let _ = req.capabilities;

                let rsa_strength = RsaKeyStrength::from_builder(zelf.opts.rsa);

                let capabilities = Capabilities {
                    networking: zelf.opts.networking,
                    security: Security::empty(),

                    has_pfm_support: false,
                    has_policy_support: false,
                    has_firmware_protection: false,

                    has_ecdsa: false,
                    has_ecc: false,
                    has_rsa: !rsa_strength.is_empty(),
                    has_aes: false,

                    ecc_strength: EccKeyStrength::empty(),
                    rsa_strength,
                    aes_strength: AesKeyStrength::empty(),
                };

                Ok(protocol::capabilities::DeviceCapabilitiesResponse {
                    capabilities,
                    timeouts: zelf.opts.timeouts,
                })
            })
            .handle::<protocol::DeviceId, _>(|zelf, _| {
                Ok(protocol::device_id::DeviceIdResponse {
                    id: zelf.opts.device_id,
                })
            })
            .handle::<protocol::DeviceInfo, _>(|zelf, _| {
                Ok(protocol::device_info::DeviceInfoResponse {
                    info: zelf.opts.identity.unique_device_identity(),
                })
            })
            .handle::<protocol::ResetCounter, _>(|zelf, req| {
                use protocol::reset_counter::*;
                // NOTE: Currently, we only handle "local resets" for port 0,
                // the "self" port.
                if req.reset_type != ResetType::Local || req.port_id != 0 {
                    return Err(protocol::Error {
                        code: protocol::ErrorCode::Unspecified,
                        data: [0; 4],
                    });
                }

                Ok(ResetCounterResponse {
                    count: zelf.opts.reset.resets_since_power_on() as u16,
                })
            })
            .handle::<protocol::DeviceUptime, _>(|zelf, req| {
                use protocol::device_uptime::*;
                // NOTE: CUrrently, we only handle port 0, the "self" port.
                if req.port_id != 0 {
                    return Err(protocol::Error {
                        code: protocol::ErrorCode::Unspecified,
                        data: [0; 4],
                    });
                }
                Ok(DeviceUptimeResponse {
                    uptime: zelf.opts.reset.uptime(),
                })
            })
            .handle::<protocol::RequestCounter, _>(|zelf, _| {
                use protocol::request_counter::*;
                Ok(RequestCounterResponse {
                    ok_count: zelf.ok_count,
                    err_count: zelf.err_count,
                })
            })
            .run(self, host_port, arena);

        match result {
            Ok(_) => self.ok_count += 1,
            Err(_) => self.err_count += 1,
        }
        result
    }
}
