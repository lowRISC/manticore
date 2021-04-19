// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A `manticore` "server" and "client" for a PA-RoT.
//!
//! This module provides structures for serving responses to a host making
//! requests to a PA-RoT.

use crate::crypto::rsa;
use crate::hardware;
use crate::mem::Arena;
use crate::net;
use crate::protocol;
use crate::protocol::capabilities;
use crate::protocol::device_id;
use crate::server::Error;

use crate::server::handler::prelude::*;

/// Options struct for initializing a [`PaRot`].
pub struct Options<'a, Identity, Reset, Rsa> {
    /// A handle to the "hardware identity" of the device.
    pub identity: &'a Identity,
    /// A handle for looking up reset-related information for the current
    /// device.
    pub reset: &'a Reset,

    /// A handle to an RSA engine builder.
    pub rsa: &'a Rsa,

    /// This device's silicon identifier.
    pub device_id: device_id::DeviceIdentifier,
    /// Integration-provided description of the device's networking
    /// capabilities.
    pub networking: capabilities::Networking,
    /// Integration-provided "acceptable timeout" lengths.
    pub timeouts: capabilities::Timeouts,
}

/// A PA-RoT, or "Platform Root of Trust", server.
///
/// This type implements the request -> response "business logic" of the
/// host <-> PA-RoT interaction. That is, it accepts input and output buffers,
/// and from those, parses incoming requests and processes them into responses.
pub struct PaRot<'a, Identity, Reset, Rsa> {
    opts: Options<'a, Identity, Reset, Rsa>,
    ok_count: u16,
    err_count: u16,
}

impl<'a, Identity, Reset, Rsa> PaRot<'a, Identity, Reset, Rsa>
where
    Identity: hardware::Identity,
    Reset: hardware::Reset,
    Rsa: rsa::Builder,
{
    /// Create a new `PaRot` with the given `Options`.
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
    #[cfg_attr(test, inline(never))]
    pub fn process_request<'req>(
        &mut self,
        host_port: &mut dyn net::HostPort,
        arena: &'req impl Arena,
    ) -> Result<(), Error> {
        let result = Handler::<&mut Self>::new()
            .handle::<protocol::FirmwareVersion, _>(|zelf, req| {
                if req.index != 0 {
                    return Err(protocol::Error {
                        code: protocol::ErrorCode::Unspecified,
                        data: [0; 4],
                    });
                }

                Ok(protocol::firmware_version::FirmwareVersionResponse {
                    version: zelf.opts.identity.firmware_version(),
                })
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

    /// Start and process a outgoing request.
    ///
    /// The request message will be read from `req`, while the response
    /// message will be written to `resp`.
    #[cfg_attr(test, inline(never))]
    pub fn process_response<'req>(
        &mut self,
        _device_port: &mut dyn net::DevicePort,
        _arena: &'req impl Arena,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::time::Duration;

    use crate::crypto::ring;
    use crate::hardware::fake;
    use crate::hardware::Identity as _;
    use crate::io::Cursor;
    use crate::mem::BumpArena;
    use crate::net::DevicePort;
    use crate::protocol::capabilities::*;
    use crate::protocol::wire::FromWire;
    use crate::protocol::wire::ToWire;
    use crate::protocol::Header;

    const NETWORKING: Networking = Networking {
        max_message_size: 1024,
        max_packet_size: 256,
        mode: RotMode::Platform,
        roles: BusRole::HOST,
    };

    const TIMEOUTS: Timeouts = Timeouts {
        regular: Duration::from_millis(30),
        crypto: Duration::from_millis(200),
    };

    const DEVICE_ID: device_id::DeviceIdentifier =
        device_id::DeviceIdentifier {
            vendor_id: 1,
            device_id: 2,
            subsys_vendor_id: 3,
            subsys_id: 4,
        };

    fn simulate_request<'a, C: protocol::Command<'a>, A: Arena>(
        scratch_space: &'a mut [u8],
        arena: &'a mut A,
        server: &mut PaRot<fake::Identity, fake::Reset, ring::rsa::Builder>,
        request: C::Req,
    ) -> Result<C::Resp, Error> {
        let len = scratch_space.len();
        let (req_scratch, port_scratch) = scratch_space.split_at_mut(len / 2);
        let mut cursor = Cursor::new(req_scratch);
        request
            .to_wire(&mut cursor)
            .expect("failed to write request");
        let request_bytes = cursor.take_consumed_bytes();

        let mut host_port = net::InMemHost::new(port_scratch);
        host_port.request(
            Header {
                is_request: true,
                command: <C::Req as protocol::Request<'a>>::TYPE,
            },
            request_bytes,
        );

        server.process_request(&mut host_port, arena)?;

        let (header, mut resp) = host_port.response().unwrap();
        assert!(!header.is_request);

        let resp_val = FromWire::from_wire(&mut resp, arena)
            .expect("failed to read response");
        assert_eq!(resp.len(), 0);
        Ok(resp_val)
    }

    fn simulate_response<'a, C: protocol::Command<'a>, A: Arena>(
        scratch_space: &'a mut [u8],
        arena: &'a mut A,
        request: C::Req,
    ) -> Result<C::Resp, Error> {
        let len = scratch_space.len();
        let (req_scratch, _port_scratch) = scratch_space.split_at_mut(len / 2);
        let mut cursor = Cursor::new(req_scratch);
        request
            .to_wire(&mut cursor)
            .expect("failed to write request");
        let request_bytes = cursor.take_consumed_bytes();

        let header = Header {
            is_request: true,
            command: <C::Req as protocol::Request<'a>>::TYPE,
        };

        // Create the DevicePort
        let mut device_port = net::InMemDevice::new();

        // Send a request to a device
        device_port.send(0x10, header, request_bytes).unwrap();

        // Fake the response
        device_port.response(
            Header {
                is_request: false,
                command: <C::Req as protocol::Request<'a>>::TYPE,
            },
            &[1, 0, 2, 0, 3, 0, 4, 0],
        );

        // Block until we receive a response
        device_port.wait_for_response(100)?;

        // Get the response
        let response = device_port.receive_response()?;

        assert_eq!(response.header().unwrap(), header);

        let payload = response.payload().unwrap();

        let resp_val = FromWire::from_wire(payload, arena)
            .expect("failed to read response");
        Ok(resp_val)
    }

    #[test]
    fn sanity() {
        let identity = fake::Identity::new(b"test version", b"random bits");
        let reset = fake::Reset::new(0, Duration::from_millis(1));
        let rsa = ring::rsa::Builder::new();
        let mut server = PaRot::new(Options {
            identity: &identity,
            reset: &reset,
            rsa: &rsa,
            device_id: DEVICE_ID,
            networking: NETWORKING,
            timeouts: TIMEOUTS,
        });

        let mut scratch = [0; 1024];
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);

        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 0 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server");
        assert_eq!(resp.version, identity.firmware_version());

        arena.reset();

        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_request::<protocol::DeviceId, _>(
            &mut scratch,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server");
        assert_eq!(resp.id, DEVICE_ID);

        arena.reset();

        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_response::<protocol::DeviceId, _>(
            &mut scratch,
            &mut arena,
            req,
        )
        .expect("got error from client");
        assert_eq!(resp.id, DEVICE_ID);
    }
}
