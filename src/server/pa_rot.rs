// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A `manticore` "server" and "client" for a PA-RoT.
//!
//! This module provides structures for serving responses to a host making
//! requests to a PA-RoT.

use crate::cert;
use crate::crypto::sha256;
use crate::crypto::sig;
use crate::hardware;
use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::net;
use crate::protocol;
use crate::protocol::capabilities;
use crate::protocol::device_id;
use crate::server::Error;

use crate::server::handler::prelude::*;

/// Options struct for initializing a [`PaRot`].
pub struct Options<'a, Identity, Reset, Sha, Ciphers, TrustChain> {
    /// A handle to the "hardware identity" of the device.
    pub identity: &'a Identity,
    /// A handle for looking up reset-related information for the current
    /// device.
    pub reset: &'a Reset,

    /// A handle to a SHA-256 engine.
    pub sha: &'a Sha,
    /// A handle to a signature verification engine,
    pub ciphers: &'a mut Ciphers,
    /// The trust chain to use for the challenge.
    pub trust_chain: &'a TrustChain,

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
pub struct PaRot<'a, Identity, Reset, Sha, Ciphers, TrustChain> {
    opts: Options<'a, Identity, Reset, Sha, Ciphers, TrustChain>,
    ok_count: u16,
    err_count: u16,
}

impl<'a, Identity, Reset, Sha, Ciphers, TrustChain>
    PaRot<'a, Identity, Reset, Sha, Ciphers, TrustChain>
where
    Identity: hardware::Identity,
    Reset: hardware::Reset,
    Sha: sha256::Builder,
    Ciphers: sig::Ciphers,
    TrustChain: cert::TrustChain,
{
    /// Create a new `PaRot` with the given `Options`.
    pub fn new(
        opts: Options<'a, Identity, Reset, Sha, Ciphers, TrustChain>,
    ) -> Self {
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
    pub fn process_request<'req, A: Arena>(
        &mut self,
        host_port: &mut dyn net::HostPort<'req>,
        arena: &'req A,
    ) -> Result<(), Error> {
        let result = Handler::<&mut Self, A>::new()
            .handle::<protocol::FirmwareVersion, _>(|ctx| {
                use protocol::firmware_version::FirmwareVersionResponse;
                if ctx.req.index == 0 {
                    return Ok(FirmwareVersionResponse {
                        version: ctx.server.opts.identity.firmware_version(),
                    });
                }

                let version = ctx
                    .server
                    .opts
                    .identity
                    .vendor_firmware_version(ctx.req.index)
                    .ok_or(UNSPECIFIED)?;
                Ok(FirmwareVersionResponse { version })
            })
            .handle::<protocol::DeviceCapabilities, _>(|ctx| {
                use protocol::capabilities::*;
                let mut crypto = ctx.req.capabilities.crypto;

                ctx.server.opts.ciphers.negotiate(&mut crypto);
                crypto.has_aes = false;
                crypto.aes_strength = AesKeyStrength::empty();

                let capabilities = Capabilities {
                    networking: ctx.server.opts.networking,
                    security: Security::empty(),

                    has_pfm_support: false,
                    has_policy_support: false,
                    has_firmware_protection: false,

                    crypto,
                };

                Ok(protocol::capabilities::DeviceCapabilitiesResponse {
                    capabilities,
                    timeouts: ctx.server.opts.timeouts,
                })
            })
            .handle::<protocol::DeviceId, _>(|ctx| {
                Ok(protocol::device_id::DeviceIdResponse {
                    id: ctx.server.opts.device_id,
                })
            })
            .handle::<protocol::DeviceInfo, _>(|ctx| {
                Ok(protocol::device_info::DeviceInfoResponse {
                    info: ctx.server.opts.identity.unique_device_identity(),
                })
            })
            .handle::<protocol::GetDigests, _>(|ctx| {
                let digests_len = ctx
                    .server
                    .opts
                    .trust_chain
                    .chain_len(ctx.req.slot)
                    .ok_or(UNSPECIFIED)?
                    .get();
                let digests = ctx
                    .arena
                    .alloc_slice::<sha256::Digest>(digests_len)
                    .map_err(|_| UNSPECIFIED)?;
                for (i, digest) in digests.iter_mut().enumerate() {
                    let cert = ctx
                        .server
                        .opts
                        .trust_chain
                        .cert(ctx.req.slot, i)
                        .ok_or(UNSPECIFIED)?;
                    ctx.server
                        .opts
                        .sha
                        .hash_contiguous(cert.raw(), digest)
                        .map_err(|_| UNSPECIFIED)?;
                }
                Ok(protocol::get_digests::GetDigestsResponse { digests })
            })
            .handle::<protocol::GetCert, _>(|ctx| {
                let cert = ctx
                    .server
                    .opts
                    .trust_chain
                    .cert(ctx.req.slot, ctx.req.cert_number as usize)
                    .ok_or(UNSPECIFIED)?;

                let start = cert.raw().len().min(ctx.req.offset as usize);
                let end = cert.raw().len().min(ctx.req.len as usize);
                Ok(protocol::get_cert::GetCertResponse {
                    slot: ctx.req.slot,
                    cert_number: ctx.req.cert_number,
                    data: &cert.raw()[start..end],
                })
            })
            .handle::<protocol::ResetCounter, _>(|ctx| {
                use protocol::reset_counter::*;
                // NOTE: Currently, we only handle "local resets" for port 0,
                // the "self" port.
                if ctx.req.reset_type != ResetType::Local
                    || ctx.req.port_id != 0
                {
                    return Err(UNSPECIFIED);
                }

                Ok(ResetCounterResponse {
                    count: ctx.server.opts.reset.resets_since_power_on() as u16,
                })
            })
            .handle::<protocol::DeviceUptime, _>(|ctx| {
                use protocol::device_uptime::*;
                // NOTE: CUrrently, we only handle port 0, the "self" port.
                if ctx.req.port_id != 0 {
                    return Err(UNSPECIFIED);
                }
                Ok(DeviceUptimeResponse {
                    uptime: ctx.server.opts.reset.uptime(),
                })
            })
            .handle::<protocol::RequestCounter, _>(|ctx| {
                use protocol::request_counter::*;
                Ok(RequestCounterResponse {
                    ok_count: ctx.server.ok_count,
                    err_count: ctx.server.err_count,
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

/// Stopgap error code until we have richer errors for Manticore and Cerberus.
const UNSPECIFIED: protocol::Error = protocol::Error {
    code: protocol::ErrorCode::Unspecified,
    data: [0; 4],
};

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
        port_out: &'a mut Option<net::InMemHost<'a>>,
        arena: &'a mut A,
        server: &mut PaRot<
            fake::Identity,
            fake::Reset,
            ring::sha256::Builder,
            ring::sig::Ciphers,
            cert::SimpleChain<0>,
        >,
        request: C::Req,
    ) -> Result<Result<C::Resp, protocol::Error>, Error> {
        use crate::protocol::Response;

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
        *port_out = Some(host_port);
        let host_port = port_out.as_mut().unwrap();

        server.process_request(host_port, arena)?;

        let (header, mut resp) = host_port.response().unwrap();
        assert!(!header.is_request);

        if header.command == protocol::Error::TYPE {
            let resp_val = FromWire::from_wire(&mut resp, arena)
                .expect("failed to read response");
            assert_eq!(resp.len(), 0);
            return Ok(Err(resp_val));
        }

        let resp_val = FromWire::from_wire(&mut resp, arena)
            .expect("failed to read response");
        assert_eq!(resp.len(), 0);
        Ok(Ok(resp_val))
    }

    fn simulate_response<'a, C: protocol::Command<'a>, A: Arena>(
        scratch_space: &'a mut [u8],
        port_out: &mut Option<net::InMemDevice<'a>>,
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

        *port_out = Some(net::InMemDevice::new());
        let device_port = port_out.as_mut().unwrap();
        device_port.send(0x10, header, request_bytes).unwrap();
        device_port.response(
            Header {
                is_request: false,
                command: <C::Req as protocol::Request<'a>>::TYPE,
            },
            &[1, 0, 2, 0, 3, 0, 4, 0],
        );
        device_port.wait_for_response(100)?;

        let response = device_port.receive_response()?;
        assert_eq!(response.header().unwrap(), header);

        let payload = response.payload().unwrap();
        // Kludge to work around DevicePort not supporting ReadZero yet.
        let mut out =
            arena.alloc_slice::<u8>(payload.remaining_data()).unwrap();
        payload.read_bytes(out).unwrap();
        let resp_val = FromWire::from_wire(&mut out, arena)
            .expect("failed to read response");
        Ok(resp_val)
    }

    #[test]
    fn sanity() {
        let identity = fake::Identity::new(
            b"test version",
            &[(1, b"vendor fw 1"), (3, b"vendor fw 3")],
            b"random bits",
        );
        let reset = fake::Reset::new(0, Duration::from_millis(1));
        let mut ciphers = ring::sig::Ciphers::new();
        let sha = ring::sha256::Builder::new();
        let trust_chain = cert::SimpleChain::parse(
            &[],
            cert::CertFormat::RiotX509,
            &mut ciphers,
        )
        .unwrap();
        let mut server = PaRot::new(Options {
            identity: &identity,
            reset: &reset,
            sha: &sha,
            ciphers: &mut ciphers,
            trust_chain: &trust_chain,
            device_id: DEVICE_ID,
            networking: NETWORKING,
            timeouts: TIMEOUTS,
        });

        let mut scratch = [0; 1024];
        let mut arena = [0; 64];
        let mut arena = BumpArena::new(&mut arena);

        let mut port = None;
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 0 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect("got error message from server");
        assert_eq!(resp.version, identity.firmware_version());

        arena.reset();

        let mut port = None;
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 1 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect("got error message from server");
        assert_eq!(Some(resp.version), identity.vendor_firmware_version(1));

        arena.reset();

        let mut port = None;
        let req =
            protocol::firmware_version::FirmwareVersionRequest { index: 2 };
        let resp = simulate_request::<protocol::FirmwareVersion, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect_err("got non-error message from server");
        assert_eq!(resp.code, protocol::ErrorCode::Unspecified);

        arena.reset();

        let mut port = None;
        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_request::<protocol::DeviceId, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            &mut server,
            req,
        )
        .expect("got error from server")
        .expect("got error message from server");
        assert_eq!(resp.id, DEVICE_ID);

        arena.reset();

        let mut port = None;
        let req = protocol::device_id::DeviceIdRequest;
        let resp = simulate_response::<protocol::DeviceId, _>(
            &mut scratch,
            &mut port,
            &mut arena,
            req,
        )
        .expect("got error from client");
        assert_eq!(resp.id, DEVICE_ID);
    }
}
