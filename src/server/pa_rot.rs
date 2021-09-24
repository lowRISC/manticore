// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A `manticore` "server" and "client" for a PA-RoT.
//!
//! This module provides structures for serving responses to a host making
//! requests to a PA-RoT.

use crate::cert;
use crate::crypto::csrng;
use crate::crypto::hash;
use crate::crypto::hash::EngineExt as _;
use crate::crypto::sig;
use crate::hardware;
use crate::mem::Arena;
use crate::mem::ArenaExt as _;
use crate::net;
use crate::protocol;
use crate::protocol::capabilities;
use crate::protocol::device_id;
use crate::protocol::get_digests::KeyExchangeAlgo;
use crate::server::Error;
use crate::session::Session;

use crate::server::handler::prelude::*;

/// Options struct for initializing a [`PaRot`].
pub struct Options<'a> {
    /// A handle to the "hardware identity" of the device.
    pub identity: &'a dyn hardware::Identity,
    /// A handle for looking up reset-related information for the current
    /// device.
    pub reset: &'a dyn hardware::Reset,

    /// A handle to a hashing engine.
    pub hasher: &'a mut dyn hash::Engine,
    /// A handle to a signature verification engine,
    pub ciphers: &'a mut dyn sig::Ciphers,
    /// A random number generator for creating nonces and ephemeral keys.
    pub csrng: &'a mut dyn csrng::Csrng,
    /// The trust chain to use for the challenge.
    pub trust_chain: &'a mut dyn cert::TrustChain,

    /// The session manager.
    pub session: &'a mut dyn Session,

    /// The value of PMR0.
    ///
    /// Eventually this should be replaced with a general "PMRs"
    /// trait.
    pub pmr0: &'a [u8],

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
pub struct PaRot<'a> {
    opts: Options<'a>,
    ok_count: u16,
    err_count: u16,

    /// State from the last `GetDigests`, which records whether the
    /// following `Challenge` will be used to initiate a key exchange.
    /// This prevents the `Challenge` from clobbering session state if
    /// key exchange won't happen.
    key_exchange: Option<KeyExchangeAlgo>,

    /// The most recent certificate slot used for an ECDH-seeding
    /// `Challenge`. This records which certificate's key needs to sign
    /// the ECDH keypair in the key exchange.
    ///
    /// Note that this is *only* changed when the most recent `GetDigests`
    /// indicated a forthcoming key exchange.
    current_cert_slot: Option<u8>,
}

impl<'a> PaRot<'a> {
    /// Create a new `PaRot` with the given `Options`.
    pub fn new(opts: Options<'a>) -> Self {
        Self {
            opts,
            ok_count: 0,
            err_count: 0,
            key_exchange: None,
            current_cert_slot: None,
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
                    .alloc_slice::<[u8; hash::Algo::Sha256.bytes()]>(
                        digests_len,
                    )
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
                        .hasher
                        .contiguous_hash(hash::Algo::Sha256, cert.raw(), digest)
                        .map_err(|_| UNSPECIFIED)?;
                }

                ctx.server.key_exchange = Some(ctx.req.key_exchange);
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
                let end = cert
                    .raw()
                    .len()
                    .min((ctx.req.len as usize).saturating_add(start));
                Ok(protocol::get_cert::GetCertResponse {
                    slot: ctx.req.slot,
                    cert_number: ctx.req.cert_number,
                    data: &cert.raw()[start..end],
                })
            })
            .handle_buffered::<protocol::Challenge, _>(|ctx| {
                use protocol::challenge::*;

                let signer = ctx
                    .server
                    .opts
                    .trust_chain
                    .signer(ctx.req.slot)
                    .ok_or(UNSPECIFIED)?;
                let nonce: &mut [u8; 32] =
                    ctx.arena.alloc().map_err(|_| UNSPECIFIED)?;
                ctx.server.opts.csrng.fill(nonce).map_err(|_| UNSPECIFIED)?;

                let tbs = ChallengeResponseTbs {
                    slot: ctx.req.slot,
                    slot_mask: 0, // Currently unspecified?
                    protocol_range: (0, 0),
                    nonce,
                    pmr0_components: 0,
                    pmr0: ctx.server.opts.pmr0,
                };

                let req_buf = ctx.req_buf;
                let signature = ctx
                    .arena
                    .alloc_slice::<u8>(signer.sig_bytes())
                    .map_err(|_| UNSPECIFIED)?;
                let sig_len = tbs
                    .as_iovec_with(|[a, b, c, d]| {
                        signer.sign(&[req_buf, a, b, c, d], signature)
                    })
                    .map_err(|_| UNSPECIFIED)?;
                let signature = &signature[..sig_len];

                if let Some(KeyExchangeAlgo::Ecdh) = ctx.server.key_exchange {
                    ctx.server
                        .opts
                        .session
                        .create_session(ctx.req.nonce, tbs.nonce)
                        .map_err(|_| UNSPECIFIED)?;
                    ctx.server.current_cert_slot = Some(tbs.slot);
                }

                Ok(ChallengeResponse { tbs, signature })
            })
            .handle::<protocol::KeyExchange, _>(|ctx| {
                use protocol::key_exchange::*;
                match &ctx.req {
                    KeyExchangeRequest::SessionKey {
                        hmac_algorithm: _,
                        pk_req,
                    } => {
                        let signer = ctx
                            .server
                            .opts
                            .trust_chain
                            .signer(
                                ctx.server
                                    .current_cert_slot
                                    .ok_or(UNSPECIFIED)?,
                            )
                            .ok_or(UNSPECIFIED)?;

                        let pk_resp = ctx
                            .arena
                            .alloc_slice(
                                ctx.server.opts.session.ephemeral_bytes(),
                            )
                            .map_err(|_| UNSPECIFIED)?;
                        let key_len = ctx
                            .server
                            .opts
                            .session
                            .begin_ecdh(pk_resp)
                            .map_err(|_| UNSPECIFIED)?;
                        let pk_resp = &pk_resp[..key_len];
                        ctx.server
                            .opts
                            .session
                            .finish_ecdh(pk_req)
                            .map_err(|_| UNSPECIFIED)?;

                        let signature = ctx
                            .arena
                            .alloc_slice(signer.sig_bytes())
                            .map_err(|_| UNSPECIFIED)?;
                        signer
                            .sign(&[pk_req, pk_resp], signature)
                            .map_err(|_| UNSPECIFIED)?;

                        Ok(KeyExchangeResponse::SessionKey {
                            pk_resp,
                            signature,
                            alias_cert_hmac: &[
                                // Pending require of crypto::sha256.
                            ],
                        })
                    }
                    _ => Err(UNSPECIFIED),
                }
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
}

/// Stopgap error code until we have richer errors for Manticore and Cerberus.
const UNSPECIFIED: protocol::Error = protocol::Error {
    code: protocol::ErrorCode::Unspecified,
    data: [0; 4],
};
