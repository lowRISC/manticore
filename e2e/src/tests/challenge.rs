// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the identity challenge.

use manticore::cert;
use manticore::cert::CertFormat;
use manticore::cert::TrustChain as _;
use manticore::crypto::hash;
use manticore::crypto::hash::EngineExt as _;
use manticore::crypto::ring;
use manticore::crypto::sig;
use manticore::crypto::sig::Ciphers as _;
use manticore::io::Cursor;
use manticore::mem::Arena as _;
use manticore::mem::BumpArena;
use manticore::protocol::cerberus::*;
use manticore::protocol::wire::ToWire;
use manticore::protocol::Req;
use manticore::protocol::Resp;
use manticore::session;
use manticore::session::Session as _;
use testutil::data::keys;
use testutil::data::x509;

use crate::support::rot;

#[test]
fn challenge() {
    let mut h = ring::hash::Engine::new();
    let virt = rot::Virtual::spawn(&rot::Options {
        cert_chain: vec![
            x509::CHAIN1.to_vec(),
            x509::CHAIN2.to_vec(),
            x509::CHAIN3.to_vec(),
        ],
        cert_format: CertFormat::RiotX509,
        alias_keypair: Some(rot::KeyPairFormat::RsaPkcs8(
            keys::KEY3_RSA_KEYPAIR.to_vec(),
        )),
        ..Default::default()
    });

    let mut arena = BumpArena::new(vec![0; 1024]);
    let resp = virt
        .send_cerberus::<GetDigests>(
            Req::<GetDigests> {
                slot: 0,
                key_exchange: get_digests::KeyExchangeAlgo::Ecdh,
            },
            &arena,
        )
        .unwrap()
        .unwrap();
    log::info!("got digests: {:#?}", resp);

    // Ensure that the root certificate is one that we implicitly trust.
    // We won't request this certificate; only the two after it.
    let mut root_hash = [0; 32];
    h.contiguous_hash(hash::Algo::Sha256, x509::CHAIN1, &mut root_hash)
        .unwrap();
    assert_eq!(resp.digests[0], root_hash);
    let digests = resp.digests.to_vec();
    arena.reset();

    let mut certs = vec![x509::CHAIN1.to_vec()];
    for (i, digest) in digests.iter().enumerate().skip(1) {
        let mut cert = Vec::new();
        loop {
            let resp = virt
                .send_cerberus::<GetCert>(
                    Req::<GetCert> {
                        slot: 0,
                        cert_number: i as u8,
                        offset: cert.len() as u16,
                        len: 256,
                    },
                    &arena,
                )
                .unwrap()
                .unwrap();
            assert_eq!(resp.slot, 0);
            assert_eq!(resp.cert_number, i as u8);
            cert.extend_from_slice(resp.data);

            let len = resp.data.len();
            arena.reset();
            if len < 256 {
                break;
            }
        }
        let mut cert_hash = [0; 32];
        h.contiguous_hash(hash::Algo::Sha256, &cert, &mut cert_hash)
            .unwrap();
        assert!(&cert_hash == digest, "got wrong cert #{} from RoT!", i);
        certs.push(cert);
    }

    // Check that we have a valid cert chain.
    let certs = certs.iter().map(Vec::as_ref).collect::<Vec<_>>();
    let mut ciphers = ring::sig::Ciphers::new();
    let certs = cert::SimpleChain::<8>::parse(
        &certs,
        CertFormat::RiotX509,
        &mut ciphers,
        None,
    )
    .unwrap();

    // Issue a challenge.
    let req = Req::<Challenge> {
        slot: 0,
        nonce: &[99; 32],
    };
    let resp = virt
        .send_cerberus::<Challenge>(req, &arena)
        .unwrap()
        .unwrap();
    log::info!("got nonce: {:?}", resp.tbs.nonce);

    // Compute the expected signee: our challenge, plus the response's
    // TBS portion.
    let mut buf = vec![0; 1024];
    let mut cursor = Cursor::new(&mut buf);
    ToWire::to_wire(&req, &mut cursor).unwrap();
    ToWire::to_wire(&resp.tbs, &mut cursor).unwrap();

    let alias_cert = certs.cert(0, digests.len() - 1).unwrap();
    let verifier = ciphers
        .verifier(sig::Algo::RsaPkcs1Sha256, alias_cert.subject_key())
        .unwrap();

    verifier
        .verify(&[cursor.consumed_bytes()], &resp.signature)
        .unwrap();

    let mut session = session::ring::Session::new();
    session.create_session(&[99; 32], resp.tbs.nonce).unwrap();

    let mut pk_req = vec![0; session.ephemeral_bytes()];
    let pk_len = session.begin_ecdh(&mut pk_req).unwrap();
    let pk_req = &pk_req[..pk_len];

    let req = Req::<KeyExchange>::SessionKey {
        hmac_algorithm: hash::Algo::Sha256,
        pk_req,
    };
    let resp = virt
        .send_cerberus::<KeyExchange>(req, &arena)
        .unwrap()
        .unwrap();
    let (pk_resp, pk_sig, alias_hmac) = match resp {
        Resp::<KeyExchange>::SessionKey {
            pk_resp,
            signature,
            alias_cert_hmac,
        } => (pk_resp, signature, alias_cert_hmac),
        _ => panic!(),
    };
    verifier.verify(&[pk_req, pk_resp], pk_sig).unwrap();

    session.finish_ecdh(hash::Algo::Sha256, pk_resp).unwrap();
    let (_, hmac_key) = session.hmac_key().unwrap();
    let mut hasher = h.new_hmac(hash::Algo::Sha256, hmac_key).unwrap();
    hasher.write(alias_cert.raw()).unwrap();
    hasher.expect(alias_hmac).unwrap();
}
