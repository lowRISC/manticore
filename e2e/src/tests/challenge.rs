// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the identity challenge.

use manticore::cert;
use manticore::cert::CertFormat;
use manticore::cert::TrustChain as _;
use manticore::crypto::ring;
use manticore::crypto::sha256;
use manticore::crypto::sha256::Builder as _;
use manticore::crypto::sig;
use manticore::crypto::sig::Ciphers as _;
use manticore::io::Cursor;
use manticore::mem::Arena as _;
use manticore::mem::BumpArena;
use manticore::protocol::wire::ToWire;
use testutil::data::keys;
use testutil::data::x509;

use crate::pa_rot;

#[test]
fn challenge() {
    use manticore::protocol::challenge::*;
    use manticore::protocol::get_cert::*;
    use manticore::protocol::get_digests::*;

    let sha = ring::sha256::Builder::new();
    let virt = pa_rot::Virtual::spawn(&pa_rot::Options {
        cert_chain: vec![
            x509::CHAIN1.to_vec(),
            x509::CHAIN2.to_vec(),
            x509::CHAIN3.to_vec(),
        ],
        cert_format: CertFormat::RiotX509,
        alias_keypair: Some(pa_rot::KeyPairFormat::RsaPkcs8(
            keys::KEY3_RSA_KEYPAIR.to_vec(),
        )),
        ..Default::default()
    });

    let mut arena = BumpArena::new(vec![0; 1024]);
    let resp = virt
        .send_local::<GetDigests, _>(
            GetDigestsRequest {
                slot: 0,
                key_exchange: KeyExchangeAlgo::None,
            },
            &arena,
        )
        .unwrap()
        .unwrap();

    // Ensure that the root certificate is one that we implicitly trust.
    // We won't request this certificate; only the two after it.
    let mut root_hash = sha256::Digest::default();
    sha.hash_contiguous(x509::CHAIN1, &mut root_hash).unwrap();
    assert_eq!(resp.digests[0], root_hash);
    let digests = resp.digests.to_vec();
    arena.reset();

    let mut certs = vec![x509::CHAIN1.to_vec()];
    for (i, digest) in digests.iter().enumerate().skip(1) {
        let mut cert = Vec::new();
        loop {
            let resp = virt
                .send_local::<GetCert, _>(
                    GetCertRequest {
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
        let mut cert_hash = sha256::Digest::default();
        sha.hash_contiguous(&cert, &mut cert_hash).unwrap();
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
    let req = ChallengeRequest {
        slot: 0,
        nonce: &[99; 32],
    };
    let resp = virt
        .send_local::<Challenge, _>(req, &arena)
        .unwrap()
        .unwrap();

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

    assert!(verifier
        .verify(&[cursor.consumed_bytes()], &resp.signature)
        .is_ok());
}
