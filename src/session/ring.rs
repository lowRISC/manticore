// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! An implementation of [`session::Session`] based on [`ring`].
//!
//! Requires the `std` feature flag to be enabled.

use core::mem;

use ring::agreement as ecdh;
use ring::hmac;

use crate::crypto::hash;
use crate::session;

/// A [`ring`]-based [`session::Session`].
pub struct Session {
    conn: Option<Connection>,
    rand: ring::rand::SystemRandom,
}

struct Connection {
    req_nonce: Box<[u8]>,
    resp_nonce: Box<[u8]>,
    keys: Keys,
}

enum Keys {
    None,
    Ecdh(ecdh::EphemeralPrivateKey),
    Session {
        aes_key: session::Key,
        hmac_key: session::Key,
        algo: hash::Algo,
    },
}

impl Session {
    /// Creates a new inactive `Session`.
    pub fn new() -> Self {
        Self {
            conn: None,
            rand: ring::rand::SystemRandom::new(),
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl session::Session for Session {
    fn create_session(
        &mut self,
        req_nonce: &[u8],
        resp_nonce: &[u8],
    ) -> Result<(), session::Error> {
        self.conn = Some(Connection {
            req_nonce: req_nonce.into(),
            resp_nonce: resp_nonce.into(),
            keys: Keys::None,
        });
        Ok(())
    }

    fn destroy_session(&mut self) -> Result<(), session::Error> {
        self.conn = None;
        Ok(())
    }

    fn ephemeral_bytes(&self) -> usize {
        // Two 32-byte point coordinates, plus the 0x04 header.
        64 + 1
    }

    fn begin_ecdh(
        &mut self,
        our_key: &mut [u8],
    ) -> Result<usize, session::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or(session::Error::BadStateTransition)?;
        let key =
            ecdh::EphemeralPrivateKey::generate(&ecdh::ECDH_P256, &self.rand)
                .map_err(|_| session::Error::Unspecified)?;

        let public = key
            .compute_public_key()
            .map_err(|_| session::Error::Unspecified)?;
        let out = our_key
            .get_mut(..public.as_ref().len())
            .ok_or(session::Error::Unspecified)?;
        out.copy_from_slice(public.as_ref());

        conn.keys = Keys::Ecdh(key);
        Ok(out.len())
    }

    fn finish_ecdh(
        &mut self,
        hmac_algorithm: hash::Algo,
        their_key: &[u8],
    ) -> Result<(), session::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or(session::Error::BadStateTransition)?;

        let our_key = match mem::replace(&mut conn.keys, Keys::None) {
            Keys::Ecdh(our_key) => our_key,
            _ => return Err(session::Error::BadStateTransition),
        };
        let their_key =
            ecdh::UnparsedPublicKey::new(&ecdh::ECDH_P256, their_key);

        conn.keys = ecdh::agree_ephemeral(
            our_key,
            &their_key,
            session::Error::Unspecified,
            |material| {
                let aes_key = sp800_108_hmac256(
                    material,
                    &conn.req_nonce,
                    &conn.resp_nonce,
                );
                let hmac_key = sp800_108_hmac256(
                    material,
                    &conn.resp_nonce,
                    &conn.req_nonce,
                );
                Ok(Keys::Session {
                    aes_key,
                    hmac_key,
                    algo: hmac_algorithm,
                })
            },
        )?;
        Ok(())
    }

    fn aes_key(&self) -> Option<&session::Key> {
        match &self.conn {
            Some(Connection {
                keys: Keys::Session { aes_key, .. },
                ..
            }) => Some(aes_key),
            _ => None,
        }
    }

    fn hmac_key(&self) -> Option<(hash::Algo, &session::Key)> {
        match &self.conn {
            Some(Connection {
                keys: Keys::Session { hmac_key, algo, .. },
                ..
            }) => Some((*algo, hmac_key)),
            _ => None,
        }
    }
}

/// Computes an SP 800-108 KDF with the Cerberus parametrization.
fn sp800_108_hmac256(key: &[u8], label: &[u8], context: &[u8]) -> session::Key {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(&1u32.to_be_bytes());
    ctx.update(label);
    ctx.update(&[0]);
    ctx.update(context);
    ctx.update(&256u16.to_be_bytes());
    let tag = ctx.sign();

    let mut key = session::Key::default();
    key.copy_from_slice(tag.as_ref());
    key
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::session::Session as _;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn agreement() {
        let mut host = Session::new();
        let mut device = Session::new();

        let req_nonce = [0x5eu8; 32];
        let resp_nonce = [0x7au8; 32];

        host.create_session(&req_nonce, &resp_nonce).unwrap();
        device.create_session(&req_nonce, &resp_nonce).unwrap();

        let mut hkey = vec![0; host.ephemeral_bytes()];
        let key_len = host.begin_ecdh(&mut hkey).unwrap();
        let hkey = &hkey[..key_len];

        let mut dkey = vec![0; host.ephemeral_bytes()];
        let key_len = device.begin_ecdh(&mut dkey).unwrap();
        let dkey = &dkey[..key_len];

        device.finish_ecdh(hash::Algo::Sha256, hkey).unwrap();
        host.finish_ecdh(hash::Algo::Sha256, dkey).unwrap();

        assert_eq!(host.aes_key(), device.aes_key());
        assert_eq!(host.hmac_key(), device.hmac_key());
    }
}
