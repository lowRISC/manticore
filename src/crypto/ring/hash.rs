// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::hash`] based on `ring`.

use core::mem;

use ring::digest;
use ring::hmac;

use crate::crypto::hash;
use crate::Result;

#[cfg(doc)]
use crate::crypto;

/// A `ring`-based [`hash::Engine`].
pub struct Engine {
    inner: Inner,
}

enum Inner {
    Idle,
    Hash(digest::Context),
    Hmac(hmac::Context, hmac::Algorithm),
}

impl Engine {
    /// Creates a new `Engine`.
    pub fn new() -> Self {
        Self { inner: Inner::Idle }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl hash::Engine for Engine {
    fn supports(&mut self, _: hash::Algo) -> bool {
        true
    }

    fn start_raw(
        &mut self,
        algo: hash::Algo,
        key: Option<&[u8]>,
    ) -> Result<(), hash::Error> {
        match key {
            Some(k) => {
                let key = hmac::Key::new(
                    match algo {
                        hash::Algo::Sha256 => hmac::HMAC_SHA256,
                        hash::Algo::Sha384 => hmac::HMAC_SHA384,
                        hash::Algo::Sha512 => hmac::HMAC_SHA512,
                    },
                    k,
                );
                self.inner =
                    Inner::Hmac(hmac::Context::with_key(&key), key.algorithm());
            }
            None => {
                self.inner = Inner::Hash(digest::Context::new(match algo {
                    hash::Algo::Sha256 => &digest::SHA256,
                    hash::Algo::Sha384 => &digest::SHA384,
                    hash::Algo::Sha512 => &digest::SHA512,
                }))
            }
        }
        Ok(())
    }

    fn write_raw(&mut self, data: &[u8]) -> Result<(), hash::Error> {
        match &mut self.inner {
            Inner::Idle => return Err(fail!(hash::Error::Idle)),
            Inner::Hash(c) => c.update(data),
            Inner::Hmac(c, _) => c.update(data),
        }
        Ok(())
    }

    fn finish_raw(&mut self, out: &mut [u8]) -> Result<(), hash::Error> {
        match mem::replace(&mut self.inner, Inner::Idle) {
            Inner::Idle => return Err(fail!(hash::Error::Idle)),
            Inner::Hash(c) => {
                check!(
                    out.len() == c.algorithm().output_len,
                    hash::Error::WrongSize
                );
                let digest = c.finish();
                out.copy_from_slice(digest.as_ref());
            }
            Inner::Hmac(c, a) => {
                check!(
                    out.len() == a.digest_algorithm().output_len,
                    hash::Error::WrongSize
                );
                let digest = c.sign();
                out.copy_from_slice(digest.as_ref());
            }
        }
        Ok(())
    }

    fn compare_raw(&mut self, expected: &[u8]) -> Result<(), hash::Error> {
        match mem::replace(&mut self.inner, Inner::Idle) {
            Inner::Idle => return Err(fail!(hash::Error::Idle)),
            Inner::Hash(c) => {
                check!(
                    expected.len() == c.algorithm().output_len,
                    hash::Error::WrongSize
                );
                let digest = c.finish();
                check!(digest.as_ref() == expected, hash::Error::Unspecified);
            }
            Inner::Hmac(c, a) => {
                check!(
                    expected.len() == a.digest_algorithm().output_len,
                    hash::Error::WrongSize
                );
                let digest = c.sign();
                ring::constant_time::verify_slices_are_equal(
                    digest.as_ref(),
                    expected,
                )
                .map_err(|_| fail!(hash::Error::Unspecified))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Algo::Sha256;
    use crate::crypto::hash::EngineExt as _;
    use testutil::data::misc_crypto;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hash256() {
        let mut e = Engine::new();
        let mut digest = [0; Sha256.bytes()];

        let mut ctx = e.new_hash(Sha256).unwrap();
        ctx.write(misc_crypto::PLAIN_TEXT).unwrap();
        ctx.finish(&mut digest).unwrap();
        assert_eq!(&digest, misc_crypto::PLAIN_SHA256);

        let mut ctx = e.new_hash(Sha256).unwrap();
        ctx.write(&misc_crypto::PLAIN_TEXT[..16]).unwrap();
        ctx.write(&misc_crypto::PLAIN_TEXT[16..]).unwrap();
        ctx.finish(&mut digest).unwrap();
        assert_eq!(&digest, misc_crypto::PLAIN_SHA256);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hmac256() {
        let mut e = Engine::new();
        let key = misc_crypto::PLAIN_TEXT;

        let mut ctx = e.new_hmac(Sha256, key).unwrap();
        ctx.write(misc_crypto::PLAIN_TEXT).unwrap();
        ctx.expect(misc_crypto::PLAIN_HMAC256).unwrap();

        let mut ctx = e.new_hmac(Sha256, key).unwrap();
        ctx.write(&misc_crypto::PLAIN_TEXT[..16]).unwrap();
        ctx.write(&misc_crypto::PLAIN_TEXT[16..]).unwrap();
        ctx.expect(misc_crypto::PLAIN_HMAC256).unwrap();
    }
}
