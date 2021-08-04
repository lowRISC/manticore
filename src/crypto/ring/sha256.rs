// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::sha256`] based on `ring`.

use ring::digest;

use crate::crypto::sha256;

#[cfg(doc)]
use crate::crypto;

/// A `ring`-based [`sha256::Builder`].
pub struct Builder {
    _priv: (),
}

impl Builder {
    /// Creates a new `Builder`.
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl sha256::Builder for Builder {
    type Hasher = Hasher;

    fn new_hasher(&self) -> Result<Hasher, sha256::Error> {
        Ok(Hasher {
            ctx: digest::Context::new(&digest::SHA256),
        })
    }
}

/// A `ring`-based [`sha256::Hasher`].
///
/// See [`Builder`].
pub struct Hasher {
    ctx: digest::Context,
}

impl sha256::Hasher for Hasher {
    fn write(&mut self, bytes: &[u8]) -> Result<(), sha256::Error> {
        self.ctx.update(bytes);
        Ok(())
    }

    fn finish(self, out: &mut sha256::Digest) -> Result<(), sha256::Error> {
        let digest = self.ctx.finish();
        out.copy_from_slice(digest.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;
    use crate::crypto::sha256::Builder as _;
    use crate::crypto::sha256::Hasher as _;
    use crate::crypto::testdata;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sha() {
        let sha = Builder::new();
        let mut digest = sha256::Digest::default();

        let mut hasher = sha.new_hasher().unwrap();
        hasher.write(testdata::PLAIN_TEXT).unwrap();
        hasher.finish(&mut digest).unwrap();
        assert_eq!(&digest, testdata::PLAIN_SHA256);

        let mut hasher = sha.new_hasher().unwrap();
        hasher.write(&testdata::PLAIN_TEXT[..16]).unwrap();
        hasher.write(&testdata::PLAIN_TEXT[16..]).unwrap();
        hasher.finish(&mut digest).unwrap();
        assert_eq!(&digest, testdata::PLAIN_SHA256);
    }
}
