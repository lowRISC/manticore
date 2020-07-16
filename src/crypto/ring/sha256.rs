// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::sha256`] based on `ring`.
//!
//! [`crypto::sha256`]: ../../sha256/index.html

use core::convert::Infallible;

use ring::digest;

use crate::crypto::sha256;

/// A `ring`-based [`sha256::Builder`].
///
/// [`sha256::Builder`]: ../../sha256/trait.Builder.html
pub struct Builder {
    _priv: (),
}

impl Builder {
    /// Creates a new `Builder`.
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl sha256::Builder for Builder {
    type Hasher = Hasher;

    fn new_hasher(&self) -> Result<Hasher, Infallible> {
        Ok(Hasher {
            ctx: digest::Context::new(&digest::SHA256),
        })
    }
}

/// A `ring`-based [`sha256::Hasher`].
///
/// See [`ring::sha256::Builder`].
///
/// [`sha256::Hasher`]: ../../sha256/trait.Hasher.html
/// [`ring::sha256::Builder`]: struct.Builder.html
pub struct Hasher {
    ctx: digest::Context,
}

impl sha256::Hasher for Hasher {
    type Error = Infallible;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Infallible> {
        self.ctx.update(bytes);
        Ok(())
    }

    fn finish(self, out: &mut sha256::Digest) -> Result<(), Infallible> {
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
