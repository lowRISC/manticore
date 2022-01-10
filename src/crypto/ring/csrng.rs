// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`crypto::csrng`] based on `ring`.
//!
//! Requires the `std` feature flag to be enabled.

use ring::rand::SecureRandom as _;
use ring::rand::SystemRandom;

use crate::crypto::csrng;
use crate::Result;

#[cfg(doc)]
use crate::crypto;

/// A [`csrng::Csrng`] backed by OS-supplied entropy.
pub struct Csrng {
    inner: SystemRandom,
}

impl Csrng {
    /// Creates a new entropy source.
    pub fn new() -> Self {
        Self {
            inner: SystemRandom::new(),
        }
    }
}

impl Default for Csrng {
    fn default() -> Self {
        Self::new()
    }
}

impl csrng::Csrng for Csrng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), csrng::Error> {
        self.inner
            .fill(buf)
            .map_err(|_| fail!(csrng::Error::Unspecified))
    }
}
