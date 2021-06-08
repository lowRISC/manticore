// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Certificate handling.
//!
//! This module implements types and functions for working with the
//! authentication portions of the Cerberus protocol, including
//! certificate parsing and handling.

use crate::crypto::sig;

/// A certificate format understood by Manticore.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CertFormat {
    /// An X.509v3 certificate, using the RIoT profile.
    ///
    /// TCG provides a published version of RIoT at
    /// https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Arch-Implicit-Identity-Based-Device-Attestation-v1-rev93.pdf.
    RiotX509,
    // TODO: describe other formats, such as the OpenDICE X.509 and CWT-based
    // formats.
}

/// A parsed certificate that has been validated against its signature.
///
/// This type contains all information necessary for validating a
/// certificate chain.
#[derive(Debug)]
pub struct Cert<'cert> {
    issuer: Name<'cert>,
    subject: Name<'cert>,
    subject_key: PublicKey<'cert>,
    signature_key: PublicKey<'cert>,
    path_len_constraint: Option<u32>,
    // Currently, we drop the authority identifier on the ground, but we may
    // want to communicate it for verification. It's an X.509-specific thing,
    // and isn't present in the CWT encoding.
}

/// A parse error for a [`Cert`].
#[derive(Clone, Debug)]
pub enum Error {
    /// Indicates that the signature is not supported by the [`Ciphers`] used.
    UnsupportedSig,
    /// Indicates that the encoding (e.g., DER or CBOR) was invalid for some
    /// reason.
    BadEncoding,
}

impl<'cert> Cert<'cert> {
    /// Parses `cert`, producing a parsed certificate in the given format.
    // TODO: Perhaps `cert` should be a Flash + Arena, instead?
    // It may also be useful to use this as an opportunity to perform a SHA
    // hash, for use in the DIGESTs series of messages.
    pub fn parse(
        cert: &'cert [u8],
        format: CertFormat,
        ciphers: &mut impl Ciphers,
    ) -> Result<Self, Error> {
        let _ = (cert, format, ciphers);
        todo!()
    }

    /// Returns the name of the certificate issuer (i.e., the subject of the
    /// certificate that signed it).
    pub fn issuer(&self) -> Name<'cert> {
        self.issuer
    }

    /// Returns the name of the certificate subject.
    pub fn subject(&self) -> Name<'cert> {
        self.subject
    }

    /// The subject key bound to this certificate.
    pub fn subject_key(&self) -> &PublicKey<'cert> {
        &self.subject_key
    }

    /// The key used in this certificate's signature.
    pub fn signature_key(&self) -> &PublicKey<'cert> {
        &self.signature_key
    }

    /// Whether this certificate's public key can be used to sign other
    /// certificates.
    ///
    /// As a matter of domain separation, certificates that can be used for
    /// this purpose should not be used for anything else.
    pub fn supports_cert_signing(&self) -> bool {
        todo!()
    }

    /// Returns whether `len` is within the path length constraint for this
    /// certificate.
    ///
    /// If this certificate signs another certificate in a trust chain, it
    /// may specify the maximum number of certificates that may follow it.
    /// `len` should be this number; by convention, it should be one less
    /// than the actual number of certificates that follow (i.e., not
    /// counting the leaf certificate).
    ///
    /// Some certificate formats might not provide such a constraint
    /// altogether, and this function will always return `true` for them.
    pub fn is_within_path_len_constraint(&self, len: usize) -> bool {
        match self.path_len_constraint {
            Some(l) => l as usize >= len,
            None => true,
        }
    }
}

/// A name associated with a certificate.
///
/// Names may only be printed (for debugging purposes) or compared
/// byte-for-byte. Manticore does not support X.500 distinguished name
/// comparisons.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Name<'cert>(&'cert [u8]);

/// A public key in a certificate.
///
/// Public keys are parsed into their component parts
#[derive(Debug)]
pub enum PublicKey<'cert> {
    /// PKCS#1.5-encoded RSA signatures using SHA-256 for hashing.
    RsaPkcs1Sha256 {
        /// The key modulus, in big-endian.
        modulus: &'cert [u8],
        /// The key exponent.
        exponent: u32,
    },
}

/// A collection of ciphers that are provided to certificate machinery.
///
/// Users are expected to implement this trait to efficiently describe to
/// Manticore which algorithms they consider acceptable and how to access them.
pub trait Ciphers {
    /// Returns a [`sig::Verify`] that can be used to verify signatures using
    /// the given `key`.
    ///
    /// Returns `None` if `key`'s algorithm is not supported.
    fn verifier<'a>(
        &'a mut self,
        key: &PublicKey,
    ) -> Option<&'a mut dyn sig::Verify<Error = ()>>;
}
