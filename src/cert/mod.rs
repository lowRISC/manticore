// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Certificate handling.
//!
//! This module implements types and functions for working with the
//! authentication portions of the Cerberus protocol, including
//! certificate parsing and handling.

use crate::crypto::sig;
use crate::io;

// Note that all parsers leverage Brian Smith's `untrusted` crate to ensure
// we don't walk off the end of the buffer. We may wind up building this
// functionality into `manticore::io` if buffering certificates in memory
// proves to be a non-starter.
#[macro_use]
mod der;

mod x509;

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
    format: CertFormat,
    issuer: Name<'cert>,
    subject: Name<'cert>,
    subject_key: PublicKeyParams<'cert>,
    basic_constraints: Option<BasicConstraints>,
    // Currently, we drop the authority identifier on the ground, but we may
    // want to communicate it for verification.

    // For now, we drop all key usage bits except for keyCertSign on the
    // ground. In the future, will want to retain more usage bits as
    // necessary.
    is_cert_sign: bool,
}

/// X.509-specific `basicConstraints` extension.
#[derive(Debug)]
struct BasicConstraints {
    is_ca: bool,
    path_len_constraint: Option<u32>,
}

/// A parse error for a [`Cert`].
///
/// Note: `Error: From<untrusted::EndOfInput>` is an *implementation detail*
/// that should not be relied upon. We reserve the right to break this but
/// Rust does not provide a way to scope `impl` blocks.
#[derive(Clone, Debug)]
pub enum Error {
    /// Indicates that the signature is not supported by the [`Ciphers`] used.
    UnsupportedSig,
    /// Indicates that the encoding (e.g., DER or CBOR) was invalid for some
    /// reason.
    BadEncoding,
    /// Indicates that a low-level I/O error occured while parsing a cert.
    Io(io::Error),
    /// An algorithm specified in a certificate was not known to Manticore.
    UnknownAlgorithm,
    /// The signature algorithm in a certificate did not match the key
    /// provided.
    WrongAlgorithm,
    /// The certificate being verified had a bad signature.
    BadSignature,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<untrusted::EndOfInput> for Error {
    fn from(_: untrusted::EndOfInput) -> Self {
        Self::Io(io::Error::BufferExhausted)
    }
}

impl<'cert> Cert<'cert> {
    /// Parses `cert`, producing a parsed certificate in the given format.
    ///
    /// If `key` (the key to verify the certificate with) is not provided, then
    /// the certificate is assumed to be self signed, and will be verified
    /// against its own subject key.
    // TODO: Perhaps `cert` should be a Flash + Arena, instead?
    // It may also be useful to use this as an opportunity to perform a SHA
    // hash, for use in the DIGESTs series of messages.
    pub fn parse(
        cert: &'cert [u8],
        format: CertFormat,
        key: Option<&PublicKeyParams<'_>>,
        ciphers: &mut impl Ciphers,
    ) -> Result<Self, Error> {
        match format {
            CertFormat::RiotX509 => x509::parse(cert, format, key, ciphers),
        }
    }

    /// Returns the format this certificate was parsed from.
    pub fn format(&self) -> CertFormat {
        self.format
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
    pub fn subject_key(&self) -> &PublicKeyParams<'cert> {
        &self.subject_key
    }

    /// Whether this certificate's public key can be used to sign other
    /// certificates.
    ///
    /// As a matter of domain separation, certificates that can be used for
    /// this purpose should not be used for anything else.
    pub fn supports_cert_signing(&self) -> bool {
        self.is_cert_sign
    }

    /// Returns whether this certificate is *explicitly* a CA (i.e., not leaf)
    /// cert.
    ///
    /// Some formats do not include this information. When validating a trust
    /// chain, this value should be checked if and only if the format includes
    /// it.
    pub fn is_explicit_ca_cert(&self) -> bool {
        match &self.basic_constraints {
            Some(bc) => bc.is_ca,
            None => false,
        }
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
        match &self.basic_constraints {
            Some(BasicConstraints {
                path_len_constraint: Some(l),
                ..
            }) => *l as usize >= len,
            _ => true,
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

/// Public key parameters extracted from a certificate.
///
/// This must be paired with a compatible [`Algo`] (which specifies *algorithm*
/// parameters) to be usable for signature verification.
#[derive(Debug)]
pub enum PublicKeyParams<'cert> {
    /// RSA in an unspecified forma with an unspecified hash function.
    Rsa {
        /// The key modulus, in big-endian.
        modulus: &'cert [u8],
        /// The key exponent, in big-endian.
        exponent: &'cert [u8],
    },
}

impl PublicKeyParams<'_> {
    /// Returns whether these parameters are appropriate for the given
    /// algorithm.
    pub fn is_params_for(&self, algo: Algo) -> bool {
        match (self, algo) {
            (Self::Rsa { .. }, Algo::RsaPkcs1Sha256) => true,
        }
    }
}

/// A signature algorithm for a subject key.
///
/// Each variant of this enum captures all parameters of the algorithm.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algo {
    /// PKCS#1.5-encoded RSA signatures using SHA-256 for hashing.
    RsaPkcs1Sha256,
}

/// A collection of ciphers that are provided to certificate machinery.
///
/// Users are expected to implement this trait to efficiently describe to
/// Manticore which algorithms they consider acceptable and how to access them.
pub trait Ciphers {
    /// The error returned by verifiers on failure.
    type Error;

    /// Returns a [`sig::Verify`] that can be used to verify signatures using
    /// the given `key`.
    ///
    /// Returns `None` if `key`'s algorithm is not supported.
    fn verifier<'a>(
        &'a mut self,
        algo: Algo,
        key: &PublicKeyParams,
    ) -> Option<&'a mut dyn sig::Verify<Error = Self::Error>>;
}
