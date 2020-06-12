// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cerberus manifest manipulation.
//!
//! Cerberus uses a number of signed "manifests" to describe both the physical
//! configuration of a system it protects, and to describe policies on what
//! firmware can run on those systems.

use core::fmt;

use crate::crypto::rsa;
use crate::io;
use crate::io::Read;
use crate::protocol::WireEnum;

pub mod fpm;
pub use fpm::Fpm;

wire_enum! {
    /// A Cerberus [`Manifest`] type.
    ///
    /// This enum represents the "magic number" `u16` value in a maniest header.
    ///
    /// [`Manifest`]: struct.Manifest.html
    pub enum ManifestType: u16 {
        /// A ["Firmware Policy Manifest"], a `manticore`-specific variant of the
        /// PFM.
        ///
        /// ["Firmware Policy Manifest"]: fpm/index.html
        Fpm = 0xda0e,
    }
}

/// A parsed, verified Cerberus manifest.
///
/// This type represents a generic, authenticated manifest. A value of this
/// type is a witness that authentication via signature was successful; it is
/// not possible to parse a `Manifest` without also verifying it.
///
///
/// On the wire, a `Manifest` looks like the following:
/// ```text
/// struct Manifest {
///     /// Total length, including the header.
///     len: u16,
///     /// The "magic number", which determines the manifest type.
///     magic: u16,
///     /// The monotonic id.
///     id: u32,
///     /// The length of the signature.
///     sig_len: u16,
///     /// Alignment padding.
///     _: u16,
///     /// The manifest-specific body.
///     body: [u8; self.len - HEADER_LEN - self.sig_len],
///     /// The cryptographic signature, an RSA signature in PKCS 1.5
///     /// format.
///     signature: [u8; self.sig_len],
/// }
/// ```
///
/// This manifest format is intended to be fully wire-compatible with Cerberus,
/// although the magic number and the manifest body may contain payloads that
/// are `manticore`-specific.
pub struct Manifest<'m> {
    /// The type of this `Manifest`.
    manifest_type: ManifestType,
    /// A monotonically-increasing ID for a `Manifest`.
    ///
    /// When a `Manifest` is updated, the incoming, updated `Manifest` is
    /// required to have a higher ID. This ensures that older manifests cannot
    /// be used in a replay attack.
    id: u32,
    /// The body of the `Manifest`. The structure of this buffer is
    /// specific to each `ManifestType`.
    ///
    /// [`ManifestType`]: enum.ManifestType.html
    body: &'m [u8],
}

/// An error returned by a [`Manifest`] parsing operation.
///
/// [`Manifest`]: struct.Manifest.html
#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    /// Indicates an error in a low-level [`io`] type.
    ///
    /// [`io`]: ../io/index.html
    Io(io::Error),
    /// Indicates that a parsed value was out of its expected range, like a
    /// magic number.
    OutOfRange,
    /// Indicates that some assumption about a manifest's alignment (internal
    /// or overall) was violated.
    Unaligned,
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// An error returned by a manifest parsing and verification operation.
///
/// This error is separate from `ParseError`, since most manifest parsing does
/// not need to perform cryptographic operations, making the `Rsa` parameter
/// unecessary.
#[derive(Clone, Copy)]
pub enum ParseOrVerifyError<Rsa: rsa::Engine> {
    /// Indicates an error in an [`rsa::Engine`].
    ///
    /// This encompases, among other errors, signature verification errors.
    ///
    /// [`rsa::Engine`]: ../crypto/rsa/trait.Engine.html
    Crypto(Rsa::Error),
    /// Indicates a non-cryptographic error.
    Parse(ParseError),
}

impl<Rsa: rsa::Engine> From<io::Error> for ParseOrVerifyError<Rsa> {
    fn from(e: io::Error) -> Self {
        Self::Parse(ParseError::Io(e))
    }
}

impl<Rsa: rsa::Engine> From<ParseError> for ParseOrVerifyError<Rsa> {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

// Note: this can't be derived, because of the non-trivial bound
// `Rsa::Error: fmt::Debug`.
impl<Rsa: rsa::Engine> fmt::Debug for ParseOrVerifyError<Rsa>
where
    Rsa::Error: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Crypto(e) => f.debug_tuple("Crypto").field(e).finish(),
            Self::Parse(e) => f.debug_tuple("Parse").field(e).finish(),
        }
    }
}

impl<'m> Manifest<'m> {
    /// Parses and verifies a `Manifest` using the provided [`rsa::Engine`].
    ///
    /// This function first parses the `Manifest`'s header, which it uses for
    /// finding the signature at the end of the buffer.
    ///
    /// `buf` must be aligned to a four-byte boundary.
    ///
    /// [`rsa::Engine`]: ../crypto/rsa/trait.Engine.html
    pub fn parse_and_verify<Rsa: rsa::Engine>(
        buf: &'m [u8],
        rsa: &mut Rsa,
    ) -> Result<Self, ParseOrVerifyError<Rsa>> {
        if buf.as_ptr().align_offset(4) != 0 {
            return Err(ParseError::Unaligned.into());
        }

        let mut r = buf;
        let buf_len = r.remaining_data();
        let len = r.read_le::<u16>()? as usize;
        let magic = r.read_le::<u16>()?;
        let id = r.read_le::<u32>()?;
        let sig_len = r.read_le::<u16>()? as usize;
        let _ = r.read_le::<u16>()?;
        let header_len = buf_len - r.remaining_data();

        let rest = r.read_bytes(len - header_len)?;
        let sig_offset = len - sig_len;
        let (body, signature) = rest.split_at(sig_offset - header_len);

        // We need to include the header in the "signed portion". This code
        // cannot panic, because we have already completely consumed the buffer
        // up until to `sig_offset`.
        let signed_portion = &buf[..sig_offset];
        rsa.verify_signature(signature, signed_portion)
            .map_err(ParseOrVerifyError::Crypto)?;

        Ok(Manifest {
            manifest_type: ManifestType::from_wire(magic)
                .ok_or(ParseError::OutOfRange)?,
            id,
            body,
        })
    }

    /// Returns the [`ManifestType`] for this `Manifest`.
    ///
    /// [`ManifestType`]: enum.ManifestType.html
    pub fn manifest_type(&self) -> ManifestType {
        self.manifest_type
    }

    /// Checks whether this `Manifest` can replace `other`.
    ///
    /// In other words, `self` must:
    /// - Be of the same type as `other`.
    /// - Have a greater or equal `id` number than `other`.
    pub fn can_replace(&self, other: &Self) -> bool {
        self.manifest_type == other.manifest_type && self.id >= other.id
    }

    /// Returns the authenticated body of the `Manifest`.
    pub fn body(&self) -> &'m [u8] {
        self.body
    }
}

/// Reads exactly `n * size_of::<T>` bytes from `r`, and converts them
/// into a slice of `T`s.
///
/// Moreover, this function requires that the next pointer that would be
/// returned by `read_bytes()` is well-aligned for `T`; otherwise,
/// `ParseError::Unaligned` is returned.
fn read_zerocopy<'m, T: zerocopy::FromBytes>(
    r: &mut &'m [u8],
    count: usize,
) -> Result<&'m [T], ParseError> {
    let expected_len = core::mem::size_of::<T>()
        .checked_mul(count)
        .ok_or(io::Error::BufferExhausted)?;
    let bytes = r.read_bytes(expected_len)?;
    let layout = zerocopy::LayoutVerified::new_slice(bytes)
        .ok_or(ParseError::Unaligned)?;
    Ok(layout.into_slice())
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::crypto::ring;
    use crate::crypto::rsa::Builder as _;
    use crate::crypto::testdata;

    const MANIFEST_HEADER: &[u8] = &[
        0x1e, 0x01, // Total length. This is the header length (12) +
        //          // body length (18) + signature length (256).
        0x0e, 0xda, // FPM magic.
        0xaa, 0x55, 0x01, 0x00, // Manifest id (0x55aa).
        0x00, 0x01, // Signature length (0x800 = 256).
        0xff, 0xff, // Padding to 4 bytes.
    ];

    const MANIFEST_CONTENTS: &[u8] = b"Manifest contents!";

    #[test]
    fn parse_manifest() {
        let mut manifest = MANIFEST_HEADER.to_vec();
        manifest.extend_from_slice(MANIFEST_CONTENTS);
        let sig = ring::Rsa::sign_with_pkcs8(
            testdata::RSA_2048_PRIV_PKCS8,
            &manifest,
        );
        manifest.extend_from_slice(&sig);
        assert_eq!(manifest.len(), 0x11e);

        let pub_key =
            ring::RsaPubKey::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8);
        let mut rsa = ring::Rsa.new_engine(pub_key).unwrap();

        let manifest = Manifest::parse_and_verify(&manifest, &mut rsa).unwrap();
        assert_eq!(manifest.manifest_type(), ManifestType::Fpm);
        assert_eq!(manifest.body(), MANIFEST_CONTENTS);
    }

    #[test]
    fn parse_manifest_too_short() {
        let mut manifest = MANIFEST_HEADER.to_vec();
        manifest.extend_from_slice(&MANIFEST_CONTENTS[1..]);
        let sig = ring::Rsa::sign_with_pkcs8(
            testdata::RSA_2048_PRIV_PKCS8,
            &manifest,
        );
        manifest.extend_from_slice(&sig);
        assert_eq!(manifest.len(), 0x11d);

        let pub_key =
            ring::RsaPubKey::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8);
        let mut rsa = ring::Rsa.new_engine(pub_key).unwrap();

        assert!(Manifest::parse_and_verify(&manifest, &mut rsa).is_err());
    }

    #[test]
    fn parse_manifest_bad_sig() {
        let mut manifest = MANIFEST_HEADER.to_vec();
        manifest.extend_from_slice(MANIFEST_CONTENTS);
        let mut sig = ring::Rsa::sign_with_pkcs8(
            testdata::RSA_2048_PRIV_PKCS8,
            &manifest,
        );

        // Flip a byte in the signature.
        sig[0] = !sig[0];
        manifest.extend_from_slice(&sig);
        assert_eq!(manifest.len(), 0x11e);

        let pub_key =
            ring::RsaPubKey::from_pkcs8(testdata::RSA_2048_PRIV_PKCS8);
        let mut rsa = ring::Rsa.new_engine(pub_key).unwrap();

        assert!(matches!(
            Manifest::parse_and_verify(&manifest, &mut rsa),
            Err(ParseOrVerifyError::Crypto(..))
        ));
    }
}
