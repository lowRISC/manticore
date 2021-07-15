// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! COSE and CWT certificate parser.
//!
//! See https://datatracker.ietf.org/doc/html/rfc8152 and
//! https://datatracker.ietf.org/doc/html/rfc8392

use crate::cert;
use crate::cert::cbor::Item;
use crate::cert::x509;
use crate::cert::Algo;
use crate::cert::Cert;
use crate::cert::Error;
use crate::cert::Name;
use crate::cert::PublicKeyParams;

#[cfg(test)]
#[path = "cwt_test.rs"]
mod test;

// Well-known CBOR labels.
#[allow(unused)]
mod label {
    use crate::cert::cbor::Int;
    // COSE header labels. See RFC8152 Table 2.
    // Labels not listed here are ignored.
    pub const COSE_ALG: Int = Int::from_i32(1);
    pub const COSE_CRIT: Int = Int::from_i32(2);
    pub const COSE_KID: Int = Int::from_i32(4);

    // COSE key structure labels. See RFC8152 Table 3.
    pub const KEY_KTY: Int = Int::from_i32(1);
    pub const KEY_KID: Int = Int::from_i32(2);
    pub const KEY_ALG: Int = Int::from_i32(3);
    pub const KEY_KEY_OPS: Int = Int::from_i32(4);
    pub const KEY_IV: Int = Int::from_i32(5);

    pub const KEY_KTY_OKP: Int = Int::from_i32(1);
    pub const KEY_KTY_EC2: Int = Int::from_i32(2);
    pub const KEY_KTY_RSA: Int = Int::from_i32(3);

    // COSE algorithms.
    //
    // See https://www.iana.org/assignments/cose/cose.xhtml
    pub const RSA_PKCS1_SHA256: Int = Int::from_i32(-257);

    // RSA key fields.
    pub const RSA_MODULUS: Int = Int::from_i32(-1);
    pub const RSA_EXPONENT: Int = Int::from_i32(-2);

    // CWT fields.
    pub const CWT_ISS: Int = Int::from_i32(1);
    pub const CWT_SUB: Int = Int::from_i32(2);
    pub const CWT_AUD: Int = Int::from_i32(3);
    pub const CWT_EXP: Int = Int::from_i32(4);
    pub const CWT_NBF: Int = Int::from_i32(5);
    pub const CWT_IAT: Int = Int::from_i32(6);
    pub const CWT_CTI: Int = Int::from_i32(7);

    // OpenDICE-specific CWT fields.
    //
    // https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#profile-design-certificate-details-cbor-cdi-certificates-additional-fields
    pub const DICE_CODE_HASH: Int = Int::from_i32(-4670545);
    pub const DICE_CODE_DESC: Int = Int::from_i32(-4670546);
    pub const DICE_CONFIG_HASH: Int = Int::from_i32(-4670547);
    pub const DICE_CODFIG_DESC: Int = Int::from_i32(-4670548);
    pub const DICE_AUTHZ_HASH: Int = Int::from_i32(-4670549);
    pub const DICE_AUTHZ_DESC: Int = Int::from_i32(-4670550);
    pub const DICE_MODE: Int = Int::from_i32(-4670551);
    pub const DICE_SPKI: Int = Int::from_i32(-4670552);
    pub const DICE_KEY_USAGE: Int = Int::from_i32(-4670553);
}

/// Parses a CWT certificate.
pub fn parse<'cert>(
    cert: &'cert [u8],
    key: Option<&PublicKeyParams<'_>>,
    ciphers: &mut impl cert::Ciphers,
) -> Result<Cert<'cert>, Error> {
    let buf = untrusted::Input::from(cert);
    let cose = buf.read_all(Error::BadEncoding, Cose::parse)?;

    let (issuer, subject, subject_key, ku) =
        cose.payload.read_all(Error::BadEncoding, |buf| {
            Item::parse(buf)?.into_map()?.walk(|map| {
                let iss =
                    Name(map.must_get(label::CWT_ISS)?.into_utf8()?.as_bytes());
                let sub =
                    Name(map.must_get(label::CWT_SUB)?.into_utf8()?.as_bytes());

                let (_algo, params) =
                    parse_cose_key(map.must_get(label::DICE_SPKI)?)?;
                let ku = map
                    .get(label::DICE_KEY_USAGE)?
                    .map(|v| x509::KeyUsage::from_le(v.into_bytes()?))
                    .transpose()?;
                Ok((iss, sub, params, ku))
            })
        })?;

    let key = key.unwrap_or(&subject_key);
    if !key.is_params_for(cose.algo) {
        return Err(Error::WrongAlgorithm);
    }

    let verifier = ciphers
        .verifier(cose.algo, key)
        .ok_or(Error::UnknownAlgorithm)?;
    // FIXME: Verify the signature once we switch sig::Verify to use something
    // like an iovec.
    // verifier.verify(cose.signature, &[
    //     // Length prefix for the whole array: major 0b100, length 5;
    //     // encoded context string.
    //     b"\x{85}\x{4a}Signature1",
    //     // Encoded protected bucket map.
    //     cose.protected_bytes,
    //     // Empty bstr for external_aad.
    //     b"\x{60}",
    //     // Encoded payload map.
    //     cose.payload.as_slice_less_safe(),
    // ]).map_err(|_| Error::BadSignature)?;
    let _ = (verifier, cose.signature, cose.protected_bytes);

    Ok(Cert {
        format: cert::CertFormat::OpenDiceCwt,
        issuer,
        subject,
        subject_key,
        basic_constraints: None,
        is_cert_sign: ku.map(|ku| ku.is_cert_sign()).unwrap_or(false),
    })
}

fn parse_cose_key<'cert>(
    key: Item<'cert, '_>,
) -> Result<(Option<Algo>, PublicKeyParams<'cert>), Error> {
    key.into_map()?.walk(|map| {
        let kty = map.must_get(label::KEY_KTY)?.into_int()?;
        let _kid =
            map.get(label::KEY_KID)?.map(Item::into_bytes).transpose()?;
        let algo = map.get(label::KEY_ALG)?.map(parse_algo).transpose()?;
        // Skip other fields for now.

        let params = match kty {
            label::KEY_KTY_RSA => {
                let modulus = map.must_get(label::RSA_MODULUS)?.into_bytes()?;
                let exponent =
                    map.must_get(label::RSA_EXPONENT)?.into_bytes()?;
                PublicKeyParams::Rsa { modulus, exponent }
            }
            _ => return Err(Error::UnknownAlgorithm),
        };
        Ok((algo, params))
    })
}

fn parse_algo(v: Item) -> Result<Algo, Error> {
    match v.into_int()? {
        label::RSA_PKCS1_SHA256 => Ok(Algo::RsaPkcs1Sha256),
        _ => Err(Error::UnknownAlgorithm),
    }
}

/// A COSE Sign1 structure.
struct Cose<'cert> {
    algo: Algo,
    protected_bytes: &'cert [u8],
    payload: untrusted::Input<'cert>,
    signature: &'cert [u8],

    // The COSE RFC isn't super clear on how you're meant to use the key id,
    // so we ignore it for now.
    #[allow(unused)]
    kid: Option<&'cert [u8]>,
}

impl<'cert> Cose<'cert> {
    fn parse(buf: &mut untrusted::Reader<'cert>) -> Result<Cose<'cert>, Error> {
        struct Headers<'cert> {
            algo: Option<Algo>,
            kid: Option<&'cert [u8]>,
        }

        fn parse_headers<'cert>(
            buf: &mut untrusted::Reader<'cert>,
            protected: bool,
        ) -> Result<Headers<'cert>, Error> {
            Item::parse(buf)?.into_map()?.walk(|map| {
                let algo = map
                    .get(label::COSE_ALG)?
                    .map(|v| {
                        if !protected {
                            return Err(Error::BadEncoding);
                        }
                        parse_algo(v)
                    })
                    .transpose()?;

                map.get(label::COSE_CRIT)?
                    .map(|v| -> Result<_, _> {
                        if !protected {
                            return Err(Error::BadEncoding);
                        }
                        v.into_array()?.with(|l| match l.into_int()? {
                            // We don't handle any other labels, so CRIT can't
                            // contain any others.
                            label::COSE_ALG
                            | label::COSE_CRIT
                            | label::COSE_KID => Ok(()),
                            _ => Err(Error::BadEncoding),
                        })
                    })
                    .transpose()?;

                let kid = map
                    .get(label::COSE_KID)?
                    .map(Item::into_bytes)
                    .transpose()?;

                Ok(Headers { algo, kid })
            })
        }

        // NOTE: the protected portion of the COSE structure is a map wrapped
        // in a bstr, similar to how X.509 extensions are DER wrapped up in
        // an OCTET STRING. The payload below is similar.
        //
        // The prefix byte for both structures needs to be preserved, since
        // those are mixed into the signature.
        let protected_bytes = Item::parse(buf)?.into_bytes()?;
        let Headers { algo, kid } = untrusted::Input::from(protected_bytes)
            .read_all(Error::BadEncoding, |buf| {
                // Because the `alg` field is a hard requirement, we don't
                // need to handle the case when `buf` is empty.
                parse_headers(buf, true)
            })?;

        let Headers { kid: kid2, .. } = parse_headers(buf, false)?;
        if kid.is_some() && kid2.is_some() {
            return Err(Error::BadEncoding);
        }

        let payload = untrusted::Input::from(Item::parse(buf)?.into_bytes()?);
        let signature = Item::parse(buf)?.into_bytes()?;

        Ok(Cose {
            algo: algo.ok_or(Error::BadEncoding)?,
            kid: kid.or(kid2),
            protected_bytes,
            payload,
            signature,
        })
    }
}
