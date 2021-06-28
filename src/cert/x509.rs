// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! X.509 parsing.

use crate::cert;
use crate::cert::der;
use crate::cert::der::Tag;
use crate::cert::Algo;
use crate::cert::Cert;
use crate::cert::Error;
use crate::cert::Name;
use crate::cert::PublicKeyParams;

#[cfg(test)]
#[path = "x509_test.rs"]
mod test;

/// OIDs used by the parser.
#[allow(unused)]
mod oid {
    use crate::cert::der::Oid;

    pub const RSA_ENCRYPTION: Oid = oid!(1, 2, 840, 113549, 1, 1, 1);
    pub const RSA_PKCS1_SHA256: Oid = oid!(1, 2, 840, 113549, 1, 1, 11);

    pub const KEY_USAGE: Oid = oid!(2, 5, 29, 15);
    pub const BASIC_CONSTRAINTS: Oid = oid!(2, 5, 29, 19);
    pub const TCG_DICE_FWID: Oid = oid!(2, 23, 133, 5, 4, 1);
}

/// Parses an RFC3279 algorithm identifier.
fn parse_algo(buf: &mut untrusted::Reader) -> Result<Algo, Error> {
    match der::oid(buf)? {
        oid::RSA_PKCS1_SHA256 => {
            der::null(buf)?;
            Ok(Algo::RsaPkcs1Sha256)
        }
        _ => Err(Error::UnknownAlgorithm),
    }
}

/// Parses an X.509 certificate.
///
/// This function performs several aggressive checks to reject any and all
/// certificates that do not fit our profile. These include:
/// - Version must be v3.
/// - Extensions must be present.
/// - `keyUsage`, `authorityKeyIdentifier`, `subjectKeyIdentifier` must all
///   be present.
///   - A `keyUsage` with `keyCertSign` and any other usage is rejected.
///
/// All of the above are treated as encoding errors.
pub fn parse<'cert>(
    cert: &'cert [u8],
    format: cert::CertFormat,
    key: Option<&PublicKeyParams<'_>>,
    ciphers: &mut impl cert::Ciphers,
) -> Result<Cert<'cert>, Error> {
    let buf = untrusted::Input::from(cert);
    let (cert, tbs, sig_algo, sig) =
        buf.read_all(Error::BadEncoding, |buf| {
            der::tagged(Tag::SEQUENCE, buf, |buf| {
                let mark = buf.mark();
                let tbs = der::parse(Tag::SEQUENCE, buf)?;
                let tbs_bytes =
                    buf.get_input_between_marks(mark, buf.mark())?;
                let sig_algo_bytes = der::parse(Tag::SEQUENCE, buf)?;
                let sig_algo =
                    sig_algo_bytes.read_all(Error::BadEncoding, parse_algo)?;

                let sig = der::bits_total(buf)?;

                let cert = tbs.read_all(Error::BadEncoding, |buf| {
                    parse_tbs(format, sig_algo_bytes, buf)
                })?;

                Ok((
                    cert,
                    tbs_bytes.as_slice_less_safe(),
                    sig_algo,
                    sig.as_slice_less_safe(),
                ))
            })
        })?;

    let key = key.unwrap_or_else(|| cert.subject_key());
    if !key.is_params_for(sig_algo) {
        return Err(Error::WrongAlgorithm);
    }

    let verifier = ciphers
        .verifier(sig_algo, key)
        .ok_or(Error::UnknownAlgorithm)?;
    verifier.verify(sig, tbs).map_err(|_| Error::BadSignature)?;

    Ok(cert)
}

fn parse_tbs<'cert>(
    format: cert::CertFormat,
    sig_algo_bytes: untrusted::Input,
    buf: &mut untrusted::Reader<'cert>,
) -> Result<Cert<'cert>, Error> {
    // Although the version field is optional, we reject all non-v3
    // certificates, which require this field.
    //
    // We treat this as a syntactic, rather than semantic, error.
    der::tagged(Tag::context_specific(0), buf, |mut buf| {
        // `v3` certificates are encoded as an `INTEGER { 2 }`.
        if der::u32(&mut buf)? != 2 {
            return Err(Error::BadEncoding);
        }
        Ok(())
    })?;

    // The certificate serial number must be a positive `INTEGER` consisting
    // of at most 20 octets.
    //
    // Like with the version, this is a syntactic error. The value itself
    // is discarded.
    let serial = der::uint(buf)?.as_slice_less_safe();
    if serial[0] == 0 || serial.len() > 20 {
        return Err(Error::BadEncoding);
    }

    // A mismatch between the inner and outer signature algorithm
    // identifiers (byte-for-byte) is a syntax error.
    let sig_algo2 = der::parse(Tag::SEQUENCE, buf)?;
    if sig_algo2 != sig_algo_bytes {
        return Err(Error::BadEncoding);
    }

    // The issuer is an opaque name.
    let issuer = Name(der::parse(Tag::SEQUENCE, buf)?.as_slice_less_safe());

    // TODO: Provide some mechanism for the user to pass in a clock, if
    // available. X.509 time parsing incurs significant complexity, so
    // it probably shouldn't be implemented until it's absolutely necessary.
    let _validity = der::parse(Tag::SEQUENCE, buf)?;

    // The subject is also opaque
    let subject = Name(der::parse(Tag::SEQUENCE, buf)?.as_slice_less_safe());

    let subject_key = der::tagged(Tag::SEQUENCE, buf, |buf| {
        let (algo, aparams) = der::tagged(Tag::SEQUENCE, buf, |buf| {
            let algo = der::oid(buf)?;
            let aparams = buf.read_bytes_to_end();
            Ok((algo, aparams))
        })?;

        der::bits_total(buf)?.read_all(Error::BadEncoding, |buf| match algo {
            oid::RSA_ENCRYPTION => {
                aparams.read_all(Error::BadEncoding, der::null)?;
                der::tagged(Tag::SEQUENCE, buf, |buf| {
                    let mut modulus = der::uint(buf)?.as_slice_less_safe();
                    // DER inserts a leading zero sometimes (to disambiguate
                    // negative integers) so we need to remove it.
                    if modulus[0] == 0 {
                        modulus = &modulus[1..];
                    }
                    let mut exponent = der::uint(buf)?.as_slice_less_safe();
                    if exponent[0] == 0 {
                        exponent = &exponent[1..];
                    }
                    Ok(PublicKeyParams::Rsa { modulus, exponent })
                })
            }
            _ => Err(Error::UnknownAlgorithm),
        })
    })?;

    // We don't care about the UIDs at all.
    let _issuer_uid = der::opt(Tag::context_specific(1), buf)?;
    let _subject_uid = der::opt(Tag::context_specific(2), buf)?;

    // Extensions are mandatory.
    let mut extns = Extensions::default();
    der::tagged(Tag::context_specific(3), buf, |buf| {
        der::tagged(Tag::SEQUENCE, buf, |buf| {
            while !buf.at_end() {
                parse_extn(buf, &mut extns)?;
            }
            Ok(())
        })
    })?;

    let is_cert_sign = match extns.is_cert_sign {
        Some(b) => b,
        _ => return Err(Error::BadEncoding),
    };

    let is_ca = match &extns.basic_constraints {
        Some(bc) => bc.is_ca,
        _ => false,
    };

    // CA certificates must always specify keyCertSign as a valid usage. To
    // fail to do so is a syntax error.
    if is_ca != is_cert_sign {
        return Err(Error::BadEncoding);
    }

    Ok(Cert {
        format,
        issuer,
        subject,
        subject_key,
        basic_constraints: extns.basic_constraints,
        is_cert_sign,
    })
}

#[derive(Default)]
struct Extensions {
    basic_constraints: Option<cert::BasicConstraints>,
    is_cert_sign: Option<bool>,
}

fn parse_extn(
    buf: &mut untrusted::Reader,
    extns: &mut Extensions,
) -> Result<(), Error> {
    der::tagged(Tag::SEQUENCE, buf, |buf| {
        let oid = der::oid(buf)?;
        let is_critical = der::opt_bool(buf)?.unwrap_or(false);
        der::tagged(Tag::OCTET_STRING, buf, |buf| match oid {
            oid::KEY_USAGE => {
                if extns.is_cert_sign.is_some() {
                    return Err(Error::BadEncoding);
                }

                // Constants from RFC5280 S4.2.1.3. I.e.,
                // ```asn1
                // KeyUsage ::= BIT STRING {
                //   digitalSignature        (0),
                //   nonRepudiation          (1),
                //   keyEncipherment         (2),
                //   dataEncipherment        (3),
                //   keyAgreement            (4),
                //   keyCertSign             (5),
                //   cRLSign                 (6),
                //   encipherOnly            (7),
                //   decipherOnly            (8),
                // }
                // ```
                //
                // Note that the bits in a `BIT STRING` are big endian
                // within bytes, so we need to "shift from the left"
                // instead.
                const CERT_SIGN_MASK: u16 = 1 << (15 - 5);

                der::bits_partial(buf)?.read_all(Error::BadEncoding, |buf| {
                    let first_byte = buf.read_byte().unwrap_or(0);
                    let second_byte = buf.read_byte().unwrap_or(0);
                    // NOTE: This technically drops any "domain-specific"
                    // bits on the ground, but we have zero interest in retaining
                    // those.
                    let bits = u16::from_be_bytes([first_byte, second_byte]);

                    extns.is_cert_sign = Some(bits & CERT_SIGN_MASK != 0);
                    if extns.is_cert_sign == Some(true)
                        && bits != CERT_SIGN_MASK
                    {
                        // For domain separation reasons, we reject all
                        // certificates that mix certificate signing with any
                        // other usage.
                        return Err(Error::BadEncoding);
                    }

                    Ok(())
                })
            }
            oid::BASIC_CONSTRAINTS => {
                if extns.basic_constraints.is_some() {
                    return Err(Error::BadEncoding);
                }
                der::tagged(Tag::SEQUENCE, buf, |buf| {
                    let is_ca = der::opt_bool(buf)?.unwrap_or(false);
                    let path_len_constraint = der::opt_u32(buf)?;
                    extns.basic_constraints = Some(cert::BasicConstraints {
                        is_ca,
                        path_len_constraint,
                    });
                    Ok(())
                })
            }
            _ if is_critical => Err(Error::BadEncoding),
            _ => {
                // Drop the rest of the bytes on the floor. `untrusted` requires
                // us to explicitly use all bytes, but we just want to ignore
                // them in this case.
                let _ = buf.read_bytes_to_end();
                Ok(())
            }
        })
    })
}
