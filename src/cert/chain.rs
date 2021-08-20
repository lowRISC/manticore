// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Cert chains.

use core::num::NonZeroUsize;

use arrayvec::ArrayVec;

use crate::cert::Cert;
use crate::cert::CertFormat;
use crate::cert::Error;
use crate::crypto::sig;

/// A trust chain collection.
///
/// A trust chain consists of a sequence of certificates, starting with a
/// self-signed root certificate, and ending in a leaf certificate with some
/// a public key we wish to authenticate against the root.
///
/// A `TrustChain` actually manages a small number of chains across several
/// *slots*; all Cerberus authentication messages refer to a specific
/// certificate slot.
pub trait TrustChain {
    /// Gets the length of the `slot`th chain.
    ///
    /// Cannot be zero; returns `None` if this chain has no such slot.
    fn chain_len(&self, slot: u8) -> Option<NonZeroUsize>;

    /// Gets the `index`th cert of the `slot`th chain.
    ///
    /// Returns `None` if `index` is out of bounds or if there is no `slot`th
    /// chain. These cases can be distinguished by calling `chain_len()`.
    fn cert(&self, slot: u8, index: usize) -> Option<&Cert>;
}

/// A simple trust with only one slot.
#[derive(Debug)]
pub struct SimpleChain<'cert, const LEN: usize> {
    chain: [Cert<'cert>; LEN],
}

impl<'cert, const LEN: usize> SimpleChain<'cert, LEN> {
    /// Parses and verifies the trust chain described by `raw_chain`,
    /// which starts at the root certificate for the trust chain.
    pub fn parse(
        raw_chain: &[&'cert [u8]],
        format: CertFormat,
        ciphers: &mut impl sig::Ciphers,
    ) -> Result<Self, Error> {
        if raw_chain.len() != LEN {
            return Err(Error::ChainTooShort);
        }

        let mut chain = ArrayVec::new();
        for (i, &raw_cert) in raw_chain.iter().enumerate() {
            let prev = chain.last();
            let key = prev.map(|cert: &Cert| cert.subject_key());
            let cert = Cert::parse(raw_cert, format, key, ciphers)?;

            let prev = prev.unwrap_or(&cert);
            if prev.subject() != cert.issuer() {
                return Err(Error::BadChainLink);
            }
            if !prev.supports_cert_signing() {
                return Err(Error::BadChainLink);
            }

            // None is also ok; it means the format (e.g. CWT) does not support
            // a CA bit.
            if prev.is_ca_cert() == Some(false) {
                return Err(Error::BadChainLink);
            }

            // raw_chain.len() - i is the number of certificates that follow
            // `cert`; the path length constraint for `prev` is the number of
            // certs that follow it, except the leaf; these numbers are the
            // same.
            if !prev.is_within_path_len_constraint(raw_chain.len() - i) {
                return Err(Error::BadChainLink);
            }

            chain.push(cert);
        }

        // Cannot panic, since we called push() LEN times.
        Ok(Self {
            chain: chain.into_inner().unwrap(),
        })
    }
}

impl<const LEN: usize> TrustChain for SimpleChain<'_, LEN> {
    fn cert(&self, slot: u8, index: usize) -> Option<&Cert> {
        if slot != 0 {
            return None;
        }
        self.chain.get(index)
    }

    fn chain_len(&self, slot: u8) -> Option<NonZeroUsize> {
        if slot != 0 {
            return None;
        }
        NonZeroUsize::new(self.chain.len())
    }
}

#[cfg(all(test, not(miri)))] // TODO(#103)
mod test {
    use super::*;
    use testutil::data::keys;
    use testutil::data::x509;

    use crate::cert::cwt::test::TestCwt;
    use crate::crypto::ring;
    use crate::crypto::sig::PublicKeyParams;

    #[test]
    fn x509_chain_parse() {
        let chain = SimpleChain::<3>::parse(
            &[x509::CHAIN1, x509::CHAIN2, x509::CHAIN3],
            CertFormat::RiotX509,
            &mut ring::sig::Ciphers::new(),
        )
        .unwrap();

        assert_eq!(chain.cert(0, 2).unwrap().raw(), x509::CHAIN3);
        assert_eq!(chain.chain_len(0), NonZeroUsize::new(3));

        assert!(chain.cert(0, 3).is_none());
        assert!(chain.cert(1, 0).is_none());
        assert!(chain.chain_len(2).is_none());
    }

    #[test]
    fn x509_chain_ooo() {
        let result = SimpleChain::<3>::parse(
            &[x509::CHAIN1, x509::CHAIN3, x509::CHAIN2],
            CertFormat::RiotX509,
            &mut ring::sig::Ciphers::new(),
        );
        assert!(result.is_err());

        let result = SimpleChain::<3>::parse(
            &[x509::CHAIN2, x509::CHAIN1, x509::CHAIN3],
            CertFormat::RiotX509,
            &mut ring::sig::Ciphers::new(),
        );
        assert!(result.is_err());
    }

    const CWT_TEST_CHAIN: &[TestCwt] = &[
        TestCwt {
            issuer: "Silicon Owner LLC",
            subject: "Silicon Owner LLC",
            spki: PublicKeyParams::Rsa {
                modulus: keys::KEY1_RSA_MOD,
                exponent: keys::KEY1_RSA_EXP,
            },
            key_usage: &[0b0010_0000],
            issuer_key: keys::KEY1_RSA_KEYPAIR,
        },
        TestCwt {
            issuer: "Silicon Owner LLC",
            subject: "Silicon Owner LLC Intermediate",
            spki: PublicKeyParams::Rsa {
                modulus: keys::KEY2_RSA_MOD,
                exponent: keys::KEY2_RSA_EXP,
            },
            key_usage: &[0b0010_0000],
            issuer_key: keys::KEY1_RSA_KEYPAIR,
        },
        TestCwt {
            issuer: "Silicon Owner LLC Intermediate",
            subject: "device19203134017823",
            spki: PublicKeyParams::Rsa {
                modulus: keys::KEY3_RSA_MOD,
                exponent: keys::KEY3_RSA_EXP,
            },
            key_usage: &[0b0010_0000],
            issuer_key: keys::KEY2_RSA_KEYPAIR,
        },
    ];

    #[test]
    fn cwt_chain_parse() {
        let data = CWT_TEST_CHAIN
            .iter()
            .map(TestCwt::encode)
            .collect::<Vec<_>>();
        let data = data.iter().map(Vec::as_ref).collect::<Vec<_>>();
        let chain = SimpleChain::<3>::parse(
            &data,
            CertFormat::OpenDiceCwt,
            &mut ring::sig::Ciphers::new(),
        )
        .unwrap();

        assert_eq!(chain.cert(0, 2).unwrap().raw(), data[2]);
        assert_eq!(chain.chain_len(0), NonZeroUsize::new(3));

        assert!(chain.cert(0, 3).is_none());
        assert!(chain.cert(1, 0).is_none());
        assert!(chain.chain_len(2).is_none());
    }

    #[test]
    fn cwt_chain_ooo() {
        let data = CWT_TEST_CHAIN
            .iter()
            .map(TestCwt::encode)
            .collect::<Vec<_>>();
        let mut data = data.iter().map(Vec::as_ref).collect::<Vec<_>>();
        data.swap(1, 2);
        let result = SimpleChain::<3>::parse(
            &data,
            CertFormat::OpenDiceCwt,
            &mut ring::sig::Ciphers::new(),
        );
        assert!(result.is_err());

        let data = CWT_TEST_CHAIN
            .iter()
            .map(TestCwt::encode)
            .collect::<Vec<_>>();
        let mut data = data.iter().map(Vec::as_ref).collect::<Vec<_>>();
        data.swap(0, 1);
        let result = SimpleChain::<3>::parse(
            &data,
            CertFormat::OpenDiceCwt,
            &mut ring::sig::Ciphers::new(),
        );
        assert!(result.is_err());
    }
}
