// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Manifest manipulation commands.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use manticore::crypto::hash;
use manticore::crypto::ring;
use manticore::io::ReadInt as _;
use manticore::manifest::owned;
use manticore::manifest::ManifestType;
use manticore::protocol::wire::WireEnum;

/// A CLI interface for Manticore's parser infrastructure.
#[derive(structopt::StructOpt)]
#[structopt(author)]
pub enum Manifest {
    /// Create a new signed manifest.
    SignManifest {
        /// PKCS#8-encoded RSA signing key to sign with.
        // TODO: Support other key types.
        #[structopt(long, parse(from_os_str))]
        key: PathBuf,

        /// The manifest type for this operation.
        #[structopt(long)]
        manifest: ManifestType,

        /// Input file, defaults to stdin.
        #[structopt(short = "i", long, parse(from_os_str))]
        input: Option<PathBuf>,

        /// Output file, defaults to stdout.
        #[structopt(short = "o", long, parse(from_os_str))]
        output: Option<PathBuf>,
    },

    /// Inspect an existing manifest.
    ShowManifest {
        /// PKCS#8-encoded RSA public key to optionally verify the signature.
        // TODO: Support other key types.
        #[structopt(long, parse(from_os_str))]
        key: Option<PathBuf>,

        /// Whether to pretty-print the resulting JSON.
        #[structopt(long)]
        pretty: bool,

        /// Input file, defaults to stdin.
        #[structopt(short = "i", long, parse(from_os_str))]
        input: Option<PathBuf>,

        /// Output file, defaults to stdout.
        #[structopt(short = "o", long, parse(from_os_str))]
        output: Option<PathBuf>,
    },
}

impl Manifest {
    pub fn run(self) {
        match self {
            Self::SignManifest {
                key,
                manifest,
                input,
                output,
            } => {
                let (mut r, mut w) =
                    crate::util::stdio(input.as_deref(), output.as_deref());

                let key = check!(fs::read(key), "failed to open file");
                let mut signer = check!(
                    ring::rsa::Sign256::from_pkcs8(&key),
                    "failed to parse key"
                );
                let mut hasher = ring::hash::Engine::new();

                let mut read_buf = Vec::new();
                check!(r.read_to_end(&mut read_buf), "failed to read file");
                let manifest = match manifest {
                    ManifestType::Pfm => {
                        let pfm: owned::Pfm = check!(
                            serde_json::from_slice(&read_buf),
                            "failed to parse PFM"
                        );
                        check!(
                            pfm.sign(
                                0x00,
                                hash::Algo::Sha256,
                                &mut hasher,
                                &mut signer
                            ),
                            "failed to sign PFM"
                        )
                    }
                };

                check!(w.write_all(&manifest), "failed to write manifest");
            }

            Self::ShowManifest {
                key,
                pretty,
                input,
                output,
            } => {
                let (mut r, w) =
                    crate::util::stdio(input.as_deref(), output.as_deref());

                let mut engine = key.map(|key| {
                    let key = check!(fs::read(key), "failed to open file");
                    let signer = check!(
                        ring::rsa::Sign256::from_pkcs8(&key),
                        "failed to parse key",
                    );
                    signer.verifier()
                });
                let mut hasher = ring::hash::Engine::new();

                let mut read_buf = Vec::new();
                check!(
                    r.read_to_end(&mut read_buf),
                    "failed to read file to end"
                );

                let mut r = read_buf.as_slice();
                let _ = check!(r.read_le::<u16>(), "input len < 4");
                let manifest_type = check!(r.read_le::<u16>(), "input len < 4");

                match ManifestType::from_wire_value(manifest_type) {
                    Some(ManifestType::Pfm) => {
                        let parse = check!(
                            owned::Pfm::parse(
                                &read_buf,
                                &mut hasher,
                                engine.as_mut()
                            ),
                            "failed to parse PFM"
                        );

                        if parse.bad_signature {
                            eprintln!("warning: signature verification failed");
                        }
                        if parse.bad_toc_hash {
                            eprintln!("warning: TOC hash verification failed");
                        }
                        for idx in parse.bad_hashes {
                            eprintln!(
                                "warning: bad hash for toc entry {}",
                                idx
                            );
                        }

                        let r = match pretty {
                            true => serde_json::to_writer_pretty(
                                w,
                                &parse.container,
                            ),
                            false => serde_json::to_writer(w, &parse.container),
                        };
                        check!(r, "failed to serialize PFM");
                    }
                    None => {
                        check!(
                            Err(format!(
                                "unknown manifest type: 0x{:04x}",
                                manifest_type
                            )),
                            "failed to parse manifest"
                        )
                    }
                }
            }
        }
    }
}
