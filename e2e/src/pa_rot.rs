// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A virtual PA-RoT that can be spoken to over local TCP.

use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::BufRead as _;
use std::io::BufReader;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::str;
use std::time::Duration;
use std::time::Instant;

use manticore::cert;
use manticore::cert::CertFormat;
use manticore::crypto::ring;
use manticore::mem::Arena;
use manticore::mem::BumpArena;
use manticore::protocol;
use manticore::protocol::capabilities;
use manticore::protocol::device_id::DeviceIdentifier;
use manticore::server;
use manticore::server::pa_rot::PaRot;

use crate::tcp;
use crate::tcp::TcpHostPort;

/// Options for the PA-RoT.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Options {
    /// A firmware version blob to report to clients.
    pub firmware_version: Vec<u8>,

    /// A unique device identity blob to report to clients.
    pub unique_device_identity: Vec<u8>,

    /// The number of resets to report since power on.
    pub resets_since_power_on: u32,

    /// The maximum message size to report as a capability
    /// (unused by the transport).
    pub max_message_size: u16,
    /// The maximum packet size to report as a capability
    /// (unused by the transport).
    pub max_packet_size: u16,

    /// The timeout to report for a non-cryptographic operation
    /// (unused other than for capabilities requests).
    pub regular_timeout: Duration,
    /// The timeout to report for a cryptographic operation.
    /// (unused other than for capabilities requests)
    pub crypto_timeout: Duration,

    /// The device identifier to report to the client.
    pub device_id: DeviceIdentifier,

    /// The initial certificate chain to provision to the device.
    pub cert_chain: Vec<Vec<u8>>,

    /// The certificate format to parse the cert chain with.
    pub cert_format: CertFormat,

    /// The keypair to use with the certificate chain.
    pub alias_keypair: Option<KeyPairFormat>,

    /// The contents of PMR #0.
    pub pmr0: Vec<u8>,
}

/// See [`Options::alias_keypair`].
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum KeyPairFormat {
    /// An RSA PKCS#8-encoded key pair.
    RsaPkcs8(Vec<u8>),
}

impl Default for Options {
    fn default() -> Self {
        Self {
            firmware_version: b"<version unspecified>".to_vec(),
            unique_device_identity: b"<uid unspecified>".to_vec(),
            resets_since_power_on: 5,
            max_message_size: 1024,
            max_packet_size: 256,
            regular_timeout: Duration::from_millis(30),
            crypto_timeout: Duration::from_millis(200),
            device_id: DeviceIdentifier {
                vendor_id: 1,
                device_id: 2,
                subsys_vendor_id: 3,
                subsys_id: 4,
            },
            cert_chain: vec![],
            cert_format: CertFormat::RiotX509,
            alias_keypair: None,
            pmr0: b"<pmr0 unspecified>".to_vec(),
        }
    }
}

/// A virtual PA-RoT, implemented as a subprocess speaking TCP.
pub struct Virtual {
    child: Child,
    port: u16,
}

impl Drop for Virtual {
    fn drop(&mut self) {
        self.child.kill().unwrap();
    }
}

impl Virtual {
    /// Extracts the name of the binary-under-test from the environment.
    ///
    /// If missing, aborts the process. This will bypass the Rust test harness's
    /// attempt to continue running other tests.
    pub fn target_binary() -> &'static OsStr {
        const TARGET_BINARY: &str = "MANTICORE_E2E_TARGET_BINARY";
        lazy_static::lazy_static! {
            static ref BINARY_PATH: OsString = match env::var_os(TARGET_BINARY) {
                Some(bin) => bin,
                None => {
                    // In order to blow up the test binary, we need to call
                    // abort ourselves. Not only that, but we need to be clever
                    // to defeat the standard library's test output capture...
                    use std::os::unix::io::FromRawFd;
                    use std::io::Write;
                    use std::fs::File;
                    use std::process;

                    #[allow(unsafe_code)]
                    let mut stderr = unsafe { File::from_raw_fd(2) };
                    let _ = writeln!(
                        stderr,
                        "Could not find environment variable {}; aborting.",
                        TARGET_BINARY
                    );
                    let _ = writeln!(
                        stderr,
                        "Consider using the e2e/run.sh script, instead."
                    );
                    process::abort();
                }
            };
        }
        &BINARY_PATH
    }

    /// Spawns a virtual PA-RoT subprocess as described by `opts`.
    pub fn spawn(opts: &Options) -> Virtual {
        log::info!("spawning server: {:#?}", opts);
        let opts = serde_json::to_string(opts).unwrap();
        let mut child = Command::new(Self::target_binary())
            .args(&["--start-pa-rot-with-options", &opts])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn server subprocess");

        // Forward stderr through the eprint! macro, so that tests can capture
        // it.
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        let _ = std::thread::spawn(move || loop {
            line.clear();
            match stderr.read_line(&mut line) {
                Ok(_) => eprint!("{}", line),
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => break,
                Err(e) => panic!("unexpected error from virtual rot: {}", e),
            }
        });

        // Wait until the child signals it's ready by writing a line to stdout.
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            stdout.read_line(&mut line).unwrap();
            if line.is_empty() {
                continue;
            }

            if let Some(port) = line.trim().strip_prefix("listening@") {
                log::info!("acked child startup: {}", line);
                return Virtual {
                    child,
                    port: port.parse().unwrap(),
                };
            }
        }
    }
    /// Sends `req` to this virtal RoT, using Cerberus-over-TCP.
    ///
    /// Blocks until a response comes back.
    pub fn send_local<'a, Cmd, A>(
        &self,
        req: Cmd::Req,
        arena: &'a A,
    ) -> Result<Result<Cmd::Resp, protocol::Error>, server::Error>
    where
        Cmd: protocol::Command<'a>,
        A: Arena,
    {
        tcp::send_local::<Cmd, A>(self.port, req, arena)
    }
}

/// Starts a server loop for serving PA-RoT requests, as described by `opts`.
pub fn serve(opts: Options) -> ! {
    log::info!("configuring server...");
    let networking = capabilities::Networking {
        max_message_size: opts.max_message_size,
        max_packet_size: opts.max_packet_size,
        mode: capabilities::RotMode::Platform,
        roles: capabilities::BusRole::HOST,
    };

    let timeouts = capabilities::Timeouts {
        regular: opts.regular_timeout,
        crypto: opts.crypto_timeout,
    };

    struct Id {
        firmware_version: [u8; 32],
        unique_device_identity: Vec<u8>,
    }
    impl manticore::hardware::Identity for Id {
        fn firmware_version(&self) -> &[u8; 32] {
            &self.firmware_version
        }
        fn unique_device_identity(&self) -> &[u8] {
            &self.unique_device_identity[..]
        }
    }
    let mut identity = Id {
        firmware_version: [0; 32],
        unique_device_identity: opts.unique_device_identity,
    };
    let prefix_len = opts.firmware_version.len().min(32);

    identity.firmware_version[..prefix_len]
        .copy_from_slice(&opts.firmware_version[..prefix_len]);

    struct Reset {
        startup_time: Instant,
        resets_since_power_on: u32,
    }
    impl manticore::hardware::Reset for Reset {
        fn resets_since_power_on(&self) -> u32 {
            self.resets_since_power_on
        }

        fn uptime(&self) -> Duration {
            self.startup_time.elapsed()
        }
    }
    let reset = Reset {
        startup_time: Instant::now(),
        resets_since_power_on: opts.resets_since_power_on,
    };

    let sha = ring::sha256::Builder::new();
    let mut ciphers = ring::sig::Ciphers::new();
    let trust_chain_bytes =
        opts.cert_chain.iter().map(Vec::as_ref).collect::<Vec<_>>();
    let mut signer = opts.alias_keypair.as_ref().map(|kp| match kp {
        KeyPairFormat::RsaPkcs8(pk8) => {
            use manticore::crypto::rsa::*;
            let kp = ring::rsa::KeyPair::from_pkcs8(pk8).unwrap();
            let builder = ring::rsa::Builder::new();
            builder.new_signer(kp).unwrap()
        }
    });
    let mut trust_chain = cert::SimpleChain::<8>::parse(
        &trust_chain_bytes,
        opts.cert_format,
        &mut ciphers,
        signer.as_mut().map(|s| s as _),
    )
    .unwrap();

    let mut server = PaRot::new(manticore::server::pa_rot::Options {
        identity: &identity,
        reset: &reset,
        sha: &sha,
        ciphers: &mut ciphers,
        trust_chain: &mut trust_chain,
        pmr0: &opts.pmr0,
        device_id: opts.device_id,
        networking,
        timeouts,
    });

    let mut host = match TcpHostPort::bind() {
        Ok(host) => host,
        Err(e) => {
            log::error!("could not connect to host: {:?}", e);
            std::process::exit(1);
        }
    };
    let port = host.port();
    log::info!("bound to port {}", port);

    // Notify parent that we're listening.
    println!("listening@{}", port);

    let mut arena = BumpArena::new(vec![0; 1024]);

    log::info!("entering server loop");
    loop {
        if let Err(e) = server.process_request(&mut host, &arena) {
            log::error!("failed to process request: {:?}", e);
        }
        arena.reset();
    }
}
