// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A virtual PA-RoT that can be spoken to over local TCP.

use std::io::BufRead as _;
use std::io::BufReader;
use std::num::ParseIntError;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::str;
use std::time::Duration;
use std::time::Instant;

use structopt::StructOpt;

use manticore::crypto::ring;
use manticore::mem::Arena as _;
use manticore::mem::BumpArena;
use manticore::protocol::capabilities;
use manticore::protocol::device_id::DeviceIdentifier;
use manticore::server::pa_rot::PaRot;

use crate::tcp::TcpHostPort;

// Exists to work around structopt wanting to interpret a
// Vec field as being "multiple arguments allowed".
#[doc(hidden)]
pub type Bytes = Vec<u8>;

mod parse {
    use super::*;

    pub fn bytes(s: &str) -> Bytes {
        s.as_bytes().to_vec()
    }

    pub fn millis(s: &str) -> Result<Duration, ParseIntError> {
        Ok(Duration::from_millis(s.parse()?))
    }
}

/// Options for the PA-RoT.
#[derive(Debug, StructOpt)]
pub struct Options {
    /// Which port to listen on.
    #[structopt(short, long)]
    pub port: u16,

    /// A firmware version blob to report to clients.
    #[structopt(
        long,
        default_value = "<version unspecified>",
        parse(from_str = parse::bytes),
    )]
    pub firmware_version: Bytes,

    /// A unique device identity blob to report to clients.
    #[structopt(
        long,
        default_value = "<uid unspecified>",
        parse(from_str = parse::bytes),
    )]
    pub unique_device_identity: Bytes,

    /// The number of resets to report since power on.
    #[structopt(long, default_value = "0")]
    pub resets_since_power_on: u32,

    /// The maximum message size to report as a capability
    /// (unused by the transport)
    #[structopt(long, default_value = "1024")]
    pub max_message_size: u16,
    /// The maximum packet size to report as a capability
    /// (unused by the transport)
    #[structopt(long, default_value = "256")]
    pub max_packet_size: u16,

    /// The timeout to report for a non-cryptographic operation in milliseconds
    /// (unused other than for capabilities requests)
    #[structopt(
        long,
        default_value = "30",
        parse(try_from_str = parse::millis),
    )]
    pub regular_timeout: Duration,
    /// The timeout to report for a cryptographic operation in milliseconds
    /// (unused other than for capabilities requests)
    #[structopt(
        long,
        default_value = "200",
        parse(try_from_str = parse::millis),
    )]
    pub crypto_timeout: Duration,

    /// The device identifier to report to the client
    #[structopt(
        long,
        default_value = r#"{"vendor_id":1,"device_id":2,"subsys_vendor_id":3,"subsys_id":4}"#,
        parse(try_from_str = serde_json::from_str),
    )]
    pub device_id: DeviceIdentifier,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            port: 9999,
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
        }
    }
}

impl Options {
    /// Convert this `Options` into command-line arguments. This is intended
    /// for simplifying an exec-into-self workflow.
    pub fn unparse(&self) -> Vec<String> {
        vec![
            format!("serve"),
            format!("--port={}", self.port),
            // TODO: Come up with a non-panicking option.
            format!(
                "--firmware-version={}",
                str::from_utf8(self.firmware_version.as_ref()).unwrap()
            ),
            format!(
                "--unique-device-identity={}",
                str::from_utf8(self.unique_device_identity.as_ref()).unwrap()
            ),
            format!("--resets-since-power-on={}", self.resets_since_power_on),
            format!("--max-message-size={}", self.max_message_size),
            format!("--max-packet-size={}", self.max_packet_size),
            format!("--regular-timeout={}", self.regular_timeout.as_millis()),
            format!("--crypto-timeout={}", self.crypto_timeout.as_millis()),
            format!(
                "--device-id={}",
                serde_json::to_string(&self.device_id).unwrap()
            ),
        ]
    }
}
/// Spawns a virtual PA-RoT subprocess as described by `opts`.
pub fn spawn(opts: &Options) -> Child {
    log::info!("spawning server: {:#?}", opts);
    // Get argv[0]. We assume this is the path to the executable.
    let exe = std::env::args_os().next().unwrap();
    let args = opts.unparse();
    let mut child = Command::new(exe)
        .args(&args)
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn server subprocess");
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();

    // Wait until the child signals it's ready by writing a line to stdout.
    while line.is_empty() {
        stdout.read_line(&mut line).unwrap();
    }
    log::info!("acked child startup: {}", line);
    return child;
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
        unique_device_identity: Bytes,
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

    let rsa = ring::rsa::Builder::new();

    let mut server = PaRot::new(manticore::server::pa_rot::Options {
        identity: &identity,
        reset: &reset,
        rsa: &rsa,
        device_id: opts.device_id,
        networking,
        timeouts,
    });

    log::info!("binding to 127.0.0.1:{}", opts.port);
    let mut host = match TcpHostPort::bind(opts.port) {
        Ok(host) => host,
        Err(e) => {
            log::error!("could not connect to host: {:?}", e);
            std::process::exit(1);
        }
    };

    // Notify parent that we're listening on the requested port.
    println!("listening!");

    let mut arena = vec![0; 64];
    let mut arena = BumpArena::new(&mut arena);

    log::info!("entering server loop");
    loop {
        if let Err(e) = server.process_request(&mut host, &arena) {
            log::error!("failed to process request: {:?}", e);
        }
        arena.reset();
    }
}
