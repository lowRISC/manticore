// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A `manticore` server that can be spoken to over local TCP.

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

#[derive(Debug, StructOpt)]
pub struct Options {
    #[structopt(short, long)]
    pub port: u16,
    #[structopt(
        long,
        default_value = "<version unspecified>",
        parse(from_str = parse::bytes),
    )]
    pub firmware_version: Bytes,
    #[structopt(
        long,
        default_value = "<uid unspecified>",
        parse(from_str = parse::bytes),
    )]
    pub unique_device_identity: Bytes,
    #[structopt(long, default_value = "0")]
    pub resets_since_power_on: u32,

    #[structopt(long, default_value = "1024")]
    pub max_message_size: u16,
    #[structopt(long, default_value = "256")]
    pub max_packet_size: u16,

    #[structopt(
        long,
        default_value = "30",
        parse(try_from_str = parse::millis),
    )]
    pub regular_timeout: Duration,
    #[structopt(
        long,
        default_value = "200",
        parse(try_from_str = parse::millis),
    )]
    pub crypto_timeout: Duration,

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

    /// Spawns a subprocess that serves a PA-RoT describes by this `Options`.
    pub fn self_exec(&self) -> Child {
        // Get argv[0]. We assume this is the path to the executable.
        let exe = std::env::args_os().next().unwrap();
        let args = self.unparse();
        let mut child = Command::new(exe)
            .args(&args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn server subprocess");
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();

        // Wait until the child signals it's ready by writing a line to stdout.
        stdout.read_line(&mut line).unwrap();
        print!("{}", line);
        child
    }
}

pub fn serve(opts: Options) -> ! {
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

    let mut ciphers = ring::sig::Ciphers::new();

    let mut server = PaRot::new(manticore::server::pa_rot::Options {
        identity: &identity,
        reset: &reset,
        ciphers: &mut ciphers,
        device_id: opts.device_id,
        networking,
        timeouts,
    });

    let mut host = TcpHostPort::bind(opts.port).unwrap();
    println!("listening at localhost:{}", opts.port);

    let mut arena = vec![0; 64];
    let mut arena = BumpArena::new(&mut arena);

    loop {
        // TODO: handle this gracefully instead of crashing on a bad packet.
        server.process_request(&mut host, &arena).unwrap();
        arena.reset();
    }
}
