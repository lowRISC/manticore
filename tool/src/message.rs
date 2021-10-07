// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for serializing and deserializing Cerberus protocol messages.

use std::any::type_name;
use std::io::Read;
use std::path::PathBuf;

use serde::de::Deserialize;

use manticore::io::write::StdWrite;
use manticore::mem::BumpArena;
use manticore::protocol;
use manticore::protocol::wire::FromWire;
use manticore::protocol::wire::ToWire;
use manticore::protocol::Command;
use manticore::protocol::CommandType;

macro_rules! proto_match {
    (($cmd:expr, $is_req:expr) in |$mty:ident: type| $expr:expr) => {
        proto_match!(($cmd, $is_req, $mty, $expr) in {
            protocol::DeviceId,
            protocol::DeviceInfo,
            protocol::DeviceUptime,
            protocol::DeviceCapabilities,
            protocol::FirmwareVersion,
            protocol::GetDigests,
            protocol::GetCert,
            protocol::GetHostState,
            protocol::Challenge,
            protocol::KeyExchange,
            protocol::ResetCounter,
            protocol::RequestCounter,
        })
    };
    (($cmd:expr, $is_req:expr, $mty:ident, $expr:expr) in {$($t:ty,)*}) => {
        match ($cmd, $is_req) {
            $(
                (<<$t as Command<'static>>::Req as protocol::Request<'static>>::TYPE, true) => {
                    type $mty = <$t as Command<'static>>::Req;
                    $expr
                }
                (<<$t as Command<'static>>::Resp as protocol::Response<'static>>::TYPE, false) => {
                    type $mty = <$t as Command<'static>>::Resp;
                    $expr
                }
            )*
            _ => todo!(),
        }
    };
}

/// Construct a Cerberus message from a JSON representation.
#[derive(structopt::StructOpt)]
pub enum Message {
    /// Converts a Cerberus message from wire form to JSON form.
    #[structopt(name = "wire2json", alias = "w2j")]
    Wire2Json {
        /// The command type for the message.
        #[structopt(short = "c", long)]
        command: CommandType,

        /// Parse a request for this command.
        #[structopt(
            long,
            conflicts_with = "respose",
            required_unless = "response"
        )]
        request: bool,

        /// Parse a response for this command.
        #[structopt(
            long,
            conflicts_with = "request",
            required_unless = "request"
        )]
        response: bool,

        /// Whether to pretty-print JSON output.
        #[structopt(long)]
        pretty: bool,

        /// Input file; defaults to stdin.
        #[structopt(short = "i", long, parse(from_os_str))]
        input: Option<PathBuf>,

        /// Output file; defaults to stdout.
        #[structopt(short = "o", long, parse(from_os_str))]
        output: Option<PathBuf>,
    },

    /// Converts a Cerberus message from JSON form to wire form.
    #[structopt(name = "json2wire", alias = "j2w")]
    Json2Wire {
        /// The command type for the message.
        #[structopt(short = "c", long)]
        command: CommandType,

        /// Parse a request for this command.
        #[structopt(
            long,
            conflicts_with = "respose",
            required_unless = "response"
        )]
        request: bool,

        /// Parse a response for this command.
        #[structopt(
            long,
            conflicts_with = "request",
            required_unless = "request"
        )]
        response: bool,

        /// Whether to pretty-print JSON output.
        #[structopt(long)]
        pretty: bool,

        /// Input file; defaults to stdin.
        #[structopt(short = "i", long, parse(from_os_str))]
        input: Option<PathBuf>,

        /// Output file; defaults to stdout.
        #[structopt(short = "o", long, parse(from_os_str))]
        output: Option<PathBuf>,
    },
}

impl Message {
    pub fn run(self) {
        match self {
            Self::Json2Wire {
                command,
                request,
                input,
                output,
                ..
            } => {
                let (r, w) = crate::util::stdio(input, output);
                let mut w = StdWrite(w);

                proto_match!((command, request) in |Msg: type| {
                    let mut de = serde_json::Deserializer::from_reader(r);
                    let msg = check!(
                        Msg::deserialize(&mut de),
                        "failed to deserialize {} from JSON",
                        type_name::<Msg>(),
                    );
                    check!(
                        msg.to_wire(&mut w),
                        "failed to serialize {}",
                        type_name::<Msg>(),
                    );
                })
            }
            Self::Wire2Json {
                command,
                request,
                pretty,
                input,
                output,
                ..
            } => {
                let (mut r, w) = crate::util::stdio(input, output);

                let mut read_buf = Vec::new();
                check!(
                    r.read_to_end(&mut read_buf),
                    "failed to read input to end",
                );
                let mut r = read_buf.as_slice();

                let arena = BumpArena::new(vec![0u8; 1024]);
                proto_match!((command, request) in |Msg: type| {
                    let msg = check!(
                        Msg::from_wire(&mut r, &arena),
                        "failed to deserialize {}",
                        type_name::<Msg>(),
                    );
                    let r = match pretty {
                        true => serde_json::to_writer_pretty(w, &msg),
                        false => serde_json::to_writer(w, &msg),
                    };
                    check!(r, "failed to serialize {} as JSON", type_name::<Msg>());
                })
            }
        }
    }
}
