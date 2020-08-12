// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `manticore-tool` is a simple command-line tool for manipulating Manticore
//! data types.

#![deny(missing_docs)]
#![deny(warnings)]
#![deny(unused)]
#![deny(unsafe_code)]

use manticore::io::write::StdWrite;
use manticore::mem::BumpArena;
use manticore::protocol::firmware_version;
use manticore::protocol::wire::FromWire;
use manticore::protocol::wire::ToWire;
use manticore::protocol::CommandType;
use manticore::protocol::Header;

use serde::de::Deserialize;

use structopt::StructOpt;

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

/// Opens the given input and output files.
///
/// If either file is missing, it is replaced with stdin or stdout, respectively.
fn open_files(
    input_file: Option<PathBuf>,
    output_file: Option<PathBuf>,
) -> (Box<dyn Read>, Box<dyn Write>) {
    let input: Box<dyn Read> = match input_file {
        Some(path) => {
            let file = File::open(path).expect("failed to open input file");
            Box::new(BufReader::new(file))
        }
        None => Box::new(io::stdin()),
    };

    let output: Box<dyn Write> = match output_file {
        Some(path) => {
            let file = File::create(path).expect("failed to open output file");
            Box::new(file)
        }
        None => Box::new(io::stdout()),
    };

    (input, output)
}

/// Deserializes a message in JSON format from `reader` and then serializes the
/// message in wire format to `writer`.
fn from_json_to_wire<'de, T, R, W>(reader: R, writer: W)
where
    T: ToWire + Deserialize<'de>,
    R: Read,
    W: manticore::io::Write,
{
    let mut de = serde_json::Deserializer::from_reader(reader);
    let msg = T::deserialize(&mut de).expect("failed to deserialize JSON");
    msg.to_wire(writer).expect("failed to write request");
}

/// Converts a JSON object into a Manticore command.
///
/// This function deserializes a message in JSON format from `input_file` and
/// then serializes a header + message in wire format to.`output_file`.
///
/// Uses `cmd_type` and `is_request` to determine the message type since the
/// JSON format does not include the message header.
fn from_json(
    cmd_type: CommandType,
    is_request: bool,
    input: impl Read,
    mut output: impl Write,
) {
    let mut stdwrite = StdWrite(&mut output);

    Header {
        is_request: is_request,
        command: cmd_type,
    }
    .to_wire(&mut stdwrite)
    .expect("failed to write header");

    match (is_request, cmd_type) {
        (true, CommandType::FirmwareVersion) => {
            from_json_to_wire::<firmware_version::FirmwareVersionRequest, _, _>(
                input, stdwrite,
            )
        }
        (false, CommandType::FirmwareVersion) => {
            from_json_to_wire::<firmware_version::FirmwareVersionResponse, _, _>(
                input, stdwrite,
            )
        }
        _ => panic!("Unsupported message type"),
    }
}

/// Macro to deserialize wire format from an input file and then run an
/// operation on the deserialized message.
///
/// This macro is a temporary workaround some Serde limiatations.
///
/// Arguments:
/// * `input_file`: Identifier to get the input file name from.
/// * `body`: A "generic" closure to run with the results of the parse.
macro_rules! read_wire_and_operate {
    ($input:ident, $body:expr) => {
        let mut input = $input;
        let mut read_buf = Vec::new();
        input
            .read_to_end(&mut read_buf)
            .expect("couldn't read from file");

        let mut arena = vec![0u8; 1024];
        let arena = BumpArena::new(&mut arena);

        let mut read_buf_slice = read_buf.as_slice();
        let header = Header::from_wire(&mut read_buf_slice, &arena)
            .expect("failed to read header");
        match (header.is_request, header.command) {
            (true, CommandType::FirmwareVersion) => {
                let message =
                    firmware_version::FirmwareVersionRequest::from_wire(
                        &mut read_buf_slice,
                        &arena,
                    )
                    .expect("failed to read response");
                let body = $body;
                body(message)
            }
            (false, CommandType::FirmwareVersion) => {
                let message =
                    firmware_version::FirmwareVersionResponse::from_wire(
                        &mut read_buf_slice,
                        &arena,
                    )
                    .expect("failed to read response");
                let body = $body;
                body(message)
            }
            _ => panic!("unsupported response type {:?}", header.command),
        }
    };
}

/// Converts a Manticore command into a JSON object.
///
/// This funciton deserializes a header + message in wire format from `input`
/// and then serialize the message as JSON to `output`.
fn to_json(pretty: bool, input: impl Read, output: impl Write) {
    read_wire_and_operate!(input, |msg| {
        if pretty {
            serde_json::to_writer_pretty(output, &msg)
        } else {
            serde_json::to_writer(output, &msg)
        }
        .expect("failed to serialize to JSON")
    });
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "manticore-tool",
    author = "lowRISC contributors",
    about = "Command-line tool for working with Manticore data"
)]
enum CliCommand {
    FromJson {
        /// The command type for the message.
        #[structopt(short = "t", long)]
        cmd_type: CommandType,

        /// Whether this message is a request.
        #[structopt(short = "r", long)]
        is_request: bool,

        /// JSON file containing containing the message; defaults to stdin.
        #[structopt(short = "i", long, parse(from_os_str))]
        input: Option<PathBuf>,

        /// Binary output file; defaults to stdout.
        #[structopt(short = "o", long, parse(from_os_str))]
        output: Option<PathBuf>,
    },
    ToJson {
        /// Whether to pretty-print the resulting JSON.
        #[structopt(short = "p", long)]
        pretty: bool,

        /// Binary file containing containing the message; defaults to stdin.
        #[structopt(short = "i", long, parse(from_os_str))]
        input: Option<PathBuf>,

        /// JSON output file; defaults to stdout.
        #[structopt(short = "o", long, parse(from_os_str))]
        output: Option<PathBuf>,
    },
}

fn main() {
    match CliCommand::from_args() {
        CliCommand::FromJson {
            cmd_type,
            is_request,
            input,
            output,
        } => {
            let (input, output) = open_files(input, output);
            from_json(cmd_type, is_request, input, output);
        }
        CliCommand::ToJson {
            pretty,
            input,
            output,
        } => {
            let (input, output) = open_files(input, output);
            to_json(pretty, input, output);
        }
    }
}
