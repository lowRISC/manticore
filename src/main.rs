// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use clap::value_t;
use clap::App;
use clap::AppSettings;
use clap::Arg;
use clap::SubCommand;

use manticore::io::StdWrite;
use manticore::mem::BumpArena;
use manticore::protocol;
use manticore::protocol::firmware_version;
use manticore::protocol::wire::FromWire;
use manticore::protocol::wire::ToWire;
use manticore::protocol::CommandType;
use manticore::protocol::Header;

use serde::de::Deserialize;

use serde_json;

use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::Read as _;

/// Deserializes a message in JSON format from `reader` and then serializes the message in wire
/// format to `writer`.
fn from_json_to_wire<'de, T, R, W>(reader: R, writer: W)
where
    T: ToWire + Deserialize<'de>,
    R: std::io::Read,
    W: manticore::io::Write,
{
    let mut de = serde_json::Deserializer::from_reader(reader);
    let msg = T::deserialize(&mut de).expect("failed to deserialize JSON");
    msg.to_wire(writer).expect("failed to write request");
}

/// Deserializes a message in JSON format from `input_file` and then serializes a header + message
/// in wire format to.`output_file`. Uses `cmd_type` and `is_request` to determine the message type
///  since the JSON format does not include the message header.
fn from_json(
    cmd_type: CommandType,
    is_request: bool,
    input_file: &str,
    output_file: &str,
) {
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&output_file)
        .expect("failed to open output file");

    let input = OpenOptions::new()
        .read(true)
        .open(&input_file)
        .expect("failed to open input file");
    let input_reader = BufReader::new(input);

    let mut stdwrite = StdWrite(&mut output);

    let header = Header {
        is_request: is_request,
        command: cmd_type,
    };
    header
        .to_wire(&mut stdwrite)
        .expect("failed to write header");

    match (is_request, cmd_type) {
        (true, CommandType::FirmwareVersion) => {
            from_json_to_wire::<firmware_version::FirmwareVersionRequest, _, _>(
                input_reader,
                stdwrite,
            )
        }
        (false, CommandType::FirmwareVersion) => {
            from_json_to_wire::<firmware_version::FirmwareVersionResponse, _, _>(
                input_reader,
                stdwrite,
            )
        }
        _ => panic!("Unsupported message type"),
    }
}

/// Macro to deserialize wire format from an input file and then run an operation on the
/// deserialized message.
/// Arguments:
/// * `input_file`: Identifier to get the input file name from.
/// * `msg`: Identifier to hold the message to operator.
/// * `op`: Expression to execute after deserializing `msg` from `input_file`.
macro_rules! read_wire_and_operate {
    ($input_file:ident, $msg:ident, $op:expr) => {
        let mut input = OpenOptions::new()
            .read(true)
            .open(&$input_file)
            .expect("failed to open input file");

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
                let $msg: protocol::firmware_version::FirmwareVersionRequest =
                    FromWire::from_wire(&mut read_buf_slice, &arena)
                        .expect("failed to read request");

                $op
            }
            (false, CommandType::FirmwareVersion) => {
                let $msg: protocol::firmware_version::FirmwareVersionResponse =
                    FromWire::from_wire(&mut read_buf_slice, &arena)
                        .expect("failed to read response");

                $op
            }
            _ => {
                panic!("unsupported response type {:?}", header.command);
            }
        }
    };
}

/// Deserializes a header + message in wire format from `input_file` and then serialize the
/// message as JSON to `output_file`.
fn to_json(input_file: &str, output_file: &str) {
    let output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(&output_file)
        .expect("failed to open output file");
    read_wire_and_operate!(input_file, msg, {
        serde_json::to_writer(output, &msg)
            .expect("failed to serialize to JSON")
    });
}

/// Deserializes a header + message in wire format from `input_file` and then prints the message
/// to the console.
fn print_message(input_file: &str) {
    read_wire_and_operate!(input_file, msg, eprintln!("{:?}", msg));
}

fn main() {
    let app = App::new("Manticore Tool")
        .version("0.1")
        .author("lowRISC contributors")
        .about("Command line tool for Manticore library")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommand(
            SubCommand::with_name("fromjson")
                .about("Generate a message from JSON and serialize it")
                .arg(
                    Arg::with_name("cmdtype")
                        .short("t")
                        .long("cmdtype")
                        .help("Command type")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("isrequest")
                        .short("r")
                        .long("isrequest")
                        .help("Whether the message is a request"),
                )
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .long("input")
                        .help("JSON input file with message data")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .help("output file for serialized message")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("tojson")
                .about("Deserialize a message and store it as JSON")
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .long("input")
                        .help("input file containing serialized message")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .help("output file for message data as JSON")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("print")
                .about("Deserialize and print a message")
                .arg(
                    Arg::with_name("input")
                        .short("i")
                        .long("input")
                        .help("input file containing serialized message")
                        .required(true)
                        .takes_value(true),
                ),
        );
    let matches = app.get_matches();

    if let Some(matches) = matches.subcommand_matches("fromjson") {
        from_json(
            value_t!(matches.value_of("cmdtype"), CommandType)
                .unwrap_or_else(|e| e.exit()),
            matches.is_present("isrequest"),
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
        );
    } else if let Some(matches) = matches.subcommand_matches("tojson") {
        to_json(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
        );
    } else if let Some(matches) = matches.subcommand_matches("print") {
        print_message(matches.value_of("input").unwrap());
    }
}
