// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `manticore-tool` is a simple command-line tool for manipulating Manticore
//! data types.

#![deny(missing_docs)]
#![deny(warnings)]
#![deny(unused)]
#![deny(unsafe_code)]

use structopt::StructOpt as _;

#[macro_use]
mod util;

mod manifest;
mod message;

/// A command-line tool for working with Manticore data.
#[allow(missing_docs)]
#[derive(structopt::StructOpt)]
#[structopt(author)]
enum CliCommand {
    #[structopt(flatten)]
    Message(message::Message),
    #[structopt(flatten)]
    Manifest(manifest::Manifest),
}

fn main() {
    match CliCommand::from_args() {
        CliCommand::Message(m) => m.run(),
        CliCommand::Manifest(m) => m.run(),
    }
}
