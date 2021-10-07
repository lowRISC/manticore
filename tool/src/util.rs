// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! I/O utilities.

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::Path;

/// Like `?`, but crashes the binary with a nice error message.
macro_rules! check {
    ($result:expr, $fmt:literal $(, $args:expr)* $(,)?) => {
        match $result {
            Ok(x) => x,
            Err(e) => {
                eprintln!("error: {}: {:?}", format_args!($fmt, $($args,)*), e);
                std::process::exit(2)
            }
        }
    }
}

/// Opens the given input and output files.
///
/// If either file is missing, it is replaced with stdin or stdout, respectively.
pub fn stdio(
    input_file: Option<impl AsRef<Path>>,
    output_file: Option<impl AsRef<Path>>,
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
