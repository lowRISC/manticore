// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A parser for Cerberus protocol tables.

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use structopt::StructOpt;

mod ast;

#[derive(Debug, StructOpt)]
struct Options {
    /// The output format; one of raw-ast, tables, in-place, or rust.
    #[structopt(long, short)]
    output: Output,

    /// A Markdown file to parse tables from.
    input: PathBuf,
}

#[derive(Debug)]
enum Output {
    RawAst,
    Tables,
    InPlace,
    Rust,
}

impl FromStr for Output {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw-ast" => Ok(Self::RawAst),
            "tables" => Ok(Self::Tables),
            "in-place" => Ok(Self::InPlace),
            "rust" => Ok(Self::Rust),
            _ => Err(format!("unknown format: {}", s)),
        }
    }
}

fn main() {
    let opts = Options::from_args();
    let text = fs::read_to_string(&opts.input).unwrap();
    let src = ast::MarkdownFile {
        file_name: opts.input,
        text,
    };

    let (ast, errors) = src.parse_tables();
    for error in errors {
        println!("{:?}", error);
        for (num, line) in error.span.lines() {
            println!("{:4}> {}", num, line);
        }
    }
    println!("{:#?}", ast);
}
