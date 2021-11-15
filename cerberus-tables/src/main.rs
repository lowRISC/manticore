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
    /// One of raw-ast, tables, tables-and-prose, or rust.
    #[structopt(long, short)]
    mode: Mode,

    /// The maximum width, in characters, that table output
    /// may have.
    #[structopt(long, short = "w")]
    max_width: Option<usize>,

    /// A Markdown file to parse tables from.
    input: PathBuf,
}

#[derive(Debug)]
enum Mode {
    RawAst,
    Tables,
    TablesAndProse,
    Rust,
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw-ast" => Ok(Self::RawAst),
            "tables" => Ok(Self::Tables),
            "tables-and-prose" => Ok(Self::TablesAndProse),
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
    for error in &errors {
        println!("{:?}", error);
        for (num, line) in error.span.lines() {
            println!("{:4}> {}", num, line);
        }
    }
    if !errors.is_empty() {
        std::process::exit(2);
    }

    match opts.mode {
        Mode::RawAst => {
            for table in ast {
                println!("{:#?}", table);
            }
        }
        Mode::Tables => {
            for table in ast {
                println!(
                    "{}",
                    ast::TableWithOptions {
                        table: &table,
                        max_width: opts.max_width,
                    }
                );
            }
        }
        Mode::TablesAndProse => {
            let mut prev = 0;
            for table in ast {
                let (start, end) = table.span.byte_range();
                print!("{}", &src.text[prev..start]);
                print!(
                    "{}",
                    ast::TableWithOptions {
                        table: &table,
                        max_width: opts.max_width,
                    }
                );
                prev = end;
            }
            print!("{}", &src.text[prev..]);
        }
        _ => unimplemented!(),
    }
}
