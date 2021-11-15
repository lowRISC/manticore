// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Parsing and AST for Cerberus Tables.
//!
//! See [`MarkdownFile::parse_tables()`].

use std::fmt;
use std::path::PathBuf;

mod parser;

/// A Markdown file taken as parsing input.
#[derive(Clone)]
pub struct MarkdownFile {
    /// The name of the file, for error-reporting purposes.
    pub file_name: PathBuf,
    /// The entire text of the file.
    pub text: String,
}

impl MarkdownFile {
    /// Parses a specification from the given [`MarkdownFile`], returning
    /// an array of tables.
    pub fn parse_tables(&self) -> (Vec<Table>, Vec<Error>) {
        let mut ctx = parser::Context::new(self);
        let mut tables = Vec::new();
        let mut errors = Vec::new();
        while ctx.peek().is_some() {
            match Table::parse(&mut ctx) {
                Ok(Some(t)) => tables.push(t),
                Ok(None) => { /* This wasn't a table! */ }
                Err(e) => errors.push(e),
            }

            // Skip forward until the end of the current line.
            let mut seen_newline = false;
            ctx.skip(|_, c| {
                if c == '\n' {
                    seen_newline = true;
                }
                seen_newline == (c == '\n')
            });
        }
        (tables, errors)
    }
}

impl fmt::Debug for MarkdownFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MarkdownFile({})", self.file_name.display())
    }
}

/// A span of code inside of a [`MarkdownFile`].
#[derive(Copy, Clone)]
pub struct Span<'md> {
    src: &'md MarkdownFile,
    range: (parser::Cursor, parser::Cursor),
}

impl<'md> Span<'md> {
    /// Returns the wrapped [`MarkdownFile`].
    pub fn src(self) -> &'md MarkdownFile {
        self.src
    }

    /// Returns the textual content of this span.
    pub fn text(self) -> &'md str {
        &self.src().text[self.range.0.byte..self.range.1.byte]
    }

    /// Returns an iterator over the lines spanned by this span.
    pub fn lines(self) -> impl Iterator<Item = (usize, &'md str)> {
        let start_line = self.range.0.line - 1;
        let end_line = self.range.0.line;
        self.src()
            .text
            .lines()
            .enumerate()
            .skip(start_line)
            .take(end_line - start_line)
    }

    /// Creates an error wrapping this span.
    fn error(self, error: ErrorKind) -> Error<'md> {
        Error {
            kind: error,
            span: self,
        }
    }
}

impl fmt::Debug for Span<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Span({}:{}:{}, {}..{})",
            self.src.file_name.display(),
            self.range.0.line,
            self.range.0.col,
            self.range.0.byte,
            self.range.1.byte
        )
    }
}

/// A single identifier, i.e. `[a-zA-Z_][0-9a-zA-Z]*`.
#[derive(Copy, Clone)]
pub struct Ident<'md>(Span<'md>);

impl<'md> Ident<'md> {
    /// Returns the wrapped [`MarkdownFile`].
    pub fn span(self) -> Span<'md> {
        self.0
    }

    /// Returns the textual content of this span.
    pub fn name(self) -> &'md str {
        self.0.text()
    }

    fn as_bits_type(self) -> Option<u64> {
        if !self.name().starts_with("b")
            || !self.name().chars().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        Some(self.name().parse::<u64>().unwrap())
    }
}

impl fmt::Debug for Ident<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} @ {}..{}",
            self.name(),
            self.span().range.0.byte,
            self.span().range.1.byte
        )
    }
}

/// A path, i.e., a sequence of dot-separated identifiers.
#[derive(Clone, Debug)]
pub struct Path<'md> {
    /// The path's components.
    pub components: Vec<Ident<'md>>,
    /// This path but in canonicalized form.
    ///
    /// Not present until after canonicalization.
    pub canonicalized: Option<Vec<&'md str>>,
    /// The node's span.
    pub span: Span<'md>,
}

/// An integer literal, in decimal, hex, or binary.
#[derive(Copy, Clone, Debug)]
pub struct Lit<'md> {
    /// The width of this literal, in bits.
    ///
    /// This includes any leading zeroes for binary or hex literals.
    ///
    /// Not present for decimal literals.
    pub bit_width: Option<usize>,
    /// The value of this literal.
    pub value: u64,
    /// The base the integer was in.
    pub base: Base,
    /// The node's span.
    pub span: Span<'md>,
}

/// An integer base: decimal, binary, or hexadecimal.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Base {
    Bin,
    Dec,
    Hex,
}

/// A type, such as raw bits or an array.
#[derive(Clone, Debug)]
pub struct Type<'md> {
    /// The kind of type this is.
    pub kind: TypeKind<'md>,
    /// The node's span.
    pub span: Span<'md>,
}

/// A [`Type`] kind.
#[derive(Clone, Debug)]
pub enum TypeKind<'md> {
    /// A raw bit string of fixed length.
    ///
    /// E.g. `b1`, `b8`, or `b256`.
    Bits(u64),

    /// A literal value.
    ///
    /// E.g. `0xabcd`.
    Lit(Lit<'md>),

    /// A reference to some other table by path.
    ///
    /// E.g. `Foo.Bar.Baz`.
    Path(Path<'md>),

    /// An enum mapping.
    ///
    /// E.g. `HashLength(hash_type)`.
    Mapping {
        /// A reference to the enum mapping table.
        mapping: Path<'md>,
        /// The mapped field.
        field: Ident<'md>,
    },

    /// An array of fixed extent.
    ///
    /// E.g. `Foo[6]`.
    FixedArray {
        /// The component type of this array.
        ty: Option<Box<Type<'md>>>,
        /// The fixed extent.
        extent: Lit<'md>,
    },

    /// An array of variable extent.
    ///
    /// E.g. `Foo[some_length]`.
    VariableArray {
        /// The component type of this array.
        ty: Option<Box<Type<'md>>>,
        /// The name of the field defining the extent.
        extent_field: Ident<'md>,
    },

    /// An array with a length prefix.
    PrefixedArray {
        /// The component type of this array.
        ty: Option<Box<Type<'md>>>,
        /// The bit-width of the length prefix.
        extent_bits: u64,
    },

    /// An array of indefinite length.
    IndefiniteArray {
        /// The component type of this array.
        ty: Option<Box<Type<'md>>>,
    },

    /// An aligned type.
    Aligned {
        /// The type being aligned.
        ty: Option<Box<Type<'md>>>,
        /// The number of bytes to align to.
        alignment: Lit<'md>,
    },
}

/// A row of a [`Table`] with values of type `Type`.
#[derive(Clone, Debug)]
pub struct TableRow<'md, Type> {
    /// The value in the first column.
    pub value: Type,
    /// The name in the second column.
    pub name: Ident<'md>,
    /// The optional description in the third column.
    pub desc: Option<Span<'md>>,
    /// This node's span.
    pub span: Span<'md>,
}

/// A table defining a message or enum.
///
/// This is a Markdown table prefixed with a line starting with wither
/// `` `message `` or `` `enum ``.
#[derive(Clone, Debug)]
pub struct Table<'md> {
    /// The name of the table itself.
    pub name: Path<'md>,
    /// This table's kind.
    pub kind: TableKind<'md>,
    /// This node's span.
    pub span: Span<'md>,
}

/// A [`Table`] kind.
#[derive(Clone, Debug)]
pub enum TableKind<'md> {
    /// A basic message table.
    Message {
        /// The table's rows.
        rows: Vec<TableRow<'md, Type<'md>>>,
    },
    /// A basic enum table.
    Enum {
        /// The table's rows.
        rows: Vec<TableRow<'md, Lit<'md>>>,
    },
    /// an enum mapping from enum values to literal values.
    ValueMap {
        /// the enum being mapped.
        from: Path<'md>,
        /// The table's rows.
        rows: Vec<TableRow<'md, Lit<'md>>>,
    },
    /// an enum mapping from enum values to types.
    TypeMap {
        /// The table's rows.
        from: Path<'md>,
        /// The table's rows.
        rows: Vec<TableRow<'md, Type<'md>>>,
    },
}

/// A parse error.
#[derive(Clone, Debug)]
pub struct Error<'md> {
    /// The location where the error occured.
    pub span: Span<'md>,
    /// The kind of error this is.
    pub kind: ErrorKind,
}

/// An [`Error`] kind.
#[derive(Clone, Debug)]
pub enum ErrorKind {
    /// Indicates that an integer failed to parse.
    BadInt,
    /// Indicates that a delimited like `[` was not matched.
    Unmatched,
    /// Indicates that something expected was missing, described by the
    /// string argument.
    Expected(String),
    /// Indicates that something unexpected was found, described by the
    /// string argument.
    Unexpected(String),
}
