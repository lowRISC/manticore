// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::ast::*;

/// Parse state for the table parser.
pub struct Context<'md> {
    src: &'md MarkdownFile,
    cursor: Cursor,
    cursor_stack: Vec<Cursor>,
}

/// A position in source code.
///
/// `line` and `col` are one-indexed.
#[derive(Copy, Clone, Debug)]
pub struct Cursor {
    /// The byte offset of this position.
    pub byte: usize,
    /// The line of this position.
    pub line: usize,
    /// The column of this position.
    pub col: usize,
}

impl Cursor {
    /// Advances the cursor, triggering a line wrap when
    /// hitting a newline.
    pub fn advance(&mut self, c: char) {
        self.byte += c.len_utf8();
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
    }
}

impl<'md> Context<'md> {
    /// Creates a new parser state.
    pub fn new(src: &'md MarkdownFile) -> Self {
        Self {
            src,
            cursor: Cursor {
                byte: 0,
                line: 1,
                col: 1,
            },
            cursor_stack: Vec::new(),
        }
    }

    /// Executes `f` inside of a scope, such that `span()` always referrs
    /// to the start of the scope.
    ///
    /// If `f` returns an error, the cursor is backtracked to where it was
    /// before `f` was run.
    pub fn try_scope<T, E>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        self.skip_spaces();
        self.cursor_stack.push(self.cursor);
        let x = f(self);
        let prev = self
            .cursor_stack
            .pop()
            .expect("popped empty cursor stack; this is a bug");
        if x.is_err() {
            self.cursor = prev;
        }
        x
    }

    /// Like `try_scope()` but infallible.
    pub fn scope<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let x: Result<_, std::convert::Infallible> =
            self.try_scope(|x| Ok(f(x)));
        x.unwrap()
    }

    /// Gets a span from the start of the innermost scope up until
    /// the current cursor.
    pub fn span(&self) -> Span<'md> {
        let start = *self
            .cursor_stack
            .last()
            .expect("popped empty cursor stack; this is a bug");
        Span {
            src: self.src,
            range: (start, self.cursor),
        }
    }

    /// Gets a zero-width span corresponding to the cursor.
    pub fn cursor(&self) -> Span<'md> {
        Span {
            src: self.src,
            range: (self.cursor, self.cursor),
        }
    }

    /// Peeks the next character.
    pub fn peek(&self) -> Option<char> {
        // Getting the character at a byte offset is oddly annoying.
        self.src.text.get(self.cursor.byte..)?.chars().next()
    }

    /// Peeks the next prefix that is `byte_len` bytes long.
    pub fn peek_prefix(&self, byte_len: usize) -> Option<&'md str> {
        self.src
            .text
            .get(self.cursor.byte..self.cursor.byte + byte_len)
    }

    /// Consumes a prefix with the exact value `prefix`, returning a span for
    /// the consumed text.
    pub fn take_str(&mut self, prefix: &str) -> Option<Span<'md>> {
        self.skip_spaces();
        if !self.src.text.get(self.cursor.byte..)?.starts_with(prefix) {
            return None;
        }
        self.scope(|zelf| {
            prefix.chars().for_each(|c| zelf.cursor.advance(c));
            Some(zelf.span())
        })
    }

    /// Consumes text so long as `cond` is true, returning the span of
    /// consumed text.
    ///
    /// `cond`'s first argument is the character index from the start of
    /// the `take_while` operation.
    pub fn take_while(
        &mut self,
        mut cond: impl FnMut(usize, char) -> bool,
    ) -> Span<'md> {
        self.scope(|zelf| {
            let mut idx = 0;
            while let Some(c) = zelf.peek() {
                if !cond(idx, c) {
                    break;
                }
                zelf.cursor.advance(c);
                idx += 1;
            }
            zelf.span()
        })
    }

    /// Like `take_while`, but skips the characters instead and returns how
    /// many characters were skipped.
    pub fn skip(&mut self, mut cond: impl FnMut(usize, char) -> bool) -> usize {
        let mut i = 0;
        while let Some(c) = self.peek() {
            if !cond(i, c) {
                break;
            }
            self.cursor.advance(c);
            i += 1;
        }
        i
    }

    /// Like `skip` but skips only spaces.
    pub fn skip_spaces(&mut self) -> usize {
        self.skip(|_, c| c == ' ')
    }

    /// Runs the given parsing function; if it returns `Ok(None)`, returns
    /// a `ErrorKind::Expected` with the given `expected`.
    pub fn expect<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<Option<T>, Error<'md>>,
        expected: impl fmt::Display,
    ) -> Result<T, Error<'md>> {
        parse(self)?.ok_or_else(|| Error {
            kind: ErrorKind::Expected(expected.to_string()),
            span: self.cursor(),
        })
    }

    /// Like `expect`, but expects a specific string.
    pub fn expect_str(
        &mut self,
        prefix: &str,
        expected: impl fmt::Display,
    ) -> Result<Span<'md>, Error<'md>> {
        self.expect(|ctx| Ok(ctx.take_str(prefix)), expected)
    }
}

impl<'md> Ident<'md> {
    pub fn parse(ctx: &mut Context<'md>) -> Result<Option<Self>, Error<'md>> {
        let id = Self(ctx.take_while(|i, c| {
            (i > 0 && c.is_ascii_digit()) || c.is_ascii_alphabetic() || c == '_'
        }));

        if id.name().is_empty() {
            Ok(None)
        } else {
            Ok(Some(id))
        }
    }
}

impl<'md> Path<'md> {
    pub fn parse(ctx: &mut Context<'md>) -> Result<Option<Self>, Error<'md>> {
        ctx.try_scope(|ctx| {
            let mut components = Vec::new();
            while let Some(id) = Ident::parse(ctx)? {
                components.push(id);
                if ctx.take_str(".").is_none() {
                    break;
                }
            }

            if components.is_empty() {
                return Ok(None);
            }
            Ok(Some(Self {
                components,
                canonicalized: None,
                span: ctx.span(),
            }))
        })
    }
}

impl<'md> Lit<'md> {
    pub fn parse(ctx: &mut Context<'md>) -> Result<Option<Self>, Error<'md>> {
        ctx.try_scope(|ctx| {
            let base = match ctx.peek_prefix(2) {
                Some("0x") | Some("0X") => Base::Hex,
                Some("0b") | Some("0B") => Base::Bin,
                _ => Base::Dec,
            };

            let span = ctx.take_while(|_, c| c.is_ascii_alphanumeric());
            if span.text().is_empty() {
                return Ok(None);
            }

            let digits = match base {
                Base::Dec => span.text(),
                _ => &span.text()[2..],
            };
            dbg!(digits);
            let (bit_width, radix) = match base {
                Base::Dec => (None, 10),
                Base::Bin => (Some(digits.len()), 2),
                Base::Hex => (Some(digits.len() * 4), 16),
            };

            let value = u64::from_str_radix(digits, radix)
                .map_err(|_| span.error(ErrorKind::BadInt))?;

            Ok(Some(Self {
                bit_width,
                value,
                base,
                span,
            }))
        })
    }
}

impl<'md> Type<'md> {
    pub fn parse(ctx: &mut Context<'md>) -> Result<Option<Self>, Error<'md>> {
        ctx.try_scope(|ctx| {
            let mut ty = Path::parse(ctx)?
                .map(|path| {
                    if let Some(width) = path.components[0].as_bits_type() {
                        if path.components.len() > 1 {
                            return Err(path.span.error(
                                ErrorKind::Unexpected(
                                    "extra path components".into(),
                                ),
                            ));
                        }

                        Ok(Type {
                            kind: TypeKind::Bits(width),
                            span: ctx.span(),
                        })
                    } else if let Some(paren) = ctx.take_str("(") {
                        let field = ctx.expect(Ident::parse, "identifier")?;
                        ctx.take_str(")")
                            .ok_or(paren.error(ErrorKind::Unmatched))?;
                        Ok(Type {
                            kind: TypeKind::Mapping {
                                mapping: path,
                                field,
                            },
                            span: ctx.span(),
                        })
                    } else {
                        Ok(Type {
                            span: path.span,
                            kind: TypeKind::Path(path),
                        })
                    }
                })
                .transpose()?;
            if ty.is_none() {
                if let Ok(Some(lit)) = Lit::parse(ctx) {
                    return Ok(Some(Type {
                        kind: TypeKind::Lit(lit),
                        span: ctx.span(),
                    }));
                }
            }

            loop {
                let brack = match ctx.take_str("[") {
                    Some(brack) => brack,
                    None => break,
                };
                if let Ok(Some(ident)) = Ident::parse(ctx) {
                    if let Some(extent_bits) = ident.as_bits_type() {
                        ty = Some(Type {
                            kind: TypeKind::PrefixedArray {
                                ty: ty.map(Box::new),
                                extent_bits,
                            },
                            span: ctx.span(),
                        });
                    } else {
                        ty = Some(Self {
                            kind: TypeKind::VariableArray {
                                ty: ty.map(Box::new),
                                extent_field: ident,
                            },
                            span: ctx.span(),
                        });
                    }
                } else if let Ok(Some(extent)) = Lit::parse(ctx) {
                    ty = Some(Self {
                        kind: TypeKind::FixedArray {
                            ty: ty.map(Box::new),
                            extent,
                        },
                        span: ctx.span(),
                    });
                } else {
                    return Err(ctx.cursor().error(ErrorKind::Expected(
                        "literal, identifier, or bits type".into(),
                    )));
                }

                ctx.take_str("]").ok_or(Error {
                    kind: ErrorKind::Unmatched,
                    span: brack,
                })?;
            }

            if ctx.take_str("...").is_some() {
                ty = Some(Type {
                    kind: TypeKind::IndefiniteArray {
                        ty: ty.map(Box::new),
                    },
                    span: ctx.span(),
                });
            }

            if ctx.take_str("align").is_some() {
                let paren = ctx.expect_str("(", "`(`")?;
                let lit = ctx.expect(Lit::parse, "literal")?;
                ctx.take_str(")").ok_or(paren.error(ErrorKind::Unmatched))?;

                ty = Some(Self {
                    kind: TypeKind::Aligned {
                        ty: ty.map(Box::new),
                        alignment: lit,
                    },
                    span: ctx.span(),
                });
            }

            Ok(ty)
        })
    }
}

/// Helper for finding the start of tables.
struct TableHeader<'md> {
    kw: Ident<'md>,
    path: Path<'md>,
    arg: Option<Path<'md>>,
    first_col: Ident<'md>,
    has_desc: bool,
}

impl<'md> TableHeader<'md> {
    pub fn parse(ctx: &mut Context<'md>) -> Result<Option<Self>, Error<'md>> {
        // The first line is:
        // `ident path(path)`\n
        //
        // If this is matched exactly without errors (but with arbitrary
        // whitespace) we assume we're looking at a table.

        if ctx.take_str("`").is_none() {
            return Ok(None);
        }

        let kw = match Ident::parse(ctx)? {
            Some(x) => x,
            None => return Ok(None),
        };

        let path = match Path::parse(ctx)? {
            Some(x) => x,
            None => return Ok(None),
        };

        let arg = if ctx.take_str("(").is_some() {
            let path = match Path::parse(ctx)? {
                Some(x) => x,
                None => return Ok(None),
            };
            if ctx.take_str(")").is_none() {
                return Ok(None);
            }
            Some(path)
        } else {
            None
        };

        if ctx.take_str("`\n").is_none() {
            return Ok(None);
        }

        // Definitely a table a this point.

        // Parse the first row:
        // | $ident | Name | (Description |)?
        ctx.expect_str("|", "pipe")?;
        let first_col = ctx.expect(Ident::parse, "identifier")?;

        ctx.expect_str("|", "pipe")?;
        ctx.expect_str("Name", "`Name`")?;
        ctx.expect_str("|", "pipe")?;

        let has_desc = ctx.take_str("Description").is_some();
        if has_desc {
            ctx.expect_str("|", "pipe")?;
        }

        ctx.expect_str("\n", "newline")?;

        // Parse the second row:
        // |----|----:|:----|
        ctx.expect_str("|", "pipe")?;
        ctx.skip(|_, c| ":-".contains(c));
        ctx.expect_str("|", "pipe")?;
        ctx.skip(|_, c| ":-".contains(c));
        ctx.expect_str("|", "pipe")?;

        if has_desc {
            ctx.skip(|_, c| ":-".contains(c));
            ctx.expect_str("|", "pipe")?;
        }
        ctx.expect_str("\n", "newline")?;

        Ok(Some(TableHeader {
            kw,
            path,
            arg,
            first_col,
            has_desc,
        }))
    }
}

impl<'md, Type> TableRow<'md, Type> {
    pub fn parse(
        ctx: &mut Context<'md>,
        parse_desc: bool,
        parse: impl FnOnce(&mut Context<'md>) -> Result<Option<Type>, Error<'md>>,
        expected: impl fmt::Display,
    ) -> Result<Option<Self>, Error<'md>> {
        ctx.scope(|ctx| {
            ctx.expect_str("|", "pipe")?;
            ctx.expect_str("`", "backtick")?;
            let value = ctx.expect(parse, expected)?;
            ctx.expect_str("`", "backtick")?;

            ctx.expect_str("|", "pipe")?;
            ctx.expect_str("`", "backtick")?;
            let name = ctx.expect(Ident::parse, "identifier")?;
            ctx.expect_str("`", "backtick")?;

            let desc = if parse_desc {
                ctx.expect_str("|", "pipe")?;

                let mut in_backticks = false;
                let desc = ctx.take_while(|_, c| {
                    if c == '`' {
                        in_backticks = !in_backticks;
                    }

                    in_backticks || c != '|'
                });

                Some(desc)
            } else {
                None
            };
            ctx.expect_str("|", "pipe")?;
            ctx.expect_str("\n", "newline")?;

            Ok(Some(TableRow {
                value,
                name,
                desc,
                span: ctx.span(),
            }))
        })
    }
}

impl<'md> Table<'md> {
    pub fn parse(ctx: &mut Context<'md>) -> Result<Option<Self>, Error<'md>> {
        pub fn collect_rows<'md, Type>(
            ctx: &mut Context<'md>,
            parse_desc: bool,
            mut parse: impl FnMut(
                &mut Context<'md>,
            ) -> Result<Option<Type>, Error<'md>>,
            expected: impl fmt::Display,
        ) -> Result<Vec<TableRow<'md, Type>>, Error<'md>> {
            let mut rows = Vec::new();
            while let Some('|') = ctx.peek() {
                rows.push(ctx.expect(
                    |ctx| TableRow::parse(ctx, parse_desc, &mut parse, "type"),
                    &expected,
                )?);
            }
            Ok(rows)
        }

        ctx.scope(|ctx| {
            let header = match TableHeader::parse(ctx)? {
                Some(h) => h,
                None => return Ok(None),
            };

            match (
                header.kw.name(),
                header.arg,
                header.first_col.name(),
                header.has_desc,
            ) {
                // `message` tables.
                ("message", None, "Type", true) => Ok(Some(Table {
                    name: header.path,
                    kind: TableKind::Message {
                        rows: collect_rows(ctx, true, Type::parse, "type")?,
                    },
                    span: ctx.span(),
                })),
                ("message", None, "Type", false) => {
                    return Err(header.path.span.error(ErrorKind::Expected(
                        "descriptions for message fields".into(),
                    )))
                }
                ("message", Some(arg), _, _) => {
                    return Err(arg.span.error(ErrorKind::Unexpected(
                        "argument in message".into(),
                    )))
                }
                ("message", None, _, _) => {
                    return Err(header
                        .first_col
                        .span()
                        .error(ErrorKind::Expected("`Type`".into())))
                }

                // `enum` tables without an argument.
                ("enum", None, "Value", true) => Ok(Some(Table {
                    name: header.path,
                    kind: TableKind::Enum {
                        rows: collect_rows(ctx, true, Lit::parse, "literal")?,
                    },
                    span: ctx.span(),
                })),
                ("enum", None, "Value", false) => {
                    return Err(header.path.span.error(ErrorKind::Expected(
                        "descriptions for enum variants".into(),
                    )))
                }
                ("enum", None, _, _) => {
                    return Err(header
                        .first_col
                        .span()
                        .error(ErrorKind::Expected("`Value`".into())))
                }

                // `enum` tables with an argument.
                ("enum", Some(arg), "Type", _) => Ok(Some(Table {
                    name: header.path,
                    kind: TableKind::TypeMap {
                        rows: collect_rows(
                            ctx,
                            header.has_desc,
                            Type::parse,
                            "type",
                        )?,
                        from: arg,
                    },
                    span: ctx.span(),
                })),
                ("enum", Some(arg), "Value", _) => Ok(Some(Table {
                    name: header.path,
                    kind: TableKind::ValueMap {
                        rows: collect_rows(
                            ctx,
                            header.has_desc,
                            Lit::parse,
                            "literal",
                        )?,
                        from: arg,
                    },
                    span: ctx.span(),
                })),
                ("enum", Some(_), _, _) => Err(header
                    .first_col
                    .span()
                    .error(ErrorKind::Expected("`Type` or `Value`".into()))),

                _ => Err(header.kw.span().error(ErrorKind::Expected(
                    "`message` or `enum`".to_string(),
                ))),
            }
        })
    }
}
