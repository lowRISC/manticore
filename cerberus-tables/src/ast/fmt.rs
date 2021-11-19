// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::ast::*;

impl fmt::Display for Ident<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, component) in self.components.iter().enumerate() {
            if i == 0 {
                write!(f, "{}", component)?;
            } else {
                write!(f, ".{}", component)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for Lit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.base {
            Base::Dec => write!(f, "{}", self.value),
            Base::Hex => write!(
                f,
                "0x{:01$x}",
                self.value,
                self.bit_width.unwrap_or(0) / 4
            ),
            Base::Bin => {
                write!(f, "0b{:01$b}", self.value, self.bit_width.unwrap_or(0))
            }
        }
    }
}

impl fmt::Display for Type<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.kind {
            TypeKind::Bits(width) => write!(f, "b{}", width),
            TypeKind::Lit(l) => write!(f, "{}", l),
            TypeKind::Path(p) => write!(f, "{}", p),
            TypeKind::Mapping { mapping, field } => {
                write!(f, "{}({})", mapping, field)
            }
            TypeKind::FixedArray {
                ty: Some(ty),
                extent,
            } => write!(f, "{}[{}]", ty, extent),
            TypeKind::FixedArray { ty: None, extent } => {
                write!(f, "[{}]", extent)
            }
            TypeKind::VariableArray {
                ty: Some(ty),
                extent_field,
            } => write!(f, "{}[{}]", ty, extent_field),
            TypeKind::VariableArray {
                ty: None,
                extent_field,
            } => write!(f, "[{}]", extent_field),
            TypeKind::PrefixedArray {
                ty: Some(ty),
                extent_bits,
            } => write!(f, "{}[b{}]", ty, extent_bits),
            TypeKind::PrefixedArray {
                ty: None,
                extent_bits,
            } => write!(f, "[b{}]", extent_bits),
            TypeKind::IndefiniteArray { ty: Some(ty) } => {
                write!(f, "{}...", ty)
            }
            TypeKind::IndefiniteArray { ty: None } => write!(f, "..."),
            TypeKind::Aligned {
                ty: Some(ty),
                alignment,
            } => write!(f, "{} align({})", ty, alignment),
            TypeKind::Aligned {
                ty: None,
                alignment,
            } => write!(f, "align({})", alignment),
        }
    }
}

pub struct TableWithOptions<'md> {
    pub table: &'md Table<'md>,
    pub max_width: Option<usize>,
}

impl fmt::Display for Table<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(
            &TableWithOptions {
                table: self,
                max_width: None,
            },
            f,
        )
    }
}

impl fmt::Display for TableWithOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let table = self.table;

        // First, write out the opening heading.
        match &table.kind {
            TableKind::Message { .. } => {
                writeln!(f, "`message {}`", table.name)?
            }
            TableKind::Enum { .. } => writeln!(f, "`enum {}`", table.name)?,
            TableKind::ValueMap { from, .. } => {
                writeln!(f, "`enum {}({})`", table.name, from)?
            }
            TableKind::TypeMap { from, .. } => {
                writeln!(f, "`enum {}({})`", table.name, from)?
            }
        }

        // To make sure everything is nicely aligned, we need to pre-format all
        // rows more-or-less.
        let rows: Vec<_> = match &table.kind {
            TableKind::Message { rows, .. } => rows
                .iter()
                .map(|row| {
                    (
                        format!("`{}`", row.value),
                        format!("`{}`", row.name),
                        row.desc.map(|d| d.text().trim()),
                    )
                })
                .collect(),
            TableKind::Enum { rows, .. } => rows
                .iter()
                .map(|row| {
                    (
                        format!("`{}`", row.value),
                        format!("`{}`", row.name),
                        row.desc.map(|d| d.text().trim()),
                    )
                })
                .collect(),
            TableKind::ValueMap { rows, .. } => rows
                .iter()
                .map(|row| {
                    (
                        format!("`{}`", row.value),
                        format!("`{}`", row.name),
                        row.desc.map(|d| d.text().trim()),
                    )
                })
                .collect(),
            TableKind::TypeMap { rows, .. } => rows
                .iter()
                .map(|row| {
                    (
                        format!("`{}`", row.value),
                        format!("`{}`", row.name),
                        row.desc.map(|d| d.text().trim()),
                    )
                })
                .collect(),
        };

        let first_col_heading = match &table.kind {
            TableKind::Message { .. } | TableKind::TypeMap { .. } => "Type",
            _ => "Value",
        };
        let has_descs =
            rows.first().map(|(_, _, d)| d.is_some()).unwrap_or(true);

        let width1 = rows
            .iter()
            .map(|(x, _, _)| x.len())
            .max()
            .unwrap_or(0)
            .max(first_col_heading.len());
        let width2 = rows
            .iter()
            .map(|(_, x, _)| x.len())
            .max()
            .unwrap_or(0)
            .max("Name".len());
        let mut width3 = rows
            .iter()
            .map(|(_, _, x)| x.map(|d| d.len()).unwrap_or(0))
            .max()
            .unwrap_or(0)
            .max("Description".len());

        // If a max width is set, `width3` must be such that
        //
        // width1 + width2 + width3 + 10 <= max_width
        //
        // The 10 accounts for the four vertical bars (when descriptions are
        // present, which is the only case where `width3` matters) and the
        // two spaces around each cell. 4 + 2 * 3 = 10.
        if let Some(max_width) = self.max_width {
            let other_chars = width1 + width2 + 10;
            let max_width3 = max_width.saturating_sub(other_chars);
            width3 = width3.min(max_width3);
        }

        // Next, we write the column headings.
        write!(
            f,
            "| {:width1$} | {:width2$} |",
            first_col_heading,
            "Name",
            width1 = width1,
            width2 = width2
        )?;
        if has_descs {
            write!(f, " {:width3$} |", "Description", width3 = width3)?;
        }
        writeln!(f)?;

        // Next, the heading separator rule.
        //
        // The +2s below is to compensate for the two spaces around the
        // pipes not being included in the widths.
        write!(f, "|")?;
        for _ in 0..width1 + 2 {
            write!(f, "-")?;
        }
        write!(f, "|")?;
        for _ in 0..width2 + 2 {
            write!(f, "-")?;
        }
        write!(f, "|")?;

        if has_descs {
            for _ in 0..width3 + 2 {
                write!(f, "-")?;
            }
            write!(f, "|")?;
        }
        writeln!(f)?;

        // Finally, write out the rows.
        for (first, name, desc) in rows {
            use fmt::Write as _;

            // We pre-allocate in order to learn the length.
            // This allocation can technically be avoided but it's not
            // worth it to do so.
            let mut line = format!(
                "| {:width1$} | {:width2$} |",
                first,
                name,
                width1 = width1,
                width2 = width2
            );
            if let Some(desc) = desc {
                // The style rule is that if a description would go past the
                // 80 column line, it may do so, but the rest of the table
                // shouldn't; width3 has been computed to have this behavior.
                //
                // However, if a line would go past the 80 column line due to
                // the space between the end of the description and the pipe,
                // that space should be omitted, instead.
                write!(line, " {:width3$}", desc, width3 = width3)?;
                if let Some(max_width) = self.max_width {
                    // If the length of the previous line is exactly one less
                    // (e.g. 79), we can only fit one more character before
                    // going over.
                    //
                    // If we would go over no matter what, we add the space
                    // anyways.
                    if line.len() == max_width - 1 {
                        line.push('|');
                    } else {
                        line.push_str(" |");
                    }
                } else {
                    line.push_str(" |");
                }
            }
            writeln!(f, "{}", line)?;
        }

        Ok(())
    }
}
