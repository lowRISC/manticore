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

impl fmt::Display for Table<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // First, write out the opening heading.
        match &self.kind {
            TableKind::Message { .. } => {
                writeln!(f, "`message {}`", self.name)?
            }
            TableKind::Enum { .. } => writeln!(f, "`enum {}`", self.name)?,
            TableKind::ValueMap { from, .. } => {
                writeln!(f, "`enum {}({})`", self.name, from)?
            }
            TableKind::TypeMap { from, .. } => {
                writeln!(f, "`enum {}({})`", self.name, from)?
            }
        }

        // To make sure everything is nicely aligned, we need to pre-format all
        // rows more-or-less.
        let rows: Vec<_> = match &self.kind {
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

        let first_col_heading = match &self.kind {
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
        let width3 = rows
            .iter()
            .map(|(_, _, x)| x.map(|d| d.len()).unwrap_or(0))
            .max()
            .unwrap_or(0)
            .max("Description".len());

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
            write!(
                f,
                "| {:width1$} | {:width2$} |",
                first,
                name,
                width1 = width1,
                width2 = width2
            )?;
            if let Some(desc) = desc {
                write!(f, " {:width3$} |", desc, width3 = width3)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}
