// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! General memory manipulation utilities, such as arenas.

// TODO: Make this a module people need to access directly.
mod arena;
pub use arena::*;

pub mod cow;
