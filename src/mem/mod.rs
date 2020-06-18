// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Memory-management utilities.

#[cfg_attr(feature = "arbitrary-derive", path = "ref_wrapper_cow.rs")]
mod ref_wrapper;
pub use ref_wrapper::Ref;
