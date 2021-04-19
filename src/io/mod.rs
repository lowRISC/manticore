// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! I/O interfaces, in lieu of [`std::io`].
//!
//! These functions and traits are mostly intended for manipulating byte
//! buffers, but they could be implemented on other types that provide a
//! read/write interface.

pub mod bit_buf;
pub mod cursor;
pub mod endian;
pub mod read;
pub mod write;

pub use cursor::Cursor;
pub use read::Read;
pub use write::Write;

/// A generic, low-level I/O error.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Indicates that some underlying buffer has been completely used up,
    /// either for reading from or writing to.
    ///
    /// This is typically a fatal error, since it is probably not possible
    /// to re-allocate that underlying buffer.
    BufferExhausted,

    /// Indicates that an unspecified, internal failure occurred.
    Internal,
}
