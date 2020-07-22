# Manticore

## About the project

Manticore is a work-in-progress implementation of the Open Compute Project's
[Cerberus] attestation protocol, developed as part of the [OpenTitan project].

Manticore aims to eventually achieve parity with Microsoft's C implementation,
while also being a proving ground for improvements and enhancements of the
protocol.

[Cerberus]: https://github.com/opencomputeproject/Project_Olympus/tree/master/Project_Cerberus
[OpenTitan project]: https://opentitan.org

## Building Manticore

Manticore is a Rust project using Cargo. It can be built with `cargo build` and
the unit tests executed with `cargo test`.

While Manticore has a moratorium on `unsafe` in its own source code, we also
have fuzz tests for all code that handles untrusted input. These tests, and
instructions for executing them, can be found under the `fuzz` directory.
Fuzz tests require nightly Rust, though the library itself builds under stable.

In order to build the Manticore command line tool, run
`cargo build --features=tool --bin manticore-tool`.

## How to contribute

Have a look at [CONTRIBUTING](./CONTRIBUTING.md) for guidelines on how to
contribute code to this repository.

All patches to Manticore are expected to include unit tests and, if they
introduce parsing code, fuzz tests as well. All code must be formatted with
`cargo fmt`. As aforementioned, `unsafe` is banned in Manticore source code.

## Licensing

Unless otherwise noted, everything in this repository is covered by the Apache
License, Version 2.0 (see [LICENSE](./LICENSE) for full text).
