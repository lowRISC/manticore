# Manticore

## About the project

Manticore is a work-in-progress implementation of the Open Compute Project's
[Cerberus] attestation protocol, developed as part of the [OpenTitan project].

Manticore aims to eventually achieve parity with Microsoft's C implementation,
while also being a proving ground for improvements and enhancements of the
protocol.

[Cerberus]: https://github.com/opencomputeproject/security/RoT/Protocol
[OpenTitan project]: https://opentitan.org

## Building Manticore

Manticore is a Rust project using Cargo. The main library can be built using
`cargo build`. Manticore also has a number of tests:
- Unit tests for the library itself: these are run with `cargo test`.
- Integration host-side tests: these are run with `./e2e/run.sh`. See the `e2e`
  directory for more information.
- Fuzz tests: these are located in the `fuzz` directory. Fuzzing requires
  a nightly Rust install.

In order to build the Manticore command line tool, run
`cargo build -p manticore-tool`.

## How to contribute

Have a look at [CONTRIBUTING](./CONTRIBUTING.md) for guidelines on how to
contribute code to this repository.

All patches to Manticore are expected to include unit tests and, if they
introduce parsing code, fuzz tests as well. All code must be formatted with
`cargo fmt`, pass `cargo clippy`, and pass all tests; CI will automatically
check for this.

As aforementioned, `unsafe` is banned in Manticore source code,
except in some files by a case-by-case basis (such as for low-level memory
management).

## Licensing

Unless otherwise noted, everything in this repository is covered by the Apache
License, Version 2.0 (see [LICENSE](./LICENSE) for full text). All code files
must have the appropriate license header, which is checked automatically by CI.
