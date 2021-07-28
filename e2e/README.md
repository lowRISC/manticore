# End-to-end tests for Manticore.

This crate contains Manticore's end-to-end tests, which stand up and interact
with a "virtual RoT" running as a subprocess over TCP.

This crate serves two major purposes:
1. To provide an easy way to black-box test Manticore; in the future, we'd
   like to be able to make it possible to test other implementations, such
   as Azure's Cerberus implementation.
2. To provide an example *integration* for platform integrators to
   understand how to build a Cerberus-compliant device using Manticore's
   toolkit.

We leverage Rust's unit test harness to run the tests. Running `cargo test` is
insufficient, since the tests won't know where to find the virtual RoT binary.
The binary must be passed explicitly via the `MANTICORE_E2E_TARGET_BINARY`
environment variable for the tests to find. The `e2e/run.sh` script shows how
to do this.

It is possible to run non-Manticore binaries under the end-to-end tests, since
they are not Manticore-specific. The only requirements are:
- They accept the same command-line interface as the `e2e` binary.
- Upon binding a TCP port, they must print `listening@<port>\n` to stdout, for
  the test harness to find the OS-allocated TCP port.

Currently, running these tests on a non-POSIX system is not supported.

