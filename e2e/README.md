# End-to-end tests for Manticore.

This crate operates as follows. When run as `./e2e run-tests`, it will
re-exec a copy of the process via `./e2e serve`. This new process is a
"virtual RoT", which is connected back to the parent over a TCP "bus".
The parent can then actuate the virtual RoT as a sort of black box.

This crate serves two major purposes:
1. To provide an easy way to black-box test Manticore; in the future, we'd
   like to be able to make it possible to test other implementations, such
   as Azure's Cerberus implementation.
2. To provide an example *integration* for platform integrators to
   understand how to build a Cerberus-compliant device using Manticore's
   toolkit.

To actually run these tests against manticore, run do
```
cargo run -p manticore-e2e -- run-tests
```
If a port allocation error occurs, the `--port` flag may be used to specify one
explicitly.
