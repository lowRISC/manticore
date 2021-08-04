# Manticore Test Utilities

This directory defines a test-only Rust crate that contains shared test
utilities used in both Manticore's unit tests and in the end-to-end and fuzz
tests.

## Test Data

This directory also includes test data under `src/data`. This data is exposed
as Rust constants that include the files as static byte slices.

To regenerate the data, run the `regenerate-test-data.sh` script. The constants
in the Rust files in `src/data` are machine-generated, but any text above the
`/* GENERATED START */` comment will be preserved.
