`manticore` Fuzz Tests
======

`manticore` provides fuzz tests for anything that serializes to and from a byte representation.
(Note that coverage is still a work in progress; eventually, we well require fuzz tests as part of all code review that adds new parsers.)

To run a fuzz target under `fuzz_target`, run
```shell
cargo install cargo-fuzz
cargo +nightly fuzz run <target>
```

Many fuzz targets (especially those involving `manticore::protocol` types) are very boilerplatey.
To make creating fuzz tests for them easier, see the script `util/new_protocol_target.py` under the project root.
