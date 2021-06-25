  '{target}':
    runs-on: ubuntu-latest
    name: 'Fuzz `{ty}` with `{test_type}`'
    steps:
    - uses: actions/checkout@v2
    - name: Install Toolchain
      uses: actions-rs/toolchain@v1
      with:
        toolchain: nightly
    - name: Install `cargo fuzz`
      run: cargo install cargo-fuzz
    - name: `cargo fuzz run --release --sanitizer address`
      run: |
        cargo +nightly fuzz run \
          --release --sanitizer address \
          {target} \
          -- -max_total_time=180

