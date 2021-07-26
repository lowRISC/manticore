  '{target}':
    runs-on: ubuntu-latest
    name: 'Fuzz `{ty}` with `{test_type}`'
    steps:
    - uses: actions/checkout@v2
    - name: Install `cargo fuzz`
      run: cargo install cargo-fuzz
    - name: Run `cargo fuzz run --release --sanitizer address`
      run: |
        cd fuzz
        cargo fuzz run \
          --release --sanitizer address \
          {target} \
          -- -max_total_time=180

