# liboptrand-rs
OptRand --- Optimistically Responsive Random Beacon (Rust)

## Dependencies

This codebase is tested on Arch Linux 
- `rustc 1.57.0 (f1edd0429 2021-11-29)`
- `cargo 1.57.0 (b2e52d7ca 2021-10-21)`

## Building

- Run `make` to build the release versions of all the code
- Run `make configs` to generate test data which contains configs for the various tests

## Testing cryptography

- Run `cargo test --all --release`. Some tests may take a while (2-3 minutes).

## Binaries
- `genconfig`: Generates config files. Use `-h` to view all the options and `Makefile` for examples.
- `opt_main`: Runs OptRand with optimistic responsiveness enabled. Use `-h` to view all the options and `scripts/run-opt.sh` for an example.
- `sync_main`: Runs OptRand with only synchronous mode enabled. Use `-h` to view all the options and `scripts/run-sync.sh` for an example.

## Scripts

- `scripts/run-opt.sh`: Runs `opt_main` locally using $4$ nodes. To play with the delta value, run `DELTA=100 bash scripts/run-opt.sh`. It supports the following environment variables
    - `DELTA=100`, delay time in ms
    - `TYPE=release` or `TYPE=debug` whether to run the code in debug mode or release mode
    - `TESTDIR=./testdata/test-local` to configure the test data directory

- `scripts/run-sync.sh` has the same options as above.