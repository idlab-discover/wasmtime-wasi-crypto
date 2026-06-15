# wasmtime-host

CLI binary providing a Wasmtime host with wasi-crypto support. Serves two purposes:

1. **Reference integration**: shows how to wire `wasmtime-wasi-crypto` into a Wasmtime host (`host.rs`).
2. **Test runner**: runs wasm test components from `test-components/` (`runner.rs`).

## Subcommands

```sh
# Run a wasm component directly
cargo run -p wasmtime-host -- run <component.wasm> [-- <args>]

# Run all tests in a wasm test binary
cargo run -p wasmtime-host -- test <component.wasm> [<filter>]
```

## Test runner behavior

The `test` subcommand:

1. Runs the component with `-- --list` to enumerate test names.
2. Runs each test in an isolated `Store` with a fresh `WasiCryptoCtx`.
3. Reports results via `libtest-mimic` (standard Rust test output format).
4. Catches host-side `todo!()` panics via `tokio::spawn` and reports them as failures with the message "Host implementation feature not yet implemented".

## Known limitation

`.cargo/config.toml` wires the `wasm32-wasip2` test runner using a relative path:

```toml
runner = "cargo run --manifest-path ../../wasmtime-host/Cargo.toml -- test"
```
