# wasmtime-wasi-crypto-workspace

A WIP Wasmtime host implementation of [wasi-crypto](https://github.com/WebAssembly/wasi-crypto) using the modern WIT / Component Model interface (v0.11.0).

The WIT spec is a direct, conservative translation of the [WITX 0.10 spec](https://github.com/WebAssembly/wasi-crypto/tree/main/witx/witx-0.10), contributed upstream via [PR #94](https://github.com/WebAssembly/wasi-crypto/pull/94) (currently draft). The current goal is feature parity with the existing [wasi-crypto-host-functions](https://github.com/wasm-crypto/wasi-crypto-host-functions) WITX implementation before any modernizations are considered.

**Status:** experimental / WIP.

## Build

```sh
cargo build
```

## Test

Each test component must be compiled for `wasm32-wasip2` and run via `wasmtime-host`:

```sh
cargo test -p wasi-crypto-common --target wasm32-wasip2
cargo test -p wasi-crypto-symmetric --target wasm32-wasip2
cargo test -p wasi-crypto-signatures --target wasm32-wasip2
cargo test -p wasi-crypto-kx --target wasm32-wasip2
cargo test -p wasi-crypto-asymmetric-common --target wasm32-wasip2
```

The `.cargo/config.toml` runner wires `cargo test --target wasm32-wasip2` to `wasmtime-host test` automatically.

## Documentation

- [`docs/architecture.md`](docs/architecture.md): WIT→bindgen→host trait→crypto pipeline, resource lifecycle, options system
- [`docs/modules.md`](docs/modules.md): per-module algorithm tables, options, test coverage, known gaps
