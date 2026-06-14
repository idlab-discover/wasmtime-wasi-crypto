# test-components

Guest Wasm test binaries for `wasmtime-wasi-crypto`. Each crate is compiled to `wasm32-wasip2` and exercises one WIT interface via the `wasmtime-host test` runner.

## Running tests

```sh
# From the workspace root:
cargo test -p wasi-crypto-common --target wasm32-wasip2
cargo test -p wasi-crypto-symmetric --target wasm32-wasip2
cargo test -p wasi-crypto-signatures --target wasm32-wasip2
```

The `.cargo/config.toml` runner dispatches automatically to `wasmtime-host test`.

## Test behavior

| Outcome | Meaning |
|---|---|
| Pass | Feature implemented and working |
| `#[should_panic]` | Optional feature not implemented; host returns `CryptoErrno::UnsupportedFeature`, guest `.unwrap()` panics as expected |
| Fail — "not yet implemented" | Host has a `todo!()` — incomplete implementation |

Optional features (secrets manager, managed keys) always return `UnsupportedFeature`, mirroring the WITX 0.10 reference implementation. Their tests are marked `#[should_panic]` and are expected to fail until the feature is implemented.

## Coverage

| Interface | Crate | Status |
|---|---|---|
| `wasi-ephemeral-crypto-common` | `wasi-crypto-common` | Partial |
| `wasi-ephemeral-crypto-symmetric` | `wasi-crypto-symmetric` | Partial |
| `wasi-ephemeral-crypto-signatures` | `wasi-crypto-signatures` | Partial |
| `wasi-ephemeral-crypto-kx` | — | Not yet written |
| `wasi-ephemeral-crypto-asymmetric-common` | — | Not yet written |
| `wasi-ephemeral-crypto-external-secrets` | — | Not yet written |

See [`../docs/modules.md`](../docs/modules.md) for detail on what each existing component covers.

## Test origin and quality

Tests were AI-generated based on the doc comments in the [WITX 0.10 spec](https://github.com/WebAssembly/wasi-crypto/tree/main/witx/witx-0.10). They are a starting point, not exhaustive. Future goal: port the test suite from [wasi-crypto-host-functions](https://github.com/wasm-crypto/wasi-crypto-host-functions).

## Regression tests

When fixing a bug, add a regression test in the appropriate `<crate>/src/lib.rs` before or alongside the fix.
