# test-components

Guest Wasm test binaries for `wasmtime-wasi-crypto`. Each crate is compiled to `wasm32-wasip2` and exercises one WIT interface via the `wasmtime-host test` runner.

## Running tests

```sh
# From anywhere within the workspace:
cargo test -p wasi-crypto-common --target wasm32-wasip2
cargo test -p wasi-crypto-symmetric --target wasm32-wasip2
cargo test -p wasi-crypto-signatures --target wasm32-wasip2
cargo test -p wasi-crypto-kx --target wasm32-wasip2
cargo test -p wasi-crypto-asymmetric-common --target wasm32-wasip2
```

The `.cargo/config.toml` runner dispatches automatically to `wasmtime-host test`.

## Test behavior

| Outcome                      | Meaning                                                                                                                |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Pass                         | Feature implemented and working                                                                                        |
| `#[should_panic]`            | Optional feature not implemented; host returns `CryptoErrno::UnsupportedFeature`, guest `.unwrap()` panics as expected |
| Fail — "not yet implemented" | Host has a `todo!()` — incomplete implementation                                                                       |

Optional features (secrets manager, managed keys) always return `UnsupportedFeature`, mirroring the WITX 0.10 reference implementation. Their tests are marked `#[should_panic]` and are expected to fail until the feature is implemented.

## Coverage

| Interface                                 | Crate                           | Status          |
| ----------------------------------------- | ------------------------------- | --------------- |
| `wasi-ephemeral-crypto-common`            | `wasi-crypto-common`            | Partial         |
| `wasi-ephemeral-crypto-symmetric`         | `wasi-crypto-symmetric`         | Partial         |
| `wasi-ephemeral-crypto-signatures`        | `wasi-crypto-signatures`        | Partial         |
| `wasi-ephemeral-crypto-kx`                | `wasi-crypto-kx`                | Partial         |
| `wasi-ephemeral-crypto-asymmetric-common` | `wasi-crypto-asymmetric-common` | Partial         |
| `wasi-ephemeral-crypto-external-secrets`  | —                               | Not yet written |

See [`../docs/modules.md`](../docs/modules.md) for detail on what each existing component covers.

## Test origin and quality

**Test origin:** AI-generated from doctests WITX 0.10, the [wasi-crypto-host-functions](https://github.com/wasm-crypto/wasi-crypto-host-functions) tests, regression tests, and invariants to uphold from the spec. Note that these tests aim to serve as a starting point, not the end all-be-all. These were mostly just generated to catch implementation bugs, but can be used for a more complete system.

## Regression tests

This project aims to make heavy use of regression tests. If you find a bug, please report it and include a test with the fix.
