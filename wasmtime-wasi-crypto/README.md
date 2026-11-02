# wasmtime-wasi-crypto

Wasmtime host implementation of the `wasi:crypto@0.12.0` WIT interfaces.

## What this crate does

Implements all nine `wasi:crypto` interfaces as Wasmtime component host functions:

- `common`: `array-output` and the shared types (`crypto-errno`, key encodings, ...)
- `symmetric`: AEAD, hash, MAC, KDF, with their keys, options and states
- `signatures`: ECDSA, EdDSA, RSA, with their key pairs, keys, options and states
- `kx`: X25519, ML-KEM, X-Wing, with their key pairs, keys and options
- `secrets-manager`: stub (`open` returns `UnsupportedFeature`)
- `symmetric-managed`, `signatures-managed`, `kx-managed`: stubs (return `UnsupportedFeature`)
- `external-secrets`: stub (returns `UnsupportedFeature`)

## Integrating into a Wasmtime host

1. Implement `WasiCryptoView` on your store data type:

```rust
impl WasiCryptoView for MyState {
    fn crypto(&mut self) -> WasiCryptoCtxView<'_> {
        WasiCryptoCtxView {
            ctx: &mut self.crypto_ctx,
            table: &mut self.table,
            limits: &mut self.limits,
        }
    }
}
```

2. Call `add_to_linker` when building your `Linker`:

```rust
wasmtime_wasi_crypto::crypto::add_to_linker(&mut linker)?;
```

See `wasmtime-host/src/host.rs` for a complete reference integration.

## Documentation

- [`../docs/architecture.md`](../docs/architecture.md): pipeline, resource lifecycle, options system, known gaps
- [`../docs/modules.md`](../docs/modules.md): per-module algorithm tables and test coverage
