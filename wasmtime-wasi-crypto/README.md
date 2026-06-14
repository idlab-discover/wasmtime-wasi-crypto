# wasmtime-wasi-crypto

Wasmtime host implementation of the `wasi:crypto@0.11.0` WIT interfaces.

## What this crate does

Implements all six `wasi-ephemeral-crypto-*` interfaces as Wasmtime component host functions:

- `wasi-ephemeral-crypto-common` — options, array_output, secrets_manager
- `wasi-ephemeral-crypto-symmetric` — AEAD, hash, MAC, KDF
- `wasi-ephemeral-crypto-signatures` — ECDSA, EdDSA, RSA
- `wasi-ephemeral-crypto-kx` — X25519, Kyber KEM
- `wasi-ephemeral-crypto-asymmetric-common` — shared keypair/publickey/secretkey operations
- `wasi-ephemeral-crypto-external-secrets` — stub (returns `UnsupportedFeature`)

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

- [`../docs/architecture.md`](../docs/architecture.md) — pipeline, resource lifecycle, options system, known gaps
- [`../docs/modules.md`](../docs/modules.md) — per-module algorithm tables and test coverage
