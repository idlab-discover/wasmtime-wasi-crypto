# Modules

Per-module reference for `wasmtime-wasi-crypto`. For the overall pipeline see [`architecture.md`](architecture.md).

---

## Symmetric (`symmetric/`)

**WIT interface:** `wasi-ephemeral-crypto-symmetric`
**Binding impl:** `bindings/symmetric.rs`

### Algorithms

| Algorithm string       | Enum variant        | Backing crate      | Category |
| ---------------------- | ------------------- | ------------------ | -------- |
| `HMAC/SHA-256`         | `HmacSha256`        | `hmac` + `sha2`    | MAC      |
| `HMAC/SHA-512`         | `HmacSha512`        | `hmac` + `sha2`    | MAC      |
| `HKDF-EXTRACT/SHA-256` | `HkdfSha256Extract` | `hkdf`             | KDF      |
| `HKDF-EXTRACT/SHA-512` | `HkdfSha512Extract` | `hkdf`             | KDF      |
| `HKDF-EXPAND/SHA-256`  | `HkdfSha256Expand`  | `hkdf`             | KDF      |
| `HKDF-EXPAND/SHA-512`  | `HkdfSha512Expand`  | `hkdf`             | KDF      |
| `SHA-256`              | `Sha256`            | `sha2`             | Hash     |
| `SHA-384`              | `Sha384`            | `sha2`             | Hash     |
| `SHA-512`              | `Sha512`            | `sha2`             | Hash     |
| `SHA-512/256`          | `Sha512_256`        | `sha2`             | Hash     |
| `AES-128-GCM`          | `Aes128Gcm`         | `aes-gcm`          | AEAD     |
| `AES-256-GCM`          | `Aes256Gcm`         | `aes-gcm`          | AEAD     |
| `CHACHA20-POLY1305`    | `ChaCha20Poly1305`  | `chacha20poly1305` | AEAD     |
| `XCHACHA20-POLY1305`   | `XChaCha20Poly1305` | `chacha20poly1305` | AEAD     |
| `XOODYAK-128`          | `Xoodyak128`        | `xoodyak`          | Hash/MAC |
| `XOODYAK-160`          | `Xoodyak160`        | `xoodyak`          | Hash/MAC |

Algorithm strings are matched case-insensitively via `.to_uppercase()`.

### Options (`SymmetricOptions`)

`SymmetricOptions` wraps an `Arc<Mutex<SymmetricOptionsInner>>` for clone-safe shared access.

| Option name    | Type                | Set via                    |
| -------------- | ------------------- | -------------------------- |
| `context`      | `Vec<u8>`           | `options_set`              |
| `salt`         | `Vec<u8>`           | `options_set`              |
| `nonce`        | `Vec<u8>`           | `options_set`              |
| `buffer`       | `&'static mut [u8]` | `options_set_guest_buffer` |
| `memory_limit` | `u64`               | `options_set_u64`          |
| `ops_limit`    | `u64`               | `options_set_u64`          |
| `parallelism`  | `u64`               | `options_set_u64`          |

### Known gaps

- Optional managed-key functions (`symmetric_key_generate_managed`, `*_store_managed`, `*_replace_managed`, `*_id`, `*_from_id`) return `UnsupportedFeature` -> mirrors WITX reference impl.

---

## Signatures (`signatures/`)

**WIT interface:** `wasi-ephemeral-crypto-signatures`
**Binding impl:** `bindings/signatures.rs`

### Algorithms

| Algorithm string                                   | Enum variant        | Family | Backing crate        |
| -------------------------------------------------- | ------------------- | ------ | -------------------- |
| `ECDSA_P256_SHA256`                                | `ECDSA_P256_SHA256` | ECDSA  | `p256`               |
| `ECDSA_K256_SHA256`                                | `ECDSA_K256_SHA256` | ECDSA  | `k256`               |
| `ECDSA_P384_SHA384`                                | `ECDSA_P384_SHA384` | ECDSA  | `p384`               |
| `ED25519`                                          | `Ed25519`           | EdDSA  | `ed25519-compact`    |
| `RSA_PKCS1_2048_SHA256` .. `RSA_PKCS1_4096_SHA512` | various             | RSA    | `boring` (BoringSSL) |
| `RSA_PSS_2048_SHA256` .. `RSA_PSS_4096_SHA512`     | various             | RSA    | `boring` (BoringSSL) |

Algorithm strings are matched case-insensitively. Note: underscores (`_`) are used as separators, unlike the slash/hyphen conventions used in symmetric.

RSA uses [`boring`](https://docs.rs/boring/latest/boring/) (Rust bindings for BoringSSL) rather than pure-Rust crates.

### Options (`SignatureOptions`)

No options are currently supported. All `options_set` / `options_set_u64` calls return `UnsupportedOption`.

### Known gaps

- Optional managed-keypair functions return `UnsupportedFeature` -> mirrors WITX reference impl.
- `keypair_from_pk_and_sk` validates algorithm compatibility but always returns `NotImplemented` (`keypair.rs:85-100`).

---

## Key Exchange (`key_exchange/`)

**WIT interface:** `wasi-ephemeral-crypto-kx`
**Binding impl:** `bindings/key_exchange.rs`

### Algorithms

| Algorithm string | Enum variant | Type | Backing crate                                  |
| ---------------- | ------------ | ---- | ---------------------------------------------- |
| `X25519`         | `X25519`     | DH   | `ed25519-compact` (x25519 feature)             |
| `KYBER-768`      | `Kyber768`   | KEM  | `pqcrypto-kyber` (optional feature `pqcrypto`) |
| `KYBER-1024`     | `Kyber1024`  | KEM  | `pqcrypto-kyber` (optional feature `pqcrypto`) |

Kyber is behind the `pqcrypto` Cargo feature, which is enabled by default.

### Options (`KxOptions`)

`KxOptionsInner` has a `context` field that is never read -> dead code.
All `options_set` / `options_set_u64` calls return `UnsupportedOption`.

### Known gaps

---

## Asymmetric Common (`asymmetric_common/`)

**WIT interface:** `wasi-ephemeral-crypto-asymmetric-common`
**Binding impl:** `bindings/asymmetric_common.rs`

Provides `PublicKey` and `SecretKey` enums that unify the signature and key-exchange variants:

```
PublicKey  ::= Signature(SignaturePublicKey) | KeyExchange(KxPublicKey)
SecretKey  ::= Signature(SignatureSecretKey) | KeyExchange(KxSecretKey)
```

The top-level `KeyPair` enum (`keypair.rs`) similarly unifies `SignatureKeyPair` and `KxKeyPair`.

### Known gaps

- `keypair_from_pk_and_sk` returns `NotImplemented` (see Signatures section above).
- Optional managed-keypair functions return `UnsupportedFeature`.

---

## Common (`bindings/common.rs`)

**WIT interface:** `wasi-ephemeral-crypto-common`

Implements options lifecycle, `array_output`, and `secrets_manager`.

### `array_output`

`ArrayOutput` is a `Cursor<Vec<u8>>` wrapper. On drop it calls `zeroize()` on the inner buffer via the [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) crate.

`array_output_pull` (WIT) calls `array_output_value.len()` to determine the exact byte count, pre-allocates `vec![0u8; len]`, then passes that buffer to `ArrayOutput::pull`. `pull` checks `buf.len() >= data.len()` before copying, so the Overflow path is never hit for a correctly-sized buffer.

### `secrets_manager`

Both functions (`secrets_manager_open`, `secrets_manager_invalidate`) return `CryptoErrno::UnsupportedFeature`. `SecretsManager` has no backing Rust type and is not mapped in `bindgen!`. This mirrors the WITX reference implementation.

---

## External Secrets (`bindings/external_secrets.rs`)

**WIT interface:** `wasi-ephemeral-crypto-external-secrets`

All functions return `CryptoErrno::UnsupportedFeature`. This interface is fully optional and not implemented.

---

## Test coverage

| Interface                                 | Test component                  | Status  | Notes                                                                                                                                                                |
| ----------------------------------------- | ------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `wasi-ephemeral-crypto-common`            | `wasi-crypto-common`            | Partial | options lifecycle covered; `secrets_manager_*` are `#[should_panic]`                                                                                                 |
| `wasi-ephemeral-crypto-symmetric`         | `wasi-crypto-symmetric`         | Partial | keys, AEAD, hash, MAC, HKDF covered; managed keys `#[should_panic]`                                                                                                  |
| `wasi-ephemeral-crypto-signatures`        | `wasi-crypto-signatures`        | Partial | Ed25519, ECDSA P256/K256/P384, RSA PKCS1/PSS covered; managed keypairs `#[should_panic]`                                                                             |
| `wasi-ephemeral-crypto-kx`                | `wasi-crypto-kx`                | Partial | X25519 DH, keypair/key round-trips, low-order point rejection covered; Kyber KEM `#[should_panic]`                                                                   |
| `wasi-ephemeral-crypto-asymmetric-common` | `wasi-crypto-asymmetric-common` | Partial | keypair/publickey/secretkey lifecycle across Ed25519, ECDSA P256/P384, X25519; `keypair_from_pk_and_sk` expects `NotImplemented`; managed keypairs `#[should_panic]` |
| `wasi-ephemeral-crypto-symmetric`         | `wasi-crypto-in-place`          | Partial | guest-memory regression tests: plain encrypt/decrypt (AEADs, Xoodyak) allocate a separate output buffer, measured via `allocation-counter` and `memory.size`; in-place tests pending |
| `wasi-ephemeral-crypto-external-secrets`  | /                               | Missing | not yet written                                                                                                                                                      |

**Test behavior:**

- Pass: feature implemented and working.
- `#[should_panic]`: optional feature not implemented; host returns `UnsupportedFeature`, guest `.unwrap()` panics as expected.
- Host `todo!()`: incomplete implementation — test fails with "Host implementation feature not yet implemented".

**Test origin:** AI-generated from doctests WITX 0.10, the [wasi-crypto-host-functions](https://github.com/wasm-crypto/wasi-crypto-host-functions) tests, regression tests, and invariants to uphold from the spec. Note that these tests aim to serve as a starting point, not the end all-be-all. These were mostly just generated to catch implementation bugs, but can be used for a more complete system.
