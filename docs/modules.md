# Modules

Per-module reference for `wasmtime-wasi-crypto`. For the overall pipeline see [`architecture.md`](architecture.md).

---

## Symmetric (`symmetric/`)

**WIT interfaces:** `symmetric`, `symmetric-managed`
**Binding impl:** `bindings/symmetric.rs`, `bindings/symmetric_managed.rs`

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

### Options (`symmetric-options` / `SymmetricOptions`)

`SymmetricOptions` wraps an `Arc<Mutex<SymmetricOptionsInner>>` for clone-safe shared access.

| Option name    | Type                | Set via            |
| -------------- | ------------------- | ------------------ |
| `context`      | `Vec<u8>`           | `set`              |
| `salt`         | `Vec<u8>`           | `set`              |
| `nonce`        | `Vec<u8>`           | `set`              |
| `buffer`       | `&'static mut [u8]` | `set-guest-buffer` |
| `memory_limit` | `u64`               | `set-u64`          |
| `ops_limit`    | `u64`               | `set-u64`          |
| `parallelism`  | `u64`               | `set-u64`          |

### Known gaps

- The optional `symmetric-managed` functions (`generate-managed`, `store-managed`, `replace-managed`, `id`, `from-id`) return `UnsupportedFeature` -> mirrors WITX reference impl.

---

## Signatures (`signatures/`)

**WIT interfaces:** `signatures`, `signatures-managed`
**Binding impl:** `bindings/signatures.rs`, `bindings/signatures_managed.rs`

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

### Key types

| WIT resource          | Rust type            | File                      |
| --------------------- | -------------------- | ------------------------- |
| `signature-keypair`   | `SignatureKeyPair`   | `signatures/keypair.rs`   |
| `signature-publickey` | `SignaturePublicKey` | `signatures/publickey.rs` |
| `signature-secretkey` | `SignatureSecretKey` | `signatures/secretkey.rs` |

Each is an enum over the ECDSA, EdDSA and RSA implementations. A key's family is fixed by its type, so signature keys can't be passed to key-exchange functions.

### Options (`signature-options` / `SignatureOptions`)

No options are currently supported. All `set` / `set-u64` calls return `UnsupportedOption`.

### Known gaps

- The optional `signatures-managed` functions return `UnsupportedFeature` -> mirrors WITX reference impl.
- `signature-keypair.from-pk-and-sk` validates algorithm compatibility but always returns `NotImplemented` (`SignatureKeyPair::from_pk_and_sk`).

---

## Key Exchange (`key_exchange/`)

**WIT interfaces:** `kx`, `kx-managed`
**Binding impl:** `bindings/kx.rs`, `bindings/kx_managed.rs`

### Algorithms

| Algorithm string | Enum variant | Type | Backing crate                          |
| ---------------- | ------------ | ---- | -------------------------------------- |
| `X25519`         | `X25519`     | DH   | `ed25519-compact` (x25519 feature)     |
| `ML-KEM-512`     | `MlKem512`   | KEM  | `ml-kem` (optional feature `pqcrypto`) |
| `ML-KEM-768`     | `MlKem768`   | KEM  | `ml-kem` (optional feature `pqcrypto`) |
| `ML-KEM-1024`    | `MlKem1024`  | KEM  | `ml-kem` (optional feature `pqcrypto`) |
| `X-WING`         | `XWing`      | KEM  | `x-wing` (optional feature `pqcrypto`) |

ML-KEM and X-Wing are behind the `pqcrypto` Cargo feature, which is enabled by default.

### Key types

| WIT resource   | Rust type     | File                        |
| -------------- | ------------- | --------------------------- |
| `kx-keypair`   | `KxKeyPair`   | `key_exchange/keypair.rs`   |
| `kx-publickey` | `KxPublicKey` | `key_exchange/publickey.rs` |
| `kx-secretkey` | `KxSecretKey` | `key_exchange/secretkey.rs` |

Diffie-Hellman is a method on the secret key (`sk.dh(peer_pk)`). KEMs use `kx-publickey.encapsulate` and `kx-secretkey.decapsulate`. A key's family is fixed by its type, so key-exchange keys can't be passed to signature functions.

### Options (`kx-options` / `KxOptions`)

`KxOptionsInner` has a `context` field that is never read -> dead code.
All `set` / `set-u64` calls return `UnsupportedOption`.

### Known gaps

- `kx-keypair.import` returns `InvalidOperation`: there is no `KxKeyPair::import`.
- `kx-keypair.from-pk-and-sk` validates algorithm compatibility but always returns `NotImplemented` (`KxKeyPair::from_pk_and_sk`).
- The optional `kx-managed` functions return `UnsupportedFeature`.

---

## Common (`bindings/common.rs`)

**WIT interface:** `common`

Implements `array-output`. The interface also declares the types shared by several families (`crypto-errno`, the key encodings, `version`, ...).

### `array-output`

`ArrayOutput` is a `Cursor<Vec<u8>>` wrapper. On drop it calls `zeroize()` on the inner buffer via the [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) crate.

`array-output.pull` (WIT) calls `array_output_value.len()` to determine the exact byte count, pre-allocates `vec![0u8; len]`, then passes that buffer to `ArrayOutput::pull`. `pull` checks `buf.len() >= data.len()` before copying, so the Overflow path is never hit for a correctly-sized buffer.

---

## Secrets manager (`bindings/secrets_manager.rs`, `secrets_manager.rs`)

**WIT interface:** `secrets-manager`

`secrets-manager.open` and `invalidate` return `CryptoErrno::UnsupportedFeature`. The `secrets-manager` resource has no backing Rust type and is not mapped in `bindgen!`. This mirrors the WITX reference implementation. `secrets-manager-options` is backed by an empty `SecretsManagerOptions`; no option names exist, so its setters return `UnsupportedOption`.

---

## External Secrets (`bindings/external_secrets.rs`)

**WIT interface:** `external-secrets`

All functions return `CryptoErrno::UnsupportedFeature`. This interface is fully optional and not implemented.

---

## Test coverage

Each test component declares a world that imports only the interfaces it tests, so it can run against a host that provides just those interfaces.

| Interface            | Test component                | Status  | Notes                                                                                                                                                                                                                                                      |
| -------------------- | ----------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `common`             | `wasi-crypto-common`          | Covered | `array-output` `len` and `pull`; also imports `symmetric`, because only a family interface can produce an `array-output`                                                                                                                                   |
| `secrets-manager`    | `wasi-crypto-secrets-manager` | Partial | `open` must return `UnsupportedFeature`; the `invalidate` scenarios only run once a secrets manager exists                                                                                                                                                 |
| `symmetric`          | `wasi-crypto-symmetric`       | Partial | options, keys, AEAD, hash, MAC, HKDF covered                                                                                                                                                                                                               |
| `symmetric-managed`  | `wasi-crypto-symmetric`       | Partial | `id` of an unmanaged key returns `UnsupportedFeature`; the other managed-key scenarios only run once a secrets manager exists                                                                                                                              |
| `signatures`         | `wasi-crypto-signatures`      | Partial | options; Ed25519, ECDSA P256/K256/P384, RSA PKCS1/PSS covered; key import/export round trips and errors; `signature-secretkey.import` expects `NotImplemented`                                                                                             |
| `signatures-managed` | `wasi-crypto-signatures`      | Partial | the managed-keypair scenario only runs once a secrets manager exists                                                                                                                                                                                       |
| `kx`                 | `wasi-crypto-kx`              | Partial | options; X25519 DH, key round-trips, low-order point rejection; ML-KEM and X-Wing encapsulation and key round-trips; `IncompatibleKeys` for mismatched algorithms in `dh` and `from-pk-and-sk`; `kx-keypair.import` and `from-pk-and-sk` not implemented   |
| `kx-managed`         | /                             | Missing | not yet written                                                                                                                                                                                                                                            |
| `symmetric`          | `wasi-crypto-in-place`        | Partial | guest-memory regression tests: plain encrypt/decrypt (AEADs, Xoodyak) allocate a separate output buffer, measured via `allocation-counter` and `memory.size`; `in_place` helpers write the result over the input with no guest allocation or memory growth |
| `symmetric`          | native: `symmetric/tests.rs`  | Partial | AEADs only (AES-GCM, (X)ChaCha20-Poly1305, Xoodyak): `insta` known-answer snapshots of ciphertext and tags, round-trip and tampered-tag checks, and host allocation counts per encrypt/decrypt operation                                                   |
| `external-secrets`   | /                             | Missing | not yet written                                                                                                                                                                                                                                            |

**Test behavior:**

- Pass: feature implemented and working.
- Pass, asserting `UnsupportedFeature`: optional feature not implemented; the test checks for exactly that error. `#[should_panic]` doesn't work for this: on `wasm32-wasip2`, libtest ignores such tests without running them, and the runner reports the ignored test as passed.
- Host `todo!()`: incomplete implementation; the test fails with "Host implementation feature not yet implemented".

**Native host tests:** `wasmtime-wasi-crypto` also has ordinary unit tests (`cargo test -p wasmtime-wasi-crypto`) that call the host implementation directly, without a guest. They cover what a component test can't observe, such as exact output bytes (`insta` snapshots, reviewed with `cargo insta review`) and host allocations.

**Test origin:** AI-generated from doctests WITX 0.10, the [wasi-crypto-host-functions](https://github.com/wasm-crypto/wasi-crypto-host-functions) tests, regression tests, and invariants to uphold from the spec. Note that these tests aim to serve as a starting point, not the end all-be-all. These were mostly just generated to catch implementation bugs, but can be used for a more complete system.
