# Architecture

## Structure

```
spec/wit/                        WIT interface definitions (source of truth for bindings)
    │
    ▼
bindings/mod.rs                  bindgen! invocation; maps WIT resources to Rust types
    │
    ▼
bindings/{common,symmetric,      Host trait implementations — the actual logic
         signatures,kx,...}.rs
    │
    ▼
symmetric/, signatures/,         Crypto implementation modules
key_exchange/, asymmetric_common/
```

The `spec/` submodule is the local copy of the WIT spec. The WIT spec itself is a direct, conservative translation of the [WITX 0.10 spec](https://github.com/WebAssembly/wasi-crypto/tree/main/witx/witx-0.10) (see [PR #94](https://github.com/WebAssembly/wasi-crypto/pull/94)).

## Key types (`crypto.rs`)

- `WasiCryptoCtx`: empty marker struct; all runtime state lives in the `ResourceTable`
- `WasiCryptoCtxView<'a>` short-lived view passed to every host function; borrows `ctx`, `table`, and `limits`
- `WasiCryptoView`: trait for the host's store data type; requires `fn crypto(&mut self) -> WasiCryptoCtxView<'_>`
- `add_to_linker`: registers all six interfaces with the Wasmtime `Linker`; see `wasmtime-host/src/host.rs` for a reference integration

## Bindings (`bindings/`)

`bindings/mod.rs` contains the `bindgen!` invocation. Its `with` block maps every WIT resource to its backing Rust type. `SecretsManager` is currently **not mapped** (commented out) — it has no backing Rust type, and all `secrets_manager_*` functions return `CryptoErrno::UnsupportedFeature`.

Each `bindings/*.rs` file implements the generated `Host` trait for `WasiCryptoCtxView<'_>`.

## Options system (`options.rs`)

Options are an optional handle passed to algorithm constructors. Each algorithm family has its own options type implementing `OptionsLike`, wrapped in the `Options` enum:

```
Options::Signatures(SignatureOptions)   — no options currently supported
Options::Symmetric(SymmetricOptions)    — context, salt, nonce, memory_limit, ops_limit, parallelism, guest_buffer
Options::KeyExchange(KxOptions)         — context field exists but is never read (dead code)
```

`options_set_guest_buffer` exists as a deprecated shim — in WITX this was a raw pointer into guest memory; in WIT it falls back to `options_set` with a `list<u8>`. Long-term fix: caller-supplied buffers from WASI 0.3.

## WIT divergences from WITX 0.10

The WIT spec is a conservative translation but a few deviations were unavoidable:

| Area                       | WITX behavior                                          | WIT behavior                                                   |
| -------------------------- | ------------------------------------------------------ | -------------------------------------------------------------- |
| `symmetric-state-decrypt`  | In-place decryption via pointer aliasing               | Separate output buffer; caller passes explicit `out-len: size` |
| `options-set-guest-buffer` | Raw pointer into guest linear memory                   | `list<u8>` stopgap; deprecated in 0.11.0                       |
| `size` type                | `usize` (platform word)                                | `u32`                                                          |
| `version`                  | `u64` constant                                         | `variant` with named cases                                     |
| Batch interfaces           | Defined and broken (also not present in wasmtime impl) | Defined but commented out of `world.wit`                       |

## In-place encryption

WITX 0.10 let a guest pass the same buffer as the input and the output of `symmetric_state_encrypt` and `symmetric_state_decrypt`, so encryption needed no extra guest memory. The WIT functions take a `list<u8>` and return a new `list<u8>`, and the canonical ABI gives the guest no way to say where the result should go:

1. The host lifts the argument into its own copy.
2. To lower the result, the host calls the guest's import `realloc`, which by default allocates a fresh buffer.
3. The guest therefore briefly holds both the input and the output, so its peak memory is about twice the message size. Wasm linear memory never shrinks, so that peak becomes the instance's permanent footprint.

The host alone can't fix this. The `realloc` that places a returned list always belongs to the guest, and a Wasmtime host can't choose where its result goes or write into the argument's memory.

**Guest-side fix.** The `in_place` module (currently in `test-components/wasi-crypto-in-place`) makes the result land in the caller's own buffer. It exports `cabi_import_realloc`, which wit-component uses for import results in preference to `cabi_realloc`. For the duration of one import call, the helpers configure it to hand out the caller's buffer for the single result allocation. By then the host has already copied the argument out, so overwriting it is safe. This is the same technique the wasi_snapshot_preview1 component adapter uses to let `fd_read` read straight into the caller's buffer, and the module mirrors the adapter's structure and names. The wrappers `in_place::encrypt`, `encrypt_detached`, `decrypt` and `decrypt_detached` use no extra guest allocation and cause no memory growth. The copies into and out of the host remain.

Because a component can only have one `cabi_import_realloc`, this fix is a guest-side layer that applications opt into, much like the preview1 adapter, rather than something the host can switch on.

**Host side.** What the host allocates while it encrypts or decrypts is described in [Symmetric encryption buffers](#symmetric-encryption-buffers-symmetric) below.

**Long-term options.** Both would let the guest supply the output buffer without the `realloc` trick:
- the Lazy ABI, with caller-supplied buffers
- a writable-buffer WIT type ([component-model #369](https://github.com/WebAssembly/component-model/issues/369))

The overall problem is tracked in [wasi-crypto #95](https://github.com/WebAssembly/wasi-crypto/issues/95).

## Symmetric encryption buffers (`symmetric/`)

The four encryption functions (`symmetric-state-encrypt`, `-encrypt-detached`, `-decrypt` and `-decrypt-detached`) take their input as a `list<u8>`. Wasmtime lifts that list into an owned `Vec<u8>`, allocated with a capacity equal to its length, and hands it to the host. The `SymmetricStateLike` encrypt and decrypt methods take that `Vec` by value, and each AEAD (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 and Xoodyak) encrypts or decrypts in it and returns the same buffer as its output.

| Operation            | Message-sized host allocations | Why                                                                     |
| -------------------- | ------------------------------ | ----------------------------------------------------------------------- |
| `encrypt`            | 1                              | Appending the tag grows the lifted buffer, which has no spare capacity. |
| `encrypt-detached`   | 0                              | The ciphertext is the input buffer; the tag is separate.                |
| `decrypt`            | 0                              | The tag is split off the end, and the rest is decrypted in place.       |
| `decrypt-detached`   | 0                              | The input buffer is decrypted in place.                                 |

Besides these, a few tag-sized allocations remain: the buffer inside the `SymmetricTag` that both encrypt variants produce, and the tag that `decrypt` splits off its input.

The tag for `encrypt` is reserved only after encrypting, so the buffer freed by that reallocation holds ciphertext, not plaintext. Avoiding the reallocation altogether would require reserving room for the tag while the guest's list is lifted, which the `bindgen!`-generated bindings do not support.

On any failure after the buffer has been modified, and on every failed decryption, the buffer is zeroized before the error is returned. AES-GCM and ChaCha20-Poly1305 verify the tag before decrypting, so a failed decryption never produces plaintext; Xoodyak decrypts before it can verify, and its buffer is zeroized on mismatch.

These numbers are for the host only. Crossing the component boundary still copies the input into the host and the output back into guest memory. The native tests in `symmetric/tests.rs` pin the output bytes of every AEAD (as `insta` snapshots) and assert the exact number of bytes each operation allocates, including the tag-sized allocations.
