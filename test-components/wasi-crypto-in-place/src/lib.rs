//! Guest-memory regression tests for the symmetric encryption APIs.
//!
//! The WIT encryption functions take a `list<u8>` and return a `list<u8>`. Under
//! the canonical ABI the host lifts the argument into its own copy, and then
//! lowers the result by calling the guest's import `realloc` for a fresh buffer.
//! As a result, the guest briefly holds both the input and the output, so peak
//! guest memory is about twice the message size. Wasm linear memory never
//! shrinks, so that peak becomes the instance's permanent footprint.
//!
//! These tests measure that behaviour with a counting global allocator
//! (`allocation-counter`) and by watching `memory.size`, so any change to it
//! (intended or not) shows up as a test failure. Run with `-- --nocapture` to
//! see the measured values.
//!
//! This lives in its own test component because its `#[global_allocator]` (and,
//! later, a custom `cabi_import_realloc`) applies to every import the component
//! makes. Keeping it isolated means the other test components still exercise
//! the default allocation path.

wit_bindgen::generate!({
    world: "imports",
    path: "../../spec/wit",
    with: {
        "wasi:crypto/wasi-ephemeral-crypto-asymmetric-common@0.11.0": generate,
        "wasi:crypto/wasi-ephemeral-crypto-common@0.11.0": generate,
        "wasi:crypto/wasi-ephemeral-crypto-external-secrets@0.11.0": generate,
        "wasi:crypto/wasi-ephemeral-crypto-kx@0.11.0": generate,
        "wasi:crypto/wasi-ephemeral-crypto-signatures@0.11.0": generate,
        "wasi:crypto/wasi-ephemeral-crypto-symmetric@0.11.0": generate,

    },
});

// ==============================================================================
// Measurement
// ==============================================================================

#[cfg(test)]
mod measurement {
    use allocation_counter::AllocationInfo;

    /// What a measured closure cost in guest memory.
    #[derive(Debug)]
    pub struct Measurement {
        /// Heap allocations made while the closure ran, as counted by the
        /// `allocation-counter` global allocator. That includes wit-bindgen's
        /// `cabi_realloc`, which the host calls to place returned lists, since
        /// it goes through the Rust global allocator.
        ///
        /// Every test runs in its own Wasmtime `Store` and wasm32-wasip2 guests
        /// are single-threaded, so this only ever sees the test's own
        /// allocations.
        pub heap: AllocationInfo,
        /// How much linear memory grew, in bytes. Linear memory never shrinks,
        /// so this is the permanent footprint cost of the call.
        pub memory_growth: usize,
    }

    const WASM_PAGE_SIZE: usize = 64 * 1024;

    /// Runs `f` and reports how much guest memory it used.
    ///
    /// `allocation_counter::measure` only accepts closures that return `()`,
    /// so the result is carried out through a local.
    pub fn measure<R>(f: impl FnOnce() -> R) -> (R, Measurement) {
        let pages_before = core::arch::wasm32::memory_size::<0>();
        let mut result = None;
        let heap = allocation_counter::measure(|| result = Some(f()));
        let pages_after = core::arch::wasm32::memory_size::<0>();

        let measurement = Measurement {
            heap,
            memory_growth: (pages_after - pages_before) * WASM_PAGE_SIZE,
        };
        (
            result.expect("measure always runs the closure"),
            measurement,
        )
    }

    /// Prints the measured values for one call.
    pub fn report(label: &str, input: &[u8], output: &[u8], m: &Measurement) {
        let placement = if input.as_ptr_range().contains(&output.as_ptr()) {
            "inside the input buffer"
        } else {
            "separate buffer"
        };
        eprintln!(
            "\n{label}:\n\
             \x20 input:          {:p}, {} bytes\n\
             \x20 output:         {:p}, {} bytes
             \x20 heap peak:      +{} bytes\n\
             \x20 heap total:     {} bytes over {} allocation(s)\n\
             \x20 linear memory:  +{} bytes ({} pages)",
            input.as_ptr(),
            input.len(),
            output.as_ptr(),
            output.len(),
            m.heap.bytes_max,
            m.heap.bytes_total,
            m.heap.count_total,
            m.memory_growth,
            m.memory_growth / WASM_PAGE_SIZE,
        );
    }
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use crate::measurement::{Measurement, measure, report};
    use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, options_open, options_set,
    };
    use crate::wasi::crypto::wasi_ephemeral_crypto_symmetric::*;

    /// Large enough that message-sized buffers stand out clearly from
    /// everything else the harness allocates, and span many wasm pages.
    /// Small enough to stay fast with a debug-built host.
    const MESSAGE_LEN: usize = 4 << 20;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Opens a state for `alg`. The AEADs require an explicit nonce (our host
    /// doesn't generate one), while Xoodyak works without one.
    fn open(alg: &str, key: &SymmetricKey) -> SymmetricState {
        let opts = if alg.starts_with("XOODYAK") {
            None
        } else {
            let opts = options_open(AlgorithmType::Symmetric).expect("options_open failed");
            options_set(&opts, "nonce", &[7u8; 12]).expect("setting nonce failed");
            Some(opts)
        };
        symmetric_state_open(alg, Some(key), opts.as_ref())
            .unwrap_or_else(|e| panic!("symmetric_state_open({alg}) failed: {e:?}"))
    }

    fn message() -> Vec<u8> {
        vec![0x5a; MESSAGE_LEN]
    }

    /// Checks the non-in-place behaviour: the host placed the result in a new,
    /// message-sized guest allocation, separate from the input, so the guest
    /// held both at the same time.
    #[track_caller]
    fn assert_fresh_output_buffer(input: &[u8], output: &[u8], m: &Measurement) {
        let output_len = output.len() as u64;
        assert!(
            !input.as_ptr_range().contains(&output.as_ptr()),
            "output unexpectedly placed inside the input buffer"
        );
        assert!(
            m.heap.bytes_max >= output_len,
            "heap peak should include the whole output buffer: {m:?}"
        );
        // Exactly one message-sized allocation (the output): anything beyond
        // it, such as an extra copy of the message, would push the total past
        // the output size by at least another half message.
        assert!(
            m.heap.bytes_total < output_len + MESSAGE_LEN as u64 / 2,
            "expected only the output buffer to be message-sized: {m:?}"
        );
        // The input was allocated before measuring, so its growth isn't
        // counted. The output needs about MESSAGE_LEN more, minus up to a page
        // of slack left over from growing memory for the input.
        assert!(
            m.memory_growth >= output.len() - 64 * 1024,
            "linear memory should grow by about the output size: {m:?}"
        );
    }

    fn encrypt_baseline(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let state = open(alg, &key);
        let plaintext = message();

        let (ciphertext, m) =
            measure(|| symmetric_state_encrypt(&state, &plaintext).expect("encrypt failed"));

        report(&format!("{alg} encrypt"), &plaintext, &ciphertext, &m);
        let tag_len = symmetric_state_max_tag_len(&state).expect("max_tag_len failed") as usize;
        assert_eq!(ciphertext.len(), MESSAGE_LEN + tag_len);
        assert_fresh_output_buffer(&plaintext, &ciphertext, &m);
    }

    fn decrypt_baseline(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let plaintext = message();
        let ciphertext =
            symmetric_state_encrypt(&open(alg, &key), &plaintext).expect("encrypt failed");
        let state = open(alg, &key);

        let (decrypted, m) = measure(|| {
            symmetric_state_decrypt(&state, &ciphertext, MESSAGE_LEN as _).expect("decrypt failed")
        });

        report(&format!("{alg} decrypt"), &ciphertext, &decrypted, &m);
        assert!(decrypted == plaintext, "decryption did not round-trip");
        assert_fresh_output_buffer(&ciphertext, &decrypted, &m);
    }

    // ── baseline: the plain list-in/list-out API always allocates ────────────
    //
    // Without help from the guest, every call gets a separate output buffer.
    // These must keep holding once opt-in in-place helpers exist: the helpers
    // must only affect calls that go through them.
    //
    // TODO: add in-place counterparts (output inside the input buffer, no
    // message-sized allocation, no memory growth) once the guest-side helper
    // exists.

    #[test]
    fn baseline_encrypt_aes256gcm_allocates_output() {
        encrypt_baseline("AES-256-GCM");
    }

    #[test]
    fn baseline_encrypt_chacha20poly1305_allocates_output() {
        encrypt_baseline("CHACHA20-POLY1305");
    }

    #[test]
    fn baseline_encrypt_xoodyak128_allocates_output() {
        encrypt_baseline("XOODYAK-128");
    }

    #[test]
    fn baseline_decrypt_aes256gcm_allocates_output() {
        decrypt_baseline("AES-256-GCM");
    }

    #[test]
    fn baseline_decrypt_chacha20poly1305_allocates_output() {
        decrypt_baseline("CHACHA20-POLY1305");
    }

    #[test]
    fn baseline_decrypt_xoodyak128_allocates_output() {
        decrypt_baseline("XOODYAK-128");
    }

    #[test]
    fn baseline_encrypt_detached_aes256gcm_allocates_output() {
        let alg = "AES-256-GCM";
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let state = open(alg, &key);
        let plaintext = message();

        let ((ciphertext, _tag), m) = measure(|| {
            symmetric_state_encrypt_detached(&state, &plaintext).expect("encrypt_detached failed")
        });

        report(
            &format!("{alg} encrypt_detached"),
            &plaintext,
            &ciphertext,
            &m,
        );
        assert_eq!(ciphertext.len(), MESSAGE_LEN);
        assert_fresh_output_buffer(&plaintext, &ciphertext, &m);
    }

    #[test]
    fn baseline_decrypt_detached_aes256gcm_allocates_output() {
        let alg = "AES-256-GCM";
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let plaintext = message();
        let (ciphertext, tag) = symmetric_state_encrypt_detached(&open(alg, &key), &plaintext)
            .expect("encrypt_detached failed");
        let raw_tag = symmetric_tag_pull(tag).expect("tag pull failed");
        let state = open(alg, &key);

        let (decrypted, m) = measure(|| {
            symmetric_state_decrypt_detached(&state, &ciphertext, &raw_tag)
                .expect("decrypt_detached failed")
        });

        report(
            &format!("{alg} decrypt_detached"),
            &ciphertext,
            &decrypted,
            &m,
        );
        assert!(decrypted == plaintext, "decryption did not round-trip");
        assert_fresh_output_buffer(&ciphertext, &decrypted, &m);
    }
}
