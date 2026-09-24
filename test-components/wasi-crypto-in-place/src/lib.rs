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
//! The [`in_place`] module prototypes the fix: wrappers that make the host
//! write the result over the input buffer.
//!
//! This lives in its own test component because its `#[global_allocator]` and
//! its `cabi_import_realloc` export apply to every import the component makes.
//! Keeping it isolated means the other test components still exercise the
//! default allocation path.

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
// In-place encryption helpers
// ==============================================================================

/// In-place wrappers around the symmetric encryption imports.
///
/// The WIT functions return a fresh `list<u8>`. To place it in guest memory,
/// the host calls the component's import `realloc`. wit-component uses the core
/// module's `cabi_import_realloc` export for that when there is one, and
/// `cabi_realloc` otherwise. The wrappers configure `cabi_import_realloc` to
/// hand out the caller's buffer for the result's allocation. By then the host
/// has already copied the argument out of guest memory, so the result can
/// safely overwrite the input.
///
/// This only removes the guest's second buffer. The host still copies the
/// input out of guest memory and the result back in.
///
/// # Relation to the wasi_snapshot_preview1 component adapter
///
/// The machinery mirrors the adapter's `ImportAlloc` / `BumpAlloc` /
/// `with_one_import_alloc` (wasmtime `crates/wasi-preview1-component-adapter`),
/// which uses it to let `fd_read` read directly into the caller's buffer. Names
/// and structure are kept the same so the two can be compared side by side.
/// The deliberate differences:
///
/// - Only the `OneAlloc` flavour exists. The adapter's other flavours serve
///   string lists (arguments, environment, preopens), which wasi-crypto has no
///   use for.
/// - `ImportAlloc::None` passes the allocation through to the default
///   allocator instead of aborting. The adapter is the only caller of its own
///   imports, but our `cabi_import_realloc` also serves the WASI imports that
///   std makes.
/// - The adapter's handling of a non-null `old_ptr` (a string shrink during
///   transcoding) is omitted: a `list<u8>` is never transcoded, and applying
///   that hack to std's own strings would corrupt its heap. Such calls go to
///   the default allocator.
///
/// TODO: move this into a reusable guest crate once the API has settled.
/// TODO: replace it with the Lazy ABI's caller-supplied buffers, or a
/// writable-buffer WIT type (component-model#369), once either exists.
pub mod in_place {
    use std::cell::Cell;
    use std::mem::forget;

    use crate::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno;
    use crate::wasi::crypto::wasi_ephemeral_crypto_symmetric::*;

    // ── import allocation (mirrors the adapter) ──────────────────────────────

    thread_local! {
        /// Used to coordinate allocations of `cabi_import_realloc`. This is the
        /// adapter's `State::import_alloc`.
        static IMPORT_ALLOC: Cell<ImportAlloc> = const { Cell::new(ImportAlloc::None) };
    }

    /// The `realloc` the host calls to allocate lists returned by imports.
    ///
    /// # Safety
    ///
    /// Only the canonical ABI should call this, with the arguments of a
    /// `realloc` call.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cabi_import_realloc(
        old_ptr: *mut u8,
        old_size: usize,
        align: usize,
        new_size: usize,
    ) -> *mut u8 {
        let mut alloc = IMPORT_ALLOC.replace(ImportAlloc::None);
        // SAFETY: forwarded unchanged from the canonical ABI's call.
        let ptr = unsafe { alloc.alloc(old_ptr, old_size, align, new_size) };
        IMPORT_ALLOC.set(alloc);
        ptr
    }

    /// Different ways that calling imports can allocate memory. This is
    /// configured whenever an import is called that may invoke
    /// `cabi_import_realloc`.
    enum ImportAlloc {
        /// A single allocation from the provided `BumpAlloc` is supported.
        /// After the single allocation is performed, all future allocations go
        /// to the default allocator (see `None`).
        OneAlloc(BumpAlloc),

        /// No import allocator is configured. Unlike in the adapter, this is
        /// the normal state: std's own imports allocate through here too.
        None,
    }

    impl ImportAlloc {
        /// To be used by `cabi_import_realloc` only!
        unsafe fn alloc(
            &mut self,
            old_ptr: *mut u8,
            old_size: usize,
            align: usize,
            size: usize,
        ) -> *mut u8 {
            if !old_ptr.is_null() {
                // SAFETY: forwarded unchanged from the canonical ABI's call.
                return unsafe { default_realloc(old_ptr, old_size, align, size) };
            }
            match self {
                ImportAlloc::OneAlloc(alloc) => unsafe {
                    let ret = alloc.alloc(align, size);
                    *self = ImportAlloc::None;
                    ret
                },
                // SAFETY: forwarded unchanged from the canonical ABI's call.
                ImportAlloc::None => unsafe { default_realloc(old_ptr, old_size, align, size) },
            }
        }
    }

    /// Helper type to manage allocations from a `base`/`len` combo. Identical
    /// to the adapter's.
    #[derive(Clone)]
    struct BumpAlloc {
        base: *mut u8,
        len: usize,
    }

    impl BumpAlloc {
        unsafe fn alloc(&mut self, align: usize, size: usize) -> *mut u8 {
            unsafe {
                self.align_to(align);
            }
            if size > self.len {
                unreachable!("allocation size is too large")
            }
            self.len -= size;
            let ret = self.base;
            self.base = unsafe { ret.add(size) };
            ret
        }

        unsafe fn align_to(&mut self, align: usize) {
            if !align.is_power_of_two() {
                unreachable!("invalid alignment");
            }
            let align_offset = self.base.align_offset(align);
            if align_offset > self.len {
                unreachable!("failed to allocate")
            }
            self.len -= align_offset;
            self.base = unsafe { self.base.add(align_offset) };
        }
    }

    /// Configure that `cabi_import_realloc` will allocate once from `base`
    /// with at most `len` bytes for the duration of `f`.
    ///
    /// Panics if the import allocator is already configured.
    fn with_one_import_alloc<T>(base: *mut u8, len: usize, f: impl FnOnce() -> T) -> T {
        let alloc = BumpAlloc { base, len };
        with_import_alloc(ImportAlloc::OneAlloc(alloc), f).0
    }

    /// Configures the `alloc` specified to be the allocator for
    /// `cabi_import_realloc` for the duration of `f`.
    ///
    /// Panics if the import allocator is already configured.
    fn with_import_alloc<T>(alloc: ImportAlloc, f: impl FnOnce() -> T) -> (T, ImportAlloc) {
        match IMPORT_ALLOC.replace(alloc) {
            ImportAlloc::None => {}
            _ => unreachable!("import allocator already set"),
        }
        let r = f();
        let alloc = IMPORT_ALLOC.replace(ImportAlloc::None);
        (r, alloc)
    }

    /// The allocation path for everything not served by a configured
    /// `ImportAlloc`. This is the same logic as the default `cabi_realloc`
    /// (Rust std's on wasm32-wasip2, and wit-bindgen's `rt::cabi_realloc`
    /// elsewhere), on top of the global allocator. The adapter has no
    /// equivalent because it never needs one (see `ImportAlloc::None`).
    ///
    /// It isn't implemented by calling `cabi_realloc` because declaring that
    /// symbol makes the linker pull in wit-bindgen's weak C shim for it, and
    /// the Rust half of that shim isn't compiled on wasm32-wasip2.
    ///
    /// # Safety
    ///
    /// Same contract as a canonical ABI `realloc` call.
    unsafe fn default_realloc(
        old_ptr: *mut u8,
        old_len: usize,
        align: usize,
        new_len: usize,
    ) -> *mut u8 {
        use std::alloc::{Layout, alloc, handle_alloc_error, realloc};

        if old_len == 0 && new_len == 0 {
            // Zero-sized allocations need no memory, only a well-aligned
            // pointer.
            return align as *mut u8;
        }
        // SAFETY: the canonical ABI passes a power-of-two `align`, and a
        // non-zero `old_len` means `old_ptr` came from an earlier call here
        // with that same layout.
        let (ptr, layout) = unsafe {
            if old_len == 0 {
                let layout = Layout::from_size_align_unchecked(new_len, align);
                (alloc(layout), layout)
            } else {
                let layout = Layout::from_size_align_unchecked(old_len, align);
                (realloc(old_ptr, layout, new_len), layout)
            }
        };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        ptr
    }

    // ── in-place calls ───────────────────────────────────────────────────────

    /// Calls `import` with the contents of `buf`, arranging for the returned
    /// list to be written into `buf`'s own allocation. On success `buf` holds
    /// the result. This follows the adapter's `fd_read`: configure a single
    /// import allocation over the caller's buffer, call the import, check the
    /// result landed there, and `forget` the `Vec` the bindings built over it.
    ///
    /// On error `buf` is left untouched: the host only allocates, and therefore
    /// only writes, on the success path.
    ///
    /// Like the adapter, this traps if the result doesn't fit in `buf`'s
    /// capacity. The wrappers below always reserve enough.
    pub fn call_in_place<E>(
        buf: &mut Vec<u8>,
        import: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<(), E> {
        let (len, capacity) = (buf.len(), buf.capacity());
        let ptr = buf.as_mut_ptr();

        // The host writes into this memory during the call, while `input` is
        // still borrowed. Rust can't observe that: the write happens on the far
        // side of an opaque import call, after the canonical ABI has finished
        // reading the argument, and `input` is never read again. The adapter
        // doesn't face this, because `fd_read`'s buffer is output-only.
        // TODO: calling the core wasm import directly with a raw pointer and
        // length would avoid holding a shared reference to memory that gets
        // written, at the cost of hand-written ABI glue.
        // SAFETY: `ptr` and `len` describe `buf`'s initialised contents, and
        // `buf` isn't touched until `input` is dead.
        let input = unsafe { std::slice::from_raw_parts(ptr, len) };
        let output = with_one_import_alloc(ptr, capacity, || import(input))?;

        // The same checks as the adapter's `fd_read`.
        assert!(output.is_empty() || output.as_ptr() == ptr);
        assert!(output.len() <= capacity);

        // wit-bindgen built `output` with `Vec::from_raw_parts`, so it claims
        // to own `buf`'s allocation, with the wrong capacity. Forget it so that
        // `buf` stays the only owner.
        let output_len = output.len();
        forget(output);
        // SAFETY: the host just initialised `output_len` bytes at `ptr`, and
        // the assert above checked that fits in `buf`'s capacity.
        unsafe { buf.set_len(output_len) };
        Ok(())
    }

    /// Encrypts `buf` in place and appends the tag.
    ///
    /// This reserves `symmetric_state_max_tag_len()` bytes of spare capacity
    /// first. Allocate `buf` with that room up front to avoid a reallocation.
    pub fn encrypt(state: &SymmetricState, buf: &mut Vec<u8>) -> Result<(), CryptoErrno> {
        let tag_len = symmetric_state_max_tag_len(state)? as usize;
        buf.reserve_exact(tag_len);
        call_in_place(buf, |input| symmetric_state_encrypt(state, input))
    }

    /// Encrypts `buf` in place and returns the tag separately.
    pub fn encrypt_detached(
        state: &SymmetricState,
        buf: &mut Vec<u8>,
    ) -> Result<SymmetricTag, CryptoErrno> {
        let mut tag = None;
        call_in_place(buf, |input| {
            let (output, t) = symmetric_state_encrypt_detached(state, input)?;
            tag = Some(t);
            Ok(output)
        })?;
        Ok(tag.expect("set whenever the call succeeds"))
    }

    /// Decrypts `buf` (ciphertext followed by the tag) in place. On success
    /// `buf` holds just the plaintext.
    pub fn decrypt(state: &SymmetricState, buf: &mut Vec<u8>) -> Result<(), CryptoErrno> {
        let tag_len = symmetric_state_max_tag_len(state)? as usize;
        // A buffer shorter than the tag can't be valid. Passing 0 lets the host
        // reject it with its usual error instead of us inventing one.
        let out_len = buf.len().saturating_sub(tag_len);
        call_in_place(buf, |input| symmetric_state_decrypt(state, input, out_len as _))
    }

    /// Decrypts `buf` in place, checking it against the detached `raw_tag`.
    pub fn decrypt_detached(
        state: &SymmetricState,
        buf: &mut Vec<u8>,
        raw_tag: &[u8],
    ) -> Result<(), CryptoErrno> {
        call_in_place(buf, |input| symmetric_state_decrypt_detached(state, input, raw_tag))
    }
}

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
    ///
    /// The input is passed as a pointer and length, because in-place calls
    /// overwrite it and it may no longer exist as a separate slice afterwards.
    pub fn report(
        label: &str,
        input_ptr: *const u8,
        input_len: usize,
        output: &[u8],
        m: &Measurement,
    ) {
        eprintln!(
            "\n{label}:\n\
             \x20 input:          {:p}, {} bytes\n\
             \x20 output:         {:p}, {} bytes\n\
             \x20 heap peak:      +{} bytes\n\
             \x20 heap total:     {} bytes over {} allocation(s)\n\
             \x20 linear memory:  +{} bytes ({} pages)",
            input_ptr,
            input_len,
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
    use crate::in_place;
    use crate::measurement::{Measurement, measure, report};
    use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, options_open, options_set,
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

    /// Returns `(plaintext, ciphertext)` for `message()` under `key`. Both stay
    /// alive, so setting them up leaves no freed message-sized heap block
    /// behind that a measured call could reuse without growing memory.
    fn encrypted_message(alg: &str, key: &SymmetricKey) -> (Vec<u8>, Vec<u8>) {
        let plaintext = message();
        let ciphertext =
            symmetric_state_encrypt(&open(alg, key), &plaintext).expect("encrypt failed");
        (plaintext, ciphertext)
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

        report(&format!("{alg} encrypt"), plaintext.as_ptr(), plaintext.len(), &ciphertext, &m);
        let tag_len = symmetric_state_max_tag_len(&state).expect("max_tag_len failed") as usize;
        assert_eq!(ciphertext.len(), MESSAGE_LEN + tag_len);
        assert_fresh_output_buffer(&plaintext, &ciphertext, &m);
    }

    fn decrypt_baseline(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let (plaintext, ciphertext) = encrypted_message(alg, &key);
        let state = open(alg, &key);

        let (decrypted, m) = measure(|| {
            symmetric_state_decrypt(&state, &ciphertext, MESSAGE_LEN as _).expect("decrypt failed")
        });

        report(&format!("{alg} decrypt"), ciphertext.as_ptr(), ciphertext.len(), &decrypted, &m);
        assert!(decrypted == plaintext, "decryption did not round-trip");
        assert_fresh_output_buffer(&ciphertext, &decrypted, &m);
    }

    // ── baseline: the plain list-in/list-out API always allocates ────────────
    //
    // Without help from the guest, every call gets a separate output buffer.
    // These must keep holding once opt-in in-place helpers exist: the helpers
    // must only affect calls that go through them.

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

        report(&format!("{alg} encrypt_detached"), plaintext.as_ptr(), plaintext.len(), &ciphertext, &m);
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

        report(&format!("{alg} decrypt_detached"), ciphertext.as_ptr(), ciphertext.len(), &decrypted, &m);
        assert!(decrypted == plaintext, "decryption did not round-trip");
        assert_fresh_output_buffer(&ciphertext, &decrypted, &m);
    }

    // ── in place: the helpers write the result over the input ───────────────

    /// A message-sized buffer with room for the tag, as a caller that plans to
    /// encrypt in place would allocate it.
    fn message_with_tag_room(state: &SymmetricState) -> Vec<u8> {
        let tag_len = symmetric_state_max_tag_len(state).expect("max_tag_len failed") as usize;
        let mut buf = Vec::with_capacity(MESSAGE_LEN + tag_len);
        buf.resize(MESSAGE_LEN, 0x5a);
        buf
    }

    /// Checks the in-place behaviour: the result sits at the start of the
    /// input's allocation, the guest never allocated a message-sized buffer,
    /// and linear memory didn't grow at all.
    #[track_caller]
    fn assert_in_place(input_ptr: *const u8, output: &[u8], m: &Measurement) {
        assert_eq!(
            output.as_ptr(),
            input_ptr,
            "output should start at the input buffer"
        );
        assert!(
            m.heap.bytes_total < MESSAGE_LEN as u64 / 2,
            "no message-sized allocation expected: {m:?}"
        );
        assert_eq!(m.memory_growth, 0, "linear memory should not grow: {m:?}");
    }

    fn encrypt_in_place(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let state = open(alg, &key);
        let mut buf = message_with_tag_room(&state);
        let (input_ptr, input_len) = (buf.as_ptr(), buf.len());

        let ((), m) = measure(|| in_place::encrypt(&state, &mut buf).expect("encrypt failed"));

        report(&format!("{alg} encrypt in place"), input_ptr, input_len, &buf, &m);
        assert_in_place(input_ptr, &buf, &m);
        // Same key and nonce, so the plain API must produce the same bytes.
        let expected =
            symmetric_state_encrypt(&open(alg, &key), &message()).expect("encrypt failed");
        assert!(buf == expected, "in-place ciphertext differs from the plain API's");
    }

    fn decrypt_in_place(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let (plaintext, mut buf) = encrypted_message(alg, &key);
        let state = open(alg, &key);
        let (input_ptr, input_len) = (buf.as_ptr(), buf.len());

        let ((), m) = measure(|| in_place::decrypt(&state, &mut buf).expect("decrypt failed"));

        report(&format!("{alg} decrypt in place"), input_ptr, input_len, &buf, &m);
        assert_in_place(input_ptr, &buf, &m);
        assert!(buf == plaintext, "decryption did not round-trip");
    }

    #[test]
    fn in_place_encrypt_aes256gcm() {
        encrypt_in_place("AES-256-GCM");
    }

    #[test]
    fn in_place_encrypt_chacha20poly1305() {
        encrypt_in_place("CHACHA20-POLY1305");
    }

    #[test]
    fn in_place_encrypt_xoodyak128() {
        encrypt_in_place("XOODYAK-128");
    }

    #[test]
    fn in_place_decrypt_aes256gcm() {
        decrypt_in_place("AES-256-GCM");
    }

    #[test]
    fn in_place_decrypt_chacha20poly1305() {
        decrypt_in_place("CHACHA20-POLY1305");
    }

    #[test]
    fn in_place_decrypt_xoodyak128() {
        decrypt_in_place("XOODYAK-128");
    }

    #[test]
    fn in_place_detached_aes256gcm_round_trip() {
        let alg = "AES-256-GCM";
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let mut buf = message();
        let (input_ptr, input_len) = (buf.as_ptr(), buf.len());

        let state = open(alg, &key);
        let (tag, m) = measure(|| {
            in_place::encrypt_detached(&state, &mut buf).expect("encrypt_detached failed")
        });
        report(&format!("{alg} encrypt_detached in place"), input_ptr, input_len, &buf, &m);
        assert_in_place(input_ptr, &buf, &m);
        let raw_tag = symmetric_tag_pull(tag).expect("tag pull failed");

        let state = open(alg, &key);
        let ((), m) = measure(|| {
            in_place::decrypt_detached(&state, &mut buf, &raw_tag)
                .expect("decrypt_detached failed")
        });
        report(&format!("{alg} decrypt_detached in place"), input_ptr, input_len, &buf, &m);
        assert_in_place(input_ptr, &buf, &m);
        assert!(buf == message(), "decryption did not round-trip");
    }

    #[test]
    fn in_place_encrypt_empty_message() {
        let alg = "AES-256-GCM";
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let state = open(alg, &key);
        let mut buf = Vec::new();

        in_place::encrypt(&state, &mut buf).expect("encrypt failed");

        let expected = symmetric_state_encrypt(&open(alg, &key), &[]).expect("encrypt failed");
        assert_eq!(buf, expected);
    }

    // ── comparison: in place against the plain API, in one setup ────────────
    //
    // The checks above bound each API against fixed thresholds in separate
    // tests. These run both versions of one operation in the same test, with
    // every input allocated before either call is measured, and check that
    // the in-place helper saved at least a message's worth of guest memory.
    //
    // The in-place call is measured first. Measured second, it could reuse
    // heap the plain call had freed, hiding growth it would otherwise cause.

    /// Checks that `in_place` needed at least one message-sized buffer less
    /// than `plain`, both at the heap peak and in linear memory growth.
    #[track_caller]
    fn assert_saves_a_message(in_place: &Measurement, plain: &Measurement) {
        assert!(
            in_place.heap.bytes_max + MESSAGE_LEN as u64 <= plain.heap.bytes_max,
            "in-place heap peak should be at least a message below the plain API's:\n\
             in place: {in_place:?}\n\
             plain:    {plain:?}"
        );
        // Up to a page of slack, as in `assert_fresh_output_buffer`: growing
        // memory for the inputs can leave part of a page free for the output.
        assert!(
            in_place.memory_growth + MESSAGE_LEN - 64 * 1024 <= plain.memory_growth,
            "in-place memory growth should be at least a message below the plain API's:\n\
             in place: {in_place:?}\n\
             plain:    {plain:?}"
        );
    }

    fn compare_encrypt(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let (in_place_state, plain_state) = (open(alg, &key), open(alg, &key));
        let mut buf = message_with_tag_room(&in_place_state);
        let plaintext = message();
        let (input_ptr, input_len) = (buf.as_ptr(), buf.len());

        let ((), in_place_m) =
            measure(|| in_place::encrypt(&in_place_state, &mut buf).expect("encrypt failed"));
        let (ciphertext, plain_m) =
            measure(|| symmetric_state_encrypt(&plain_state, &plaintext).expect("encrypt failed"));

        report(&format!("{alg} encrypt in place (compared)"), input_ptr, input_len, &buf, &in_place_m);
        report(&format!("{alg} encrypt plain (compared)"), plaintext.as_ptr(), plaintext.len(), &ciphertext, &plain_m);
        assert!(buf == ciphertext, "in-place ciphertext differs from the plain API's");
        assert_saves_a_message(&in_place_m, &plain_m);
    }

    fn compare_decrypt(alg: &str) {
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let (plaintext, ciphertext) = encrypted_message(alg, &key);
        let mut buf = ciphertext.clone();
        let (in_place_state, plain_state) = (open(alg, &key), open(alg, &key));
        let (input_ptr, input_len) = (buf.as_ptr(), buf.len());

        let ((), in_place_m) =
            measure(|| in_place::decrypt(&in_place_state, &mut buf).expect("decrypt failed"));
        let (decrypted, plain_m) = measure(|| {
            symmetric_state_decrypt(&plain_state, &ciphertext, MESSAGE_LEN as _)
                .expect("decrypt failed")
        });

        report(&format!("{alg} decrypt in place (compared)"), input_ptr, input_len, &buf, &in_place_m);
        report(&format!("{alg} decrypt plain (compared)"), ciphertext.as_ptr(), ciphertext.len(), &decrypted, &plain_m);
        assert!(buf == plaintext && decrypted == plaintext, "decryption did not round-trip");
        assert_saves_a_message(&in_place_m, &plain_m);
    }

    #[test]
    fn compare_encrypt_aes256gcm() {
        compare_encrypt("AES-256-GCM");
    }

    #[test]
    fn compare_encrypt_chacha20poly1305() {
        compare_encrypt("CHACHA20-POLY1305");
    }

    #[test]
    fn compare_encrypt_xoodyak128() {
        compare_encrypt("XOODYAK-128");
    }

    #[test]
    fn compare_decrypt_aes256gcm() {
        compare_decrypt("AES-256-GCM");
    }

    #[test]
    fn compare_decrypt_chacha20poly1305() {
        compare_decrypt("CHACHA20-POLY1305");
    }

    #[test]
    fn compare_decrypt_xoodyak128() {
        compare_decrypt("XOODYAK-128");
    }

    // TODO: compare the detached variants too. They are only measured against
    // fixed thresholds, in `baseline_*_detached_*` and
    // `in_place_detached_aes256gcm_round_trip`.

    // TODO: test that `call_in_place` traps when the result doesn't fit in the
    // buffer's capacity (the adapter's `BumpAlloc` behaviour). Guests build
    // with panic=abort, so `#[should_panic]` can't express this, and the
    // runner has no notion of an expected guest trap yet.

    #[test]
    fn in_place_decrypt_failure_leaves_buffer_untouched() {
        let alg = "AES-256-GCM";
        let key = symmetric_key_generate(alg, None).expect("key generation failed");
        let mut buf =
            symmetric_state_encrypt(&open(alg, &key), &message()).expect("encrypt failed");
        *buf.last_mut().expect("ciphertext includes a tag") ^= 1;
        let corrupted = buf.clone();

        let result = in_place::decrypt(&open(alg, &key), &mut buf);

        assert!(
            matches!(result, Err(CryptoErrno::InvalidTag)),
            "expected InvalidTag, got {result:?}"
        );
        assert!(buf == corrupted, "a failed decrypt must not modify the buffer");

        // The import allocator was never used, and must have been reset to
        // `None` anyway: a plain call afterwards still gets a separate buffer.
        let plaintext = message();
        let ciphertext =
            symmetric_state_encrypt(&open(alg, &key), &plaintext).expect("encrypt failed");
        assert!(!buf.as_ptr_range().contains(&ciphertext.as_ptr()));
    }
}
