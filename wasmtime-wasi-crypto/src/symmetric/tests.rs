// ==============================================================================
// Known-answer tests for the AEAD encrypt/decrypt family
// ==============================================================================
//
// These tests pin the exact ciphertext and tag bytes that every AEAD produces
// for a fixed key, nonce, additional data and message. They exist so that
// changes to *how* the host encrypts (for example, encrypting in the buffer it
// already owns instead of a copy) can be proven not to change *what* it
// produces. The guest-side in-place tests can't catch that: they compare the
// in-place helpers against the plain API, and both would change together.
//
// The snapshots were recorded from the implementation as it was before the
// in-place rework, so a snapshot diff means the output bytes changed.
//
// Every operation opens a fresh state, because the AEAD states consume their
// nonce on encryption and Xoodyak's duplex state advances with every call.

use super::{SymmetricKey, SymmetricOptions, SymmetricState, SymmetricTag};
use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, error::CryptoResult,
    limits::Limits, options::OptionsLike,
};

const AD: &[u8] = b"wasi-crypto known-answer test additional data";

// 62 bytes: not a multiple of the 16-byte AES/Poly1305 block nor of the
// 24-byte Xoodyak squeeze rate, so the final partial block is exercised.
const MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog, twice over again.";

/// Describes one algorithm under test: its name and the lengths of the
/// deterministic key and nonce to derive for it.
struct Case {
    alg: &'static str,
    key_len: usize,
    nonce_len: usize,
}

/// The bytes a snapshot pins, hex-encoded for a readable diff.
#[derive(Debug)]
#[allow(dead_code)] // Read only through the `Debug` impl by insta.
struct KnownAnswer {
    ciphertext_and_tag: String,
    detached_ciphertext: String,
    detached_tag: String,
    empty_message_tag: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------------------
// Operation helpers
// ------------------------------------------------------------------------------
//
// These are the only places that call the `SymmetricStateLike` encrypt/decrypt
// methods, so a change to their signatures only needs to be mirrored here.
// They take their input as an owned `Vec`, because that is what the
// `bindgen!`-generated bindings hand the host.

/// Opens a fresh state with a deterministic key and nonce, and absorbs [`AD`].
fn open(case: &Case) -> SymmetricState {
    let raw_key: Vec<u8> = (0..case.key_len).map(|i| i as u8).collect();
    let nonce: Vec<u8> = (0..case.nonce_len).map(|i| 0xa0 + i as u8).collect();
    let key = SymmetricKey::import(case.alg, &raw_key).expect("key length matches the algorithm");
    let mut options = SymmetricOptions::default();
    options
        .set("nonce", &nonce)
        .expect("nonce is a supported symmetric option");
    let state = SymmetricState::open(case.alg, Some(&key), Some(&options), &Limits::new())
        .expect("key, nonce and algorithm are valid");
    state
        .inner()
        .absorb(AD)
        .expect("AEADs accept additional data");
    state
}

fn encrypt(state: &SymmetricState, message: Vec<u8>) -> CryptoResult<Vec<u8>> {
    state.inner().encrypt(message)
}

fn encrypt_detached(
    state: &SymmetricState,
    message: Vec<u8>,
) -> CryptoResult<(Vec<u8>, SymmetricTag)> {
    state.inner().encrypt_detached(message)
}

fn decrypt(
    state: &SymmetricState,
    ciphertext_and_tag: Vec<u8>,
    out_len: usize,
) -> CryptoResult<Vec<u8>> {
    state.inner().decrypt(ciphertext_and_tag, out_len)
}

fn decrypt_detached(
    state: &SymmetricState,
    ciphertext: Vec<u8>,
    tag: &[u8],
) -> CryptoResult<Vec<u8>> {
    state.inner().decrypt_detached(ciphertext, tag)
}

fn expect_invalid_tag(result: CryptoResult<Vec<u8>>) {
    let err = result.expect_err("a tampered tag must not verify");
    assert!(
        matches!(err.downcast_ref(), Some(CryptoErrno::InvalidTag)),
        "expected InvalidTag, got {err:?}"
    );
}

// ------------------------------------------------------------------------------
// The shared test body
// ------------------------------------------------------------------------------

/// Encrypts [`MESSAGE`] (attached and detached) and an empty message, checks
/// that decryption round-trips and that a tampered tag is rejected, and
/// returns the bytes to snapshot.
fn known_answer(case: &Case) -> KnownAnswer {
    let tag_len = open(case)
        .inner()
        .max_tag_len()
        .expect("AEADs have a tag length");

    // Attached encryption must produce exactly `ciphertext || tag`.
    let ciphertext_and_tag = encrypt(&open(case), MESSAGE.to_vec()).expect("encryption succeeds");
    assert_eq!(ciphertext_and_tag.len(), MESSAGE.len() + tag_len);

    // Detached encryption must produce the same bytes, just split in two.
    let (detached_ciphertext, detached_tag) =
        encrypt_detached(&open(case), MESSAGE.to_vec()).expect("detached encryption succeeds");
    let detached_tag = detached_tag.as_ref().to_vec();
    assert_eq!(detached_ciphertext, ciphertext_and_tag[..MESSAGE.len()]);
    assert_eq!(detached_tag, ciphertext_and_tag[MESSAGE.len()..]);

    // Both decryption variants recover the message.
    assert_eq!(
        decrypt(&open(case), ciphertext_and_tag.clone(), MESSAGE.len())
            .expect("decryption succeeds"),
        MESSAGE
    );
    assert_eq!(
        decrypt_detached(&open(case), detached_ciphertext.clone(), &detached_tag)
            .expect("detached decryption succeeds"),
        MESSAGE
    );

    // Flipping one tag bit makes both decryption variants fail with InvalidTag.
    let mut tampered = ciphertext_and_tag.clone();
    *tampered.last_mut().expect("the tag is not empty") ^= 1;
    expect_invalid_tag(decrypt(&open(case), tampered, MESSAGE.len()));
    let mut tampered_tag = detached_tag.clone();
    tampered_tag[0] ^= 1;
    expect_invalid_tag(decrypt_detached(
        &open(case),
        detached_ciphertext.clone(),
        &tampered_tag,
    ));

    // An empty message encrypts to the tag alone, and still round-trips.
    let empty_message_tag = encrypt(&open(case), Vec::new()).expect("empty encryption succeeds");
    assert_eq!(empty_message_tag.len(), tag_len);
    assert_eq!(
        decrypt(&open(case), empty_message_tag.clone(), 0).expect("empty decryption succeeds"),
        b""
    );

    KnownAnswer {
        ciphertext_and_tag: hex(&ciphertext_and_tag),
        detached_ciphertext: hex(&detached_ciphertext),
        detached_tag: hex(&detached_tag),
        empty_message_tag: hex(&empty_message_tag),
    }
}

// ------------------------------------------------------------------------------
// The algorithms under test
// ------------------------------------------------------------------------------

const AES_128_GCM: Case = Case {
    alg: "AES-128-GCM",
    key_len: 16,
    nonce_len: 12,
};
const AES_256_GCM: Case = Case {
    alg: "AES-256-GCM",
    key_len: 32,
    nonce_len: 12,
};
const CHACHA20_POLY1305: Case = Case {
    alg: "CHACHA20-POLY1305",
    key_len: 32,
    nonce_len: 12,
};
const XCHACHA20_POLY1305: Case = Case {
    alg: "XCHACHA20-POLY1305",
    key_len: 32,
    nonce_len: 24,
};
const XOODYAK_128: Case = Case {
    alg: "XOODYAK-128",
    key_len: 16,
    nonce_len: 16,
};
const XOODYAK_160: Case = Case {
    alg: "XOODYAK-160",
    key_len: 20,
    nonce_len: 16,
};

// ------------------------------------------------------------------------------
// Known-answer tests, one per algorithm
// ------------------------------------------------------------------------------

#[test]
fn known_answer_aes_128_gcm() {
    insta::assert_debug_snapshot!(known_answer(&AES_128_GCM));
}

#[test]
fn known_answer_aes_256_gcm() {
    insta::assert_debug_snapshot!(known_answer(&AES_256_GCM));
}

#[test]
fn known_answer_chacha20_poly1305() {
    insta::assert_debug_snapshot!(known_answer(&CHACHA20_POLY1305));
}

#[test]
fn known_answer_xchacha20_poly1305() {
    insta::assert_debug_snapshot!(known_answer(&XCHACHA20_POLY1305));
}

#[test]
fn known_answer_xoodyak_128() {
    insta::assert_debug_snapshot!(known_answer(&XOODYAK_128));
}

#[test]
fn known_answer_xoodyak_160() {
    insta::assert_debug_snapshot!(known_answer(&XOODYAK_160));
}

// ==============================================================================
// Host allocation measurements
// ==============================================================================
//
// These tests measure how much the host allocates while it encrypts or
// decrypts a large message, starting from the owned `Vec` that the bindings
// receive. Wasmtime lifts a `list<u8>` into `Vec::with_capacity(len)` and then
// fills it, so the inputs here are built the same way: capacity equals length.
//
// `allocation-counter` counts per thread, so tests running in parallel don't
// disturb each other. It doesn't implement `realloc`, so `GlobalAlloc`'s
// default applies and every reallocation counts as a fresh allocation of the
// new size. Growing a `Vec` therefore shows up as a whole extra copy, which is
// the worst case the system allocator could hit.
//
// Run with `-- --nocapture` to print the measured values.

use allocation_counter::AllocationInfo;

const LARGE_LEN: usize = 1 << 20;

/// The exact number of bytes one operation is expected to allocate, split
/// into message-sized and tag-sized parts. Expressing it this way, rather than
/// rounding to whole messages, also catches a stray small allocation.
#[derive(Clone, Copy)]
struct Bytes {
    messages: u64,
    tags: u64,
}

impl Bytes {
    fn total(self, tag_len: usize) -> u64 {
        self.messages * LARGE_LEN as u64 + self.tags * tag_len as u64
    }
}

/// Formats as e.g. "1 message + 2 tags", "1 tag" or "nothing".
impl std::fmt::Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let plural = |n: u64| if n == 1 { "" } else { "s" };
        let parts: Vec<String> = [(self.messages, "message"), (self.tags, "tag")]
            .into_iter()
            .filter(|&(n, _)| n > 0)
            .map(|(n, unit)| format!("{n} {unit}{}", plural(n)))
            .collect();
        if parts.is_empty() {
            f.pad("nothing")
        } else {
            f.pad(&parts.join(" + "))
        }
    }
}

/// What each operation is expected to allocate.
struct ExpectedAllocations {
    encrypt: Bytes,
    encrypt_detached: Bytes,
    decrypt: Bytes,
    decrypt_detached: Bytes,
}

/// Builds an input `Vec` the way Wasmtime's lift does.
fn lifted(bytes: &[u8]) -> Vec<u8> {
    let mut lifted = Vec::with_capacity(bytes.len());
    lifted.extend_from_slice(bytes);
    lifted
}

/// Runs `f` and returns its result together with what it allocated.
fn measure<R>(f: impl FnOnce() -> R) -> (R, AllocationInfo) {
    // `allocation_counter::measure` only accepts closures that return `()`.
    let mut result = None;
    let info = allocation_counter::measure(|| result = Some(f()));
    (result.expect("measure always runs the closure"), info)
}

/// Prints one table of all measurements for `case`, then checks that each
/// operation allocated exactly the expected number of bytes.
///
/// The table goes out in a single `eprint!`, which holds the stderr lock for
/// the whole write, so tables from tests running in parallel don't interleave.
/// Printing before asserting means a failing test still shows every row.
fn report(case: &Case, tag_len: usize, rows: &[(&str, AllocationInfo, Bytes)]) {
    let mut table = format!(
        "\n{} (message {LARGE_LEN} bytes, tag {tag_len} bytes)\n  \
         {:<16}  {:>9}  {:>6}  {:>9}  {:>9}  {}\n",
        case.alg, "operation", "bytes", "allocs", "peak", "expected", "expected as",
    );
    for (operation, info, expected) in rows {
        table += &format!(
            "  {operation:<16}  {:>9}  {:>6}  {:>9}  {:>9}  {expected}\n",
            info.bytes_total,
            info.count_total,
            info.bytes_max,
            expected.total(tag_len),
        );
    }
    eprint!("{table}");

    for (operation, info, expected) in rows {
        assert_eq!(
            info.bytes_total,
            expected.total(tag_len),
            "{} {operation}: expected {expected}",
            case.alg,
        );
    }
}

/// Measures all four operations on a [`LARGE_LEN`]-byte message. Only the
/// operation itself runs inside the measurement: opening the state, building
/// the lifted input and copying the tag out of its `SymmetricTag` happen
/// outside it.
fn measure_allocations(case: &Case, expected: ExpectedAllocations) {
    let message = vec![0x5a; LARGE_LEN];
    let tag_len = open(case)
        .inner()
        .max_tag_len()
        .expect("AEADs have a tag length");

    let (state, input) = (open(case), lifted(&message));
    let (ciphertext_and_tag, encrypt_info) = measure(|| encrypt(&state, input));
    let ciphertext_and_tag = ciphertext_and_tag.expect("encryption succeeds");

    let (state, input) = (open(case), lifted(&message));
    let (detached, encrypt_detached_info) = measure(|| encrypt_detached(&state, input));
    let (ciphertext, tag) = detached.expect("detached encryption succeeds");

    let (state, input) = (open(case), lifted(&ciphertext_and_tag));
    let (plaintext, decrypt_info) = measure(|| decrypt(&state, input, LARGE_LEN));
    assert_eq!(plaintext.expect("decryption succeeds"), message);

    let (state, input) = (open(case), lifted(&ciphertext));
    let (plaintext, decrypt_detached_info) =
        measure(|| decrypt_detached(&state, input, tag.as_ref()));
    assert_eq!(plaintext.expect("detached decryption succeeds"), message);

    report(
        case,
        tag_len,
        &[
            ("encrypt", encrypt_info, expected.encrypt),
            (
                "encrypt_detached",
                encrypt_detached_info,
                expected.encrypt_detached,
            ),
            ("decrypt", decrypt_info, expected.decrypt),
            (
                "decrypt_detached",
                decrypt_detached_info,
                expected.decrypt_detached,
            ),
        ],
    );
}

// Every algorithm encrypts and decrypts in the buffer the bindings received.
// Only the attached encrypt allocates a message-sized buffer: appending the
// tag to a `Vec` whose capacity equals its length reallocates it once, to
// message + tag bytes. The remaining tag-sized allocations are:
// - encrypt and encrypt_detached: the `Vec` inside the `SymmetricTag` that the
//   detached primitive returns (the attached encrypt is built on it).
// - decrypt: `split_off` moving the trailing tag into its own `Vec`.
//
// For comparison, before the host worked in the received buffer, AES-GCM and
// ChaCha20-Poly1305 allocated 3 copies for encrypt (a `to_vec()` copy, whose
// capacity then doubled when the tag was appended) and 1 for each other
// operation, and Xoodyak allocated 1 fresh output buffer per operation.
const IN_PLACE: ExpectedAllocations = ExpectedAllocations {
    encrypt: Bytes {
        messages: 1,
        tags: 2,
    },
    encrypt_detached: Bytes {
        messages: 0,
        tags: 1,
    },
    decrypt: Bytes {
        messages: 0,
        tags: 1,
    },
    decrypt_detached: Bytes {
        messages: 0,
        tags: 0,
    },
};

#[test]
fn host_allocations_aes_128_gcm() {
    measure_allocations(&AES_128_GCM, IN_PLACE);
}

#[test]
fn host_allocations_aes_256_gcm() {
    measure_allocations(&AES_256_GCM, IN_PLACE);
}

#[test]
fn host_allocations_chacha20_poly1305() {
    measure_allocations(&CHACHA20_POLY1305, IN_PLACE);
}

#[test]
fn host_allocations_xchacha20_poly1305() {
    measure_allocations(&XCHACHA20_POLY1305, IN_PLACE);
}

#[test]
fn host_allocations_xoodyak_128() {
    measure_allocations(&XOODYAK_128, IN_PLACE);
}

#[test]
fn host_allocations_xoodyak_160() {
    measure_allocations(&XOODYAK_160, IN_PLACE);
}
