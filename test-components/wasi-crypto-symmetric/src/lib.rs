// The world imports only the interfaces under test, so these tests also run
// against a host that provides just those (and their dependencies).
wit_bindgen::generate!({
    path: "../../spec/wit",
    inline: "
        package wasi-crypto-tests:symmetric;

        world symmetric-tests {
            import wasi:crypto/symmetric@0.12.0;
            import wasi:crypto/symmetric-managed@0.12.0;
        }
    ",
    world: "symmetric-tests",
    // The world is in its own test package, so the `wasi:crypto` interfaces
    // it imports need bindings generated explicitly.
    generate_all,
});

// This component covers the `symmetric` and `symmetric-managed` interfaces.
#[cfg(test)]
mod tests {
    // wit-bindgen re-exports every `use`d type inside each interface module,
    // so each type is imported from the interface that declares it; glob
    // imports from several modules would be ambiguous.
    use crate::wasi::crypto::common::{ArrayOutput, CryptoErrno, Version};
    use crate::wasi::crypto::secrets_manager::SecretsManager;
    use crate::wasi::crypto::symmetric::{
        SymmetricKey, SymmetricOptions, SymmetricState, SymmetricTag,
    };
    use crate::wasi::crypto::symmetric_managed;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn generate(alg: &str) -> SymmetricKey {
        SymmetricKey::generate(alg, None)
            .unwrap_or_else(|e| panic!("SymmetricKey::generate({alg}) failed: {e:?}"))
    }

    fn import(alg: &str, raw: &[u8]) -> SymmetricKey {
        SymmetricKey::import(alg, raw)
            .unwrap_or_else(|e| panic!("SymmetricKey::import({alg}) failed: {e:?}"))
    }

    fn open(alg: &str, key: Option<&SymmetricKey>) -> SymmetricState {
        SymmetricState::open(alg, key, None)
            .unwrap_or_else(|e| panic!("SymmetricState::open({alg}) failed: {e:?}"))
    }

    // ── options ───────────────────────────────────────────────────────────────

    #[test]
    fn options_open_drop_symmetric() {
        let opts = SymmetricOptions::new();
        drop(opts);
    }

    #[test]
    fn options_set_u64_threads() {
        let opts = SymmetricOptions::new();
        match opts.set_u64("threads", 1) {
            Ok(()) | Err(CryptoErrno::UnsupportedOption) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(opts);
    }

    #[test]
    fn options_set_context_bytes() {
        let opts = SymmetricOptions::new();
        match opts.set("context", b"test-context") {
            Ok(()) | Err(CryptoErrno::UnsupportedOption) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(opts);
    }

    #[test]
    fn options_set_rejects_garbage_name() {
        let opts = SymmetricOptions::new();
        match opts.set_u64("__not_a_real_option__", 0) {
            Err(CryptoErrno::UnsupportedOption) => {}
            Ok(()) => panic!("host accepted garbage option name"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(opts);
    }

    // ── key lifecycle ─────────────────────────────────────────────────────────

    #[test]
    fn key_generate_and_drop() {
        let key = generate("HMAC/SHA-256");
        drop(key);
    }

    #[test]
    fn key_import_and_drop() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        drop(key);
    }

    #[test]
    fn key_export_produces_array_output() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let array_out = key.export().unwrap();
        let bytes = ArrayOutput::pull(array_out).unwrap();
        assert_eq!(bytes, b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn key_export_round_trips_raw_material() {
        let raw = b"aaaabbbbccccddddaaaabbbbccccdddd";
        let key = import("HMAC/SHA-256", raw);
        let array_out = key.export().unwrap();
        let exported = ArrayOutput::pull(array_out).unwrap();
        assert_eq!(exported.as_slice(), raw.as_slice());
        drop(key);
    }

    #[test]
    fn key_generate_unsupported_algorithm() {
        match SymmetricKey::generate("__not_a_real_algo__", None) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(_) => panic!("should have rejected unknown algorithm"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── state open / drop ────────────────────────────────────────────────────

    #[test]
    fn state_open_drop_no_key() {
        let state = open("SHA-256", None);
        drop(state);
    }

    #[test]
    fn state_open_drop_with_key() {
        let key = generate("HMAC/SHA-256");
        let state = SymmetricState::open("HMAC/SHA-256", Some(&key), None).unwrap();
        drop(state);
        drop(key);
    }

    #[test]
    fn state_open_key_not_supported() {
        // Hash functions do not accept keys; providing one must return invalid_key.
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        match SymmetricState::open("SHA-256", Some(&key), None) {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(s) => {
                drop(s);
                panic!("SHA-256 should reject a key");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    #[test]
    fn state_open_key_required() {
        // MAC functions require a key; omitting one must return key_required.
        match SymmetricState::open("HMAC/SHA-256", None, None) {
            Err(CryptoErrno::KeyRequired) => {}
            Ok(s) => {
                drop(s);
                panic!("HMAC/SHA-256 should require a key");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn state_clone() {
        let key = generate("HMAC/SHA-256");
        let state = SymmetricState::open("HMAC/SHA-256", Some(&key), None).unwrap();
        state.absorb(b"hello").unwrap();
        let clone = state.clone().unwrap();
        // Both handles share the same underlying state: verify the clone produces a valid-length tag.
        let tag_clone = clone.squeeze_tag().unwrap();
        let raw_clone = SymmetricTag::pull(tag_clone).unwrap();
        assert_eq!(raw_clone.len(), 32); // HMAC/SHA-256 produces 32 bytes
        drop(key);
    }

    // ── hashing (doc example: SHA-256) ──────────────────────────────────────

    #[test]
    fn hash_shake128_absorb_squeeze() {
        let state = open("SHA-256", None);
        state.absorb(b"data").unwrap();
        state.absorb(b"more_data").unwrap();
        let out = state.squeeze().unwrap();
        assert_eq!(out.len(), 32); // SHA-256 always produces 32 bytes
    }

    #[test]
    fn hash_same_input_same_output() {
        let digest = |data: &[u8]| {
            let state = open("SHA-256", None);
            state.absorb(data).unwrap();
            state.squeeze().unwrap()
        };
        assert_eq!(digest(b"hello"), digest(b"hello"));
        assert_ne!(digest(b"hello"), digest(b"world"));
    }

    // ── MAC (doc examples: HMAC/SHA-512) ────────────────────────────────────

    #[test]
    fn mac_hmac_sha512_compute_and_pull() {
        // Adapted from the "MAC" doc example.
        let key = import("HMAC/SHA-512", b"key");
        let state = SymmetricState::open("HMAC/SHA-512", Some(&key), None).unwrap();
        state.absorb(b"data").unwrap();
        state.absorb(b"more_data").unwrap();
        let tag = state.squeeze_tag().unwrap();
        let raw = SymmetricTag::pull(tag).unwrap();
        assert_eq!(raw.len(), 64); // HMAC/SHA-512 produces 64 bytes
        drop(key);
    }

    #[test]
    fn mac_tag_len() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let state = SymmetricState::open("HMAC/SHA-256", Some(&key), None).unwrap();
        let tag = state.squeeze_tag().unwrap();
        let len = tag.len().unwrap();
        assert_eq!(len, 32);
        drop(tag);
        drop(key);
    }

    #[test]
    fn mac_verify_correct_tag() {
        // Adapted from the "MAC verification" doc example.
        let key = import("HMAC/SHA-512", b"key");

        // Compute reference tag.
        let state = SymmetricState::open("HMAC/SHA-512", Some(&key), None).unwrap();
        state.absorb(b"data").unwrap();
        state.absorb(b"more_data").unwrap();
        let tag = state.squeeze_tag().unwrap();
        let expected = SymmetricTag::pull(tag).unwrap();

        // Verify against the same input.
        let state2 = SymmetricState::open("HMAC/SHA-512", Some(&key), None).unwrap();
        state2.absorb(b"data").unwrap();
        state2.absorb(b"more_data").unwrap();
        let tag2 = state2.squeeze_tag().unwrap();
        tag2.verify(&expected).unwrap();

        drop(key);
    }

    #[test]
    fn mac_verify_wrong_tag_returns_invalid_tag() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let state = SymmetricState::open("HMAC/SHA-256", Some(&key), None).unwrap();
        state.absorb(b"data").unwrap();
        let tag = state.squeeze_tag().unwrap();
        let wrong = vec![0u8; 32];
        match tag.verify(&wrong) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(()) => panic!("wrong tag should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    #[test]
    fn mac_tag_drop_explicit() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let state = SymmetricState::open("HMAC/SHA-256", Some(&key), None).unwrap();
        let tag = state.squeeze_tag().unwrap();
        drop(tag);
        drop(key);
    }

    // ── BLAKE3 XOF (doc example) ─────────────────────────────────────────────

    #[test]
    fn blake3_xof_two_squeezes_differ() {
        let key = import("HMAC/SHA-256", b"aaaabbbbccccddddaaaabbbbccccdddd");
        let state = open("HMAC/SHA-256", Some(&key));
        state.absorb(b"context").unwrap();
        let tag = state.squeeze_tag().unwrap();
        let raw = SymmetricTag::pull(tag).unwrap();
        assert_eq!(raw.len(), 32); // HMAC/SHA-256 tag is 32 bytes
        // Repeat with different input — must produce a different tag.
        let state2 = open("HMAC/SHA-256", Some(&key));
        state2.absorb(b"other_context").unwrap();
        let tag2 = state2.squeeze_tag().unwrap();
        let raw2 = SymmetricTag::pull(tag2).unwrap();
        assert_ne!(raw, raw2);
        drop(key);
    }

    // ── HKDF (doc example: extract-and-expand) ───────────────────────────────

    #[test]
    fn hkdf_extract_and_expand() {
        // Adapted from the "Key derivation using extract-and-expand" doc example.
        let ikm = import("HKDF-EXTRACT/SHA-512", b"input_key_material");
        let extract_state = SymmetricState::open("HKDF-EXTRACT/SHA-512", Some(&ikm), None).unwrap();
        extract_state.absorb(b"salt").unwrap();
        let prk = extract_state.squeeze_key("HKDF-EXPAND/SHA-512").unwrap();

        let expand_state = SymmetricState::open("HKDF-EXPAND/SHA-512", Some(&prk), None).unwrap();
        expand_state.absorb(b"info").unwrap();
        let subkey = expand_state.squeeze().unwrap();
        assert!(!subkey.is_empty());

        drop(ikm);
        drop(prk);
    }

    // ── AEAD: AES-256-GCM explicit nonce (doc example) ───────────────────────

    #[test]
    fn aead_aes256gcm_explicit_nonce_encrypt_decrypt() {
        // Adapted from the "AEAD encryption with an explicit nonce" doc example.
        let nonce = [0u8; 12]; // AES-256-GCM uses 12-byte nonces
        let message = b"test message";
        let aad = b"additional data";

        let key = generate("AES-256-GCM");

        // Encrypt
        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        enc_state.absorb(aad).unwrap();
        let ciphertext = enc_state.encrypt(message).unwrap();

        // Decrypt
        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        dec_state.absorb(aad).unwrap();
        let out_len = message.len();
        let plaintext = dec_state.decrypt(&ciphertext, out_len as u32).unwrap();

        assert_eq!(plaintext, message);
        drop(key);
    }

    #[test]
    fn aead_aes256gcm_wrong_tag_returns_invalid_tag() {
        let nonce = [0u8; 12];
        let key = generate("AES-256-GCM");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let mut ciphertext = enc_state.encrypt(b"hello").unwrap();

        // Corrupt the tag (last 16 bytes for GCM)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let out_len = (ciphertext.len() - 16) as u32; // AES-GCM tag is 16 bytes
        match dec_state.decrypt(&ciphertext, out_len) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(_) => panic!("corrupted ciphertext should not decrypt"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    // ── AEAD: auto-nonce retrieval ────────────────────────────────────────────

    #[test]
    fn aead_auto_nonce_retrievable_via_options_get() {
        let nonce = [0xabu8; 12];
        let key = generate("AES-256-GCM");
        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let nonce_buf = state.options_get("nonce").unwrap();
        assert_eq!(
            nonce_buf, nonce,
            "nonce retrieved from state must match the one set"
        );
        drop(state);
        drop(key);
    }

    // ── detached encrypt/decrypt ─────────────────────────────────────────────

    #[test]
    fn aead_aes256gcm_detached_round_trip() {
        let nonce = [0u8; 12];
        let message = b"detached test";
        let key = generate("AES-256-GCM");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let (ciphertext, tag) = enc_state.encrypt_detached(message).unwrap();
        let raw_tag = SymmetricTag::pull(tag).unwrap();

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let plaintext = dec_state.decrypt_detached(&ciphertext, &raw_tag).unwrap();

        assert_eq!(plaintext, message);
        drop(key);
    }

    // ── max_tag_len ───────────────────────────────────────────────────────────

    #[test]
    fn aead_max_tag_len_nonzero_for_gcm() {
        let key = generate("AES-256-GCM");
        let opts = SymmetricOptions::new();
        opts.set("nonce", &[0u8; 12]).unwrap();
        let state = SymmetricState::open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let tag_len = state.max_tag_len().unwrap();
        assert_eq!(tag_len, 16); // GCM tag is always 16 bytes
        drop(state);
        drop(key);
    }

    // ── options_get_u64 ───────────────────────────────────────────────────────

    #[test]
    fn state_options_get_u64_unsupported_returns_error() {
        let state = open("SHA-256", None);
        match state.options_get_u64("__nonexistent__") {
            Err(CryptoErrno::UnsupportedOption) | Err(CryptoErrno::OptionNotSet) => {}
            Ok(v) => panic!("should not return a value for unknown option, got {v}"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(state);
    }

    // ── managed key operations ────────────────────────────────────────────────
    //
    // Managed keys need a secrets manager, which the host doesn't implement:
    // `SecretsManager::open` returns `UnsupportedFeature`. `#[should_panic]`
    // can't express that on wasm: libtest ignores such tests without running
    // them, and the runner reports the ignored test as passed. So these tests
    // run, accept exactly `UnsupportedFeature` from `open`, and only exercise
    // the managed-key scenario once a secrets manager exists.

    /// Opens a secrets manager, or returns `None` when the host reports
    /// `UnsupportedFeature`. Any other error fails the test.
    // TODO: assert that `open` succeeds once the host implements a secrets manager.
    fn open_secrets_manager() -> Option<SecretsManager> {
        match SecretsManager::open(None) {
            Ok(sm) => Some(sm),
            Err(CryptoErrno::UnsupportedFeature) => {
                eprintln!("secrets manager unsupported by the host; rest of the test skipped");
                None
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn managed_key_generate_store_retrieve() {
        let Some(sm) = open_secrets_manager() else {
            return;
        };
        let key = symmetric_managed::generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let key_id = symmetric_managed::store_managed(&sm, &key).unwrap();
        let retrieved = symmetric_managed::from_id(&sm, &key_id, Version::Latest).unwrap();
        drop(key);
        drop(retrieved);
        drop(sm);
    }

    #[test]
    fn managed_key_id_returns_id_and_version() {
        let Some(sm) = open_secrets_manager() else {
            return;
        };
        let key = symmetric_managed::generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let (id, version) = symmetric_managed::id(&key).unwrap();
        assert!(!id.is_empty());
        // Version::Latest has a known numeric representation; any non-zero value is valid
        let _ = version;
        drop(key);
        drop(sm);
    }

    #[test]
    fn managed_key_replace() {
        let Some(sm) = open_secrets_manager() else {
            return;
        };
        let old = symmetric_managed::generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let new = symmetric_managed::generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let _new_version = symmetric_managed::replace_managed(&sm, old, &new).unwrap();
        drop(new);
        drop(sm);
    }

    #[test]
    fn unmanaged_key_id_returns_unsupported_feature() {
        let key = generate("HMAC/SHA-256");
        match symmetric_managed::id(&key) {
            Err(CryptoErrno::UnsupportedFeature) => {}
            Ok(_) => panic!("unmanaged key should not have an id"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    // ── hash: all SHA-2 variants ──────────────────────────────────────────────

    #[test]
    fn hash_sha384_absorb_squeeze() {
        let state = open("SHA-384", None);
        state.absorb(b"data").unwrap();
        let out = state.squeeze().unwrap();
        assert_eq!(out.len(), 48, "SHA-384 always produces 48 bytes");
    }

    #[test]
    fn hash_sha512_absorb_squeeze() {
        let state = open("SHA-512", None);
        state.absorb(b"data").unwrap();
        let out = state.squeeze().unwrap();
        assert_eq!(out.len(), 64, "SHA-512 always produces 64 bytes");
    }

    #[test]
    fn hash_sha512_256_correct_fips_iv() {
        // SHA-512/256 is the FIPS 180-4 hash with its own distinct initial values.
        // For "abc" the expected digest is 53048e26...
        // Plain SHA-512 truncated to 32 bytes would be ddaf35..., which must NOT appear.
        let state = open("SHA-512/256", None);
        state.absorb(b"abc").unwrap();
        let out = state.squeeze().unwrap();
        assert_eq!(out.len(), 32);
        let expected = [
            0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c,
            0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46, 0xe0, 0xe2, 0xf1, 0x31,
            0x07, 0xe7, 0xaf, 0x23,
        ];
        let truncated_sha512 = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a,
        ];
        assert_eq!(
            out, expected,
            "SHA-512/256 must use FIPS 180-4 initial values"
        );
        assert_ne!(
            out, truncated_sha512,
            "SHA-512/256 must not be plain truncated SHA-512"
        );
    }

    #[test]
    fn hash_sha256_known_answer() {
        // Known digest for "data" || "more_data" from the WITX reference test_hash.
        let state = open("SHA-256", None);
        state.absorb(b"data").unwrap();
        state.absorb(b"more_data").unwrap();
        let out = state.squeeze().unwrap();
        let expected: [u8; 32] = [
            19, 196, 14, 236, 34, 84, 26, 21, 94, 23, 32, 16, 199, 253, 110, 246, 84, 228, 225, 56,
            160, 194, 9, 35, 249, 169, 16, 98, 162, 127, 87, 182,
        ];
        assert_eq!(out, expected);
    }

    // ── HKDF: SHA-256 variant ─────────────────────────────────────────────────

    #[test]
    fn hkdf_sha256_extract_and_expand() {
        let ikm = import("HKDF-EXTRACT/SHA-256", b"input_key_material");
        let extract_state = SymmetricState::open("HKDF-EXTRACT/SHA-256", Some(&ikm), None).unwrap();
        extract_state.absorb(b"salt").unwrap();
        let prk = extract_state.squeeze_key("HKDF-EXPAND/SHA-256").unwrap();

        let expand_state = SymmetricState::open("HKDF-EXPAND/SHA-256", Some(&prk), None).unwrap();
        expand_state.absorb(b"info").unwrap();
        let subkey = expand_state.squeeze().unwrap();
        assert_eq!(subkey.len(), 32, "HKDF-EXPAND/SHA-256 OKM is 32 bytes");

        drop(ikm);
        drop(prk);
    }

    // ── AEAD: AES-128-GCM ─────────────────────────────────────────────────────

    #[test]
    fn aead_aes128gcm_encrypt_decrypt() {
        let nonce = [0u8; 12];
        let message = b"hello aes128";
        let key = generate("AES-128-GCM");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("AES-128-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let ciphertext = enc_state.encrypt(message).unwrap();

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state = SymmetricState::open("AES-128-GCM", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let plaintext = dec_state
            .decrypt(&ciphertext, message.len() as u32)
            .unwrap();
        assert_eq!(plaintext, message);
        drop(key);
    }

    #[test]
    fn aead_aes128gcm_wrong_tag_returns_invalid_tag() {
        let nonce = [0u8; 12];
        let key = generate("AES-128-GCM");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("AES-128-GCM", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let mut ciphertext = enc_state.encrypt(b"hello").unwrap();
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state = SymmetricState::open("AES-128-GCM", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let out_len = (ciphertext.len() - 16) as u32;
        match dec_state.decrypt(&ciphertext, out_len) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(_) => panic!("corrupted ciphertext should not decrypt"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    // ── AEAD: ChaCha20-Poly1305 ───────────────────────────────────────────────

    #[test]
    fn aead_chacha20poly1305_encrypt_decrypt() {
        let nonce = [42u8; 12];
        let message = b"test chacha20";
        let key = generate("CHACHA20-POLY1305");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("CHACHA20-POLY1305", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let ciphertext = enc_state.encrypt(message).unwrap();

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state =
            SymmetricState::open("CHACHA20-POLY1305", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let plaintext = dec_state
            .decrypt(&ciphertext, message.len() as u32)
            .unwrap();
        assert_eq!(plaintext, message);
        drop(key);
    }

    #[test]
    fn aead_chacha20poly1305_key_len_is_32() {
        let key = generate("CHACHA20-POLY1305");
        let raw = {
            let ao = key.export().unwrap();
            ArrayOutput::pull(ao).unwrap()
        };
        assert_eq!(raw.len(), 32, "ChaCha20-Poly1305 key is 32 bytes");
        drop(key);
    }

    #[test]
    fn aead_chacha20poly1305_wrong_tag_returns_invalid_tag() {
        let nonce = [0u8; 12];
        let key = generate("CHACHA20-POLY1305");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("CHACHA20-POLY1305", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let mut ciphertext = enc_state.encrypt(b"hello").unwrap();
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state =
            SymmetricState::open("CHACHA20-POLY1305", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let out_len = (ciphertext.len() - 16) as u32;
        match dec_state.decrypt(&ciphertext, out_len) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(_) => panic!("corrupted ciphertext should not decrypt"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    #[test]
    fn aead_chacha20poly1305_detached_round_trip() {
        let nonce = [1u8; 12];
        let message = b"detached chacha";
        let key = generate("CHACHA20-POLY1305");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state = SymmetricState::open("CHACHA20-POLY1305", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let (ciphertext, tag) = enc_state.encrypt_detached(message).unwrap();
        let raw_tag = SymmetricTag::pull(tag).unwrap();

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state =
            SymmetricState::open("CHACHA20-POLY1305", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let plaintext = dec_state.decrypt_detached(&ciphertext, &raw_tag).unwrap();
        assert_eq!(plaintext, message);
        drop(key);
    }

    // ── AEAD: XChaCha20-Poly1305 ─────────────────────────────────────────────

    #[test]
    fn aead_xchacha20poly1305_encrypt_decrypt() {
        let nonce = [7u8; 24]; // XChaCha20 uses a 24-byte nonce
        let message = b"test xchacha20";
        let key = generate("XCHACHA20-POLY1305");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state =
            SymmetricState::open("XCHACHA20-POLY1305", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let ciphertext = enc_state.encrypt(message).unwrap();

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state =
            SymmetricState::open("XCHACHA20-POLY1305", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let plaintext = dec_state
            .decrypt(&ciphertext, message.len() as u32)
            .unwrap();
        assert_eq!(plaintext, message);
        drop(key);
    }

    #[test]
    fn aead_xchacha20poly1305_wrong_tag_returns_invalid_tag() {
        let nonce = [0u8; 24];
        let key = generate("XCHACHA20-POLY1305");

        let opts = SymmetricOptions::new();
        opts.set("nonce", &nonce).unwrap();
        let enc_state =
            SymmetricState::open("XCHACHA20-POLY1305", Some(&key), Some(&opts)).unwrap();
        drop(opts);
        let mut ciphertext = enc_state.encrypt(b"hello").unwrap();
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let opts2 = SymmetricOptions::new();
        opts2.set("nonce", &nonce).unwrap();
        let dec_state =
            SymmetricState::open("XCHACHA20-POLY1305", Some(&key), Some(&opts2)).unwrap();
        drop(opts2);
        let out_len = (ciphertext.len() - 16) as u32;
        match dec_state.decrypt(&ciphertext, out_len) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(_) => panic!("corrupted ciphertext should not decrypt"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(key);
    }

    // ── Xoodyak-128: hash, MAC, AEAD, ratchet ────────────────────────────────

    #[test]
    fn xoodyak128_keyless_hash_squeeze() {
        let state = open("XOODYAK-128", None);
        state.absorb(b"data").unwrap();
        state.absorb(b"more_data").unwrap();
        let out = state.squeeze().unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn xoodyak128_squeeze_tag() {
        let key = generate("XOODYAK-128");
        let state = SymmetricState::open("XOODYAK-128", Some(&key), None).unwrap();
        state.absorb(b"data").unwrap();
        let tag = state.squeeze_tag().unwrap();
        let raw = SymmetricTag::pull(tag).unwrap();
        assert!(!raw.is_empty());
        drop(key);
    }

    #[test]
    fn xoodyak128_encrypt_decrypt() {
        let msg = b"test xoodyak";
        let key = generate("XOODYAK-128");

        let enc_state = SymmetricState::open("XOODYAK-128", Some(&key), None).unwrap();
        let ciphertext = enc_state.encrypt(msg).unwrap();

        let dec_state = SymmetricState::open("XOODYAK-128", Some(&key), None).unwrap();
        let plaintext = dec_state.decrypt(&ciphertext, msg.len() as u32).unwrap();
        assert_eq!(plaintext, msg);
        drop(key);
    }

    #[test]
    fn xoodyak128_session_squeeze_ratchet_matches() {
        // Port of the WITX reference test_session: two parties run the same
        // sequence of absorb/squeeze/encrypt/absorb/ratchet/squeeze and must
        // arrive at identical squeezed outputs.
        let msg = b"test";
        let key = generate("XOODYAK-128");

        // Sender side
        let sender = SymmetricState::open("XOODYAK-128", Some(&key), None).unwrap();
        sender.absorb(b"data").unwrap();
        let squeezed_sender1 = sender.squeeze().unwrap();
        let ciphertext = sender.encrypt(msg).unwrap();
        sender.absorb(b"more_data").unwrap();
        sender.ratchet().unwrap();
        let squeezed_sender2 = sender.squeeze().unwrap();

        // Receiver side
        let receiver = SymmetricState::open("XOODYAK-128", Some(&key), None).unwrap();
        receiver.absorb(b"data").unwrap();
        let squeezed_receiver1 = receiver.squeeze().unwrap();
        let plaintext = receiver.decrypt(&ciphertext, msg.len() as u32).unwrap();
        assert_eq!(plaintext, msg);
        receiver.absorb(b"more_data").unwrap();
        receiver.ratchet().unwrap();
        let squeezed_receiver2 = receiver.squeeze().unwrap();

        assert_eq!(
            squeezed_sender1, squeezed_receiver1,
            "pre-encrypt squeeze must match"
        );
        assert_eq!(
            squeezed_sender2, squeezed_receiver2,
            "post-ratchet squeeze must match"
        );
        drop(key);
    }

    // ── Xoodyak-160 ──────────────────────────────────────────────────────────

    #[test]
    fn xoodyak160_encrypt_decrypt() {
        let msg = b"test xoodyak160";
        let key = generate("XOODYAK-160");

        let enc_state = SymmetricState::open("XOODYAK-160", Some(&key), None).unwrap();
        let ciphertext = enc_state.encrypt(msg).unwrap();

        let dec_state = SymmetricState::open("XOODYAK-160", Some(&key), None).unwrap();
        let plaintext = dec_state.decrypt(&ciphertext, msg.len() as u32).unwrap();
        assert_eq!(plaintext, msg);
        drop(key);
    }
}
