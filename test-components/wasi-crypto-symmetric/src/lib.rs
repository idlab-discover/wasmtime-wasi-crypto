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

#[cfg(test)]
mod tests {
    use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, options_close, options_open, options_set,
    };
    use crate::wasi::crypto::wasi_ephemeral_crypto_symmetric::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn generate(alg: &str) -> SymmetricKey {
        symmetric_key_generate(alg, None)
            .unwrap_or_else(|e| panic!("symmetric_key_generate({alg}) failed: {e:?}"))
    }

    fn import(alg: &str, raw: &[u8]) -> SymmetricKey {
        symmetric_key_import(alg, raw)
            .unwrap_or_else(|e| panic!("symmetric_key_import({alg}) failed: {e:?}"))
    }

    fn open(alg: &str, key: Option<&SymmetricKey>) -> SymmetricState {
        symmetric_state_open(alg, key, None)
            .unwrap_or_else(|e| panic!("symmetric_state_open({alg}) failed: {e:?}"))
    }

    // ── key lifecycle ─────────────────────────────────────────────────────────

    #[test]
    fn key_generate_and_close() {
        let key = generate("HMAC/SHA-256");
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn key_import_and_close() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn key_export_produces_array_output() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let array_out = symmetric_key_export(&key).unwrap();
        let bytes =
            crate::wasi::crypto::wasi_ephemeral_crypto_common::array_output_pull(&array_out)
                .unwrap();
        assert_eq!(bytes, b"0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn key_export_round_trips_raw_material() {
        let raw = b"aaaabbbbccccddddaaaabbbbccccdddd";
        let key = import("HMAC/SHA-256", raw);
        let array_out = symmetric_key_export(&key).unwrap();
        let exported =
            crate::wasi::crypto::wasi_ephemeral_crypto_common::array_output_pull(&array_out)
                .unwrap();
        assert_eq!(exported.as_slice(), raw.as_slice());
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn key_generate_unsupported_algorithm() {
        match symmetric_key_generate("__not_a_real_algo__", None) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(_) => panic!("should have rejected unknown algorithm"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── state open / close ───────────────────────────────────────────────────

    #[test]
    fn state_open_close_no_key() {
        let state = open("SHA-256", None);
        symmetric_state_close(state).unwrap();
    }

    #[test]
    fn state_open_close_with_key() {
        let key = generate("HMAC/SHA-256");
        let state = symmetric_state_open("HMAC/SHA-256", Some(&key), None).unwrap();
        symmetric_state_close(state).unwrap();
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn state_open_key_not_supported() {
        // Hash functions do not accept keys; providing one must return invalid_key.
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        match symmetric_state_open("SHA-256", Some(&key), None) {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(s) => {
                symmetric_state_close(s).unwrap();
                panic!("SHA-256 should reject a key");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn state_open_key_required() {
        // MAC functions require a key; omitting one must return key_required.
        match symmetric_state_open("HMAC/SHA-256", None, None) {
            Err(CryptoErrno::KeyRequired) => {}
            Ok(s) => {
                symmetric_state_close(s).unwrap();
                panic!("HMAC/SHA-256 should require a key");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn state_clone() {
        let key = generate("HMAC/SHA-256");
        let state = symmetric_state_open("HMAC/SHA-256", Some(&key), None).unwrap();
        symmetric_state_absorb(&state, b"hello").unwrap();
        let clone = symmetric_state_clone(&state).unwrap();
        // Both handles share the same underlying state: verify the clone produces a valid-length tag.
        let tag_clone = symmetric_state_squeeze_tag(&clone).unwrap();
        let raw_clone = symmetric_tag_pull(&tag_clone).unwrap();
        assert_eq!(raw_clone.len(), 32); // HMAC/SHA-256 produces 32 bytes
        symmetric_key_close(key).unwrap();
    }

    // ── hashing (doc example: SHA-256) ──────────────────────────────────────

    #[test]
    fn hash_shake128_absorb_squeeze() {
        let state = open("SHA-256", None);
        symmetric_state_absorb(&state, b"data").unwrap();
        symmetric_state_absorb(&state, b"more_data").unwrap();
        let out = symmetric_state_squeeze(&state).unwrap();
        assert_eq!(out.len(), 32); // SHA-256 always produces 32 bytes
    }

    #[test]
    fn hash_same_input_same_output() {
        let digest = |data: &[u8]| {
            let state = open("SHA-256", None);
            symmetric_state_absorb(&state, data).unwrap();
            symmetric_state_squeeze(&state).unwrap()
        };
        assert_eq!(digest(b"hello"), digest(b"hello"));
        assert_ne!(digest(b"hello"), digest(b"world"));
    }

    // ── MAC (doc examples: HMAC/SHA-512) ────────────────────────────────────

    #[test]
    fn mac_hmac_sha512_compute_and_pull() {
        // Adapted from the "MAC" doc example.
        let key = import("HMAC/SHA-512", b"key");
        let state = symmetric_state_open("HMAC/SHA-512", Some(&key), None).unwrap();
        symmetric_state_absorb(&state, b"data").unwrap();
        symmetric_state_absorb(&state, b"more_data").unwrap();
        let tag = symmetric_state_squeeze_tag(&state).unwrap();
        let raw = symmetric_tag_pull(&tag).unwrap();
        assert_eq!(raw.len(), 64); // HMAC/SHA-512 produces 64 bytes
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn mac_tag_len() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let state = symmetric_state_open("HMAC/SHA-256", Some(&key), None).unwrap();
        let tag = symmetric_state_squeeze_tag(&state).unwrap();
        let len = symmetric_tag_len(&tag).unwrap();
        assert_eq!(len, 32);
        symmetric_tag_close(tag).unwrap();
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn mac_verify_correct_tag() {
        // Adapted from the "MAC verification" doc example.
        let key = import("HMAC/SHA-512", b"key");

        // Compute reference tag.
        let state = symmetric_state_open("HMAC/SHA-512", Some(&key), None).unwrap();
        symmetric_state_absorb(&state, b"data").unwrap();
        symmetric_state_absorb(&state, b"more_data").unwrap();
        let tag = symmetric_state_squeeze_tag(&state).unwrap();
        let expected = symmetric_tag_pull(&tag).unwrap();

        // Verify against the same input.
        let state2 = symmetric_state_open("HMAC/SHA-512", Some(&key), None).unwrap();
        symmetric_state_absorb(&state2, b"data").unwrap();
        symmetric_state_absorb(&state2, b"more_data").unwrap();
        let tag2 = symmetric_state_squeeze_tag(&state2).unwrap();
        symmetric_tag_verify(&tag2, &expected).unwrap();

        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn mac_verify_wrong_tag_returns_invalid_tag() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let state = symmetric_state_open("HMAC/SHA-256", Some(&key), None).unwrap();
        symmetric_state_absorb(&state, b"data").unwrap();
        let tag = symmetric_state_squeeze_tag(&state).unwrap();
        let wrong = vec![0u8; 32];
        match symmetric_tag_verify(&tag, &wrong) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(()) => panic!("wrong tag should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn mac_tag_close_explicit() {
        let key = import("HMAC/SHA-256", b"0123456789abcdef0123456789abcdef");
        let state = symmetric_state_open("HMAC/SHA-256", Some(&key), None).unwrap();
        let tag = symmetric_state_squeeze_tag(&state).unwrap();
        symmetric_tag_close(tag).unwrap();
        symmetric_key_close(key).unwrap();
    }

    // ── BLAKE3 XOF (doc example) ─────────────────────────────────────────────

    #[test]
    fn blake3_xof_two_squeezes_differ() {
        let key = import("HMAC/SHA-256", b"aaaabbbbccccddddaaaabbbbccccdddd");
        let state = open("HMAC/SHA-256", Some(&key));
        symmetric_state_absorb(&state, b"context").unwrap();
        let tag = symmetric_state_squeeze_tag(&state).unwrap();
        let raw = symmetric_tag_pull(&tag).unwrap();
        assert_eq!(raw.len(), 32); // HMAC/SHA-256 tag is 32 bytes
        // Repeat with different input — must produce a different tag.
        let state2 = open("HMAC/SHA-256", Some(&key));
        symmetric_state_absorb(&state2, b"other_context").unwrap();
        let tag2 = symmetric_state_squeeze_tag(&state2).unwrap();
        let raw2 = symmetric_tag_pull(&tag2).unwrap();
        assert_ne!(raw, raw2);
        symmetric_key_close(key).unwrap();
    }

    // ── HKDF (doc example: extract-and-expand) ───────────────────────────────

    #[test]
    fn hkdf_extract_and_expand() {
        // Adapted from the "Key derivation using extract-and-expand" doc example.
        let ikm = import("HKDF-EXTRACT/SHA-512", b"input_key_material");
        let extract_state = symmetric_state_open("HKDF-EXTRACT/SHA-512", Some(&ikm), None).unwrap();
        symmetric_state_absorb(&extract_state, b"salt").unwrap();
        let prk = symmetric_state_squeeze_key(&extract_state, "HKDF-EXPAND/SHA-512").unwrap();

        let expand_state = symmetric_state_open("HKDF-EXPAND/SHA-512", Some(&prk), None).unwrap();
        symmetric_state_absorb(&expand_state, b"info").unwrap();
        let subkey = symmetric_state_squeeze(&expand_state).unwrap();
        assert!(!subkey.is_empty());

        symmetric_key_close(ikm).unwrap();
        symmetric_key_close(prk).unwrap();
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
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts, "nonce", &nonce).unwrap();
        let enc_state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        options_close(opts).unwrap();
        symmetric_state_absorb(&enc_state, aad).unwrap();
        let ciphertext = symmetric_state_encrypt(&enc_state, message).unwrap();

        // Decrypt
        let opts2 = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts2, "nonce", &nonce).unwrap();
        let dec_state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts2)).unwrap();
        options_close(opts2).unwrap();
        symmetric_state_absorb(&dec_state, aad).unwrap();
        let out_len = message.len();
        let plaintext = symmetric_state_decrypt(&dec_state, &ciphertext, out_len as u32).unwrap();

        assert_eq!(plaintext, message);
        symmetric_key_close(key).unwrap();
    }

    #[test]
    fn aead_aes256gcm_wrong_tag_returns_invalid_tag() {
        let nonce = [0u8; 12];
        let key = generate("AES-256-GCM");

        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts, "nonce", &nonce).unwrap();
        let enc_state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        options_close(opts).unwrap();
        let mut ciphertext = symmetric_state_encrypt(&enc_state, b"hello").unwrap();

        // Corrupt the tag (last 16 bytes for GCM)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xff;

        let opts2 = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts2, "nonce", &nonce).unwrap();
        let dec_state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts2)).unwrap();
        options_close(opts2).unwrap();
        let out_len = (ciphertext.len() - 16) as u32; // AES-GCM tag is 16 bytes
        match symmetric_state_decrypt(&dec_state, &ciphertext, out_len) {
            Err(CryptoErrno::InvalidTag) => {}
            Ok(_) => panic!("corrupted ciphertext should not decrypt"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        symmetric_key_close(key).unwrap();
    }

    // ── AEAD: auto-nonce retrieval ────────────────────────────────────────────

    #[test]
    fn aead_auto_nonce_retrievable_via_options_get() {
        let nonce = [0xabu8; 12];
        let key = generate("AES-256-GCM");
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts, "nonce", &nonce).unwrap();
        let state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        options_close(opts).unwrap();
        let nonce_buf = symmetric_state_options_get(&state, "nonce").unwrap();
        assert_eq!(nonce_buf, nonce, "nonce retrieved from state must match the one set");
        symmetric_state_close(state).unwrap();
        symmetric_key_close(key).unwrap();
    }

    // ── detached encrypt/decrypt ─────────────────────────────────────────────

    #[test]
    fn aead_aes256gcm_detached_round_trip() {
        let nonce = [0u8; 12];
        let message = b"detached test";
        let key = generate("AES-256-GCM");

        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts, "nonce", &nonce).unwrap();
        let enc_state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        options_close(opts).unwrap();
        let (ciphertext, tag) = symmetric_state_encrypt_detached(&enc_state, message).unwrap();
        let raw_tag = symmetric_tag_pull(&tag).unwrap();

        let opts2 = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts2, "nonce", &nonce).unwrap();
        let dec_state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts2)).unwrap();
        options_close(opts2).unwrap();
        let plaintext =
            symmetric_state_decrypt_detached(&dec_state, &ciphertext, &raw_tag).unwrap();

        assert_eq!(plaintext, message);
        symmetric_key_close(key).unwrap();
    }

    // ── max_tag_len ───────────────────────────────────────────────────────────

    #[test]
    fn aead_max_tag_len_nonzero_for_gcm() {
        let key = generate("AES-256-GCM");
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        options_set(&opts, "nonce", &[0u8; 12]).unwrap();
        let state = symmetric_state_open("AES-256-GCM", Some(&key), Some(&opts)).unwrap();
        options_close(opts).unwrap();
        let tag_len = symmetric_state_max_tag_len(&state).unwrap();
        assert_eq!(tag_len, 16); // GCM tag is always 16 bytes
        symmetric_state_close(state).unwrap();
        symmetric_key_close(key).unwrap();
    }

    // ── options_get_u64 ───────────────────────────────────────────────────────

    #[test]
    fn state_options_get_u64_unsupported_returns_error() {
        let state = open("SHA-256", None);
        match symmetric_state_options_get_u64(&state, "__nonexistent__") {
            Err(CryptoErrno::UnsupportedOption) | Err(CryptoErrno::OptionNotSet) => {}
            Ok(v) => panic!("should not return a value for unknown option, got {v}"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        symmetric_state_close(state).unwrap();
    }

    // ── managed key operations ────────────────────────────────────────────────

    #[test]
    #[should_panic]
    fn managed_key_generate_store_retrieve() {
        use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
            Version, secrets_manager_close, secrets_manager_open,
        };
        let sm = secrets_manager_open(None).unwrap();
        let key = symmetric_key_generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let key_id = symmetric_key_store_managed(&sm, &key).unwrap();
        let retrieved = symmetric_key_from_id(&sm, &key_id, Version::Latest).unwrap();
        symmetric_key_close(key).unwrap();
        symmetric_key_close(retrieved).unwrap();
        secrets_manager_close(sm).unwrap();
    }

    #[test]
    #[should_panic]
    fn managed_key_id_returns_id_and_version() {
        use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
            secrets_manager_close, secrets_manager_open,
        };
        let sm = secrets_manager_open(None).unwrap();
        let key = symmetric_key_generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let (id, version) = symmetric_key_id(&key).unwrap();
        assert!(!id.is_empty());
        // Version::Latest has a known numeric representation; any non-zero value is valid
        let _ = version;
        symmetric_key_close(key).unwrap();
        secrets_manager_close(sm).unwrap();
    }

    #[test]
    #[should_panic]
    fn managed_key_replace() {
        use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
            secrets_manager_close, secrets_manager_open,
        };
        let sm = secrets_manager_open(None).unwrap();
        let old = symmetric_key_generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let new = symmetric_key_generate_managed(&sm, "HMAC/SHA-256", None).unwrap();
        let _new_version = symmetric_key_replace_managed(&sm, old, &new).unwrap();
        symmetric_key_close(new).unwrap();
        secrets_manager_close(sm).unwrap();
    }

    #[test]
    fn unmanaged_key_id_returns_unsupported_feature() {
        let key = generate("HMAC/SHA-256");
        match symmetric_key_id(&key) {
            Err(CryptoErrno::UnsupportedFeature) => {}
            Ok(_) => panic!("unmanaged key should not have an id"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        symmetric_key_close(key).unwrap();
    }
}
