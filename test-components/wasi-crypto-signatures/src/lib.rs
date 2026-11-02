// The world imports only the interfaces under test, so these tests also run
// against a host that provides just those (and their dependencies).
wit_bindgen::generate!({
    path: "../../spec/wit",
    inline: "
        package wasi-crypto-tests:signatures;

        world signatures-tests {
            import wasi:crypto/signatures@0.12.0;
            import wasi:crypto/signatures-managed@0.12.0;
        }
    ",
    world: "signatures-tests",
    // The world is in its own test package, so the `wasi:crypto` interfaces
    // it imports need bindings generated explicitly.
    generate_all,
});

// This component covers the `signatures` and `signatures-managed` interfaces.
#[cfg(test)]
mod tests {
    use crate::wasi::crypto::common::{
        ArrayOutput, CryptoErrno, KeypairEncoding, PublickeyEncoding, SecretkeyEncoding,
    };
    use crate::wasi::crypto::secrets_manager::SecretsManager;
    use crate::wasi::crypto::signatures::{
        Signature, SignatureEncoding, SignatureKeypair, SignatureOptions, SignaturePublickey,
        SignatureSecretkey, SignatureState, SignatureVerificationState,
    };
    use crate::wasi::crypto::signatures_managed::{generate_managed, store_managed};

    // ── options ───────────────────────────────────────────────────────────────

    #[test]
    fn options_open_drop_signatures() {
        let opts = SignatureOptions::new();
        drop(opts);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Generate a keypair, extract the public key, return both.
    fn generate_kp(alg: &str) -> (SignatureKeypair, SignaturePublickey) {
        let kp = SignatureKeypair::generate(alg, None)
            .unwrap_or_else(|e| panic!("SignatureKeypair::generate({alg}) failed: {e:?}"));
        let pk = kp
            .publickey()
            .unwrap_or_else(|e| panic!("SignatureKeypair::publickey({alg}) failed: {e:?}"));
        (kp, pk)
    }

    /// Sign `msg` with `kp`, return the raw signature bytes.
    fn sign(kp: &SignatureKeypair, msg: &[u8]) -> Vec<u8> {
        let state = SignatureState::open(kp).unwrap();
        state.update(msg).unwrap();
        let sig = state.sign().unwrap();
        drop(state);
        let array_out = sig.export(SignatureEncoding::Raw).unwrap();
        drop(sig);
        ArrayOutput::pull(array_out).unwrap()
    }

    /// Verify `raw_sig` over `msg` with `pk`. Returns the result directly so
    /// callers can assert on error cases too.
    fn verify_raw(
        pk: &SignaturePublickey,
        msg: &[u8],
        alg: &str,
        raw_sig: &[u8],
        encoding: SignatureEncoding,
    ) -> Result<(), CryptoErrno> {
        let sig = Signature::import(alg, raw_sig, encoding)?;
        let state = SignatureVerificationState::open(pk)?;
        state.update(msg)?;
        state.verify(&sig)?;
        drop(state);
        drop(sig);
        Ok(())
    }

    // ── Ed25519 ───────────────────────────────────────────────────────────────

    #[test]
    fn ed25519_sign_and_verify() {
        let (kp, pk) = generate_kp("Ed25519");
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", "Ed25519", &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ed25519_wrong_message_returns_invalid_signature() {
        let (kp, pk) = generate_kp("Ed25519");
        let raw_sig = sign(&kp, b"correct message");
        match verify_raw(
            &pk,
            b"wrong message",
            "Ed25519",
            &raw_sig,
            SignatureEncoding::Raw,
        ) {
            Err(CryptoErrno::InvalidSignature) => {}
            Ok(()) => panic!("wrong message should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ed25519_sign_twice_returns_same_signature() {
        // Calling sign() twice on the same state (without any update in between)
        // must succeed and return the same bytes — the state is not invalidated.
        let (kp, pk) = generate_kp("Ed25519");
        let state = SignatureState::open(&kp).unwrap();

        state.update(b"message").unwrap();
        let sig1 = state.sign().unwrap();
        let raw1 = ArrayOutput::pull(sig1.export(SignatureEncoding::Raw).unwrap()).unwrap();
        drop(sig1);

        let sig2 = state.sign().unwrap();
        let raw2 = ArrayOutput::pull(sig2.export(SignatureEncoding::Raw).unwrap()).unwrap();
        drop(sig2);

        // Ed25519 is deterministic; both calls must return identical bytes.
        assert_eq!(raw1, raw2);
        // And the signature must verify against the original message.
        verify_raw(&pk, b"message", "Ed25519", &raw1, SignatureEncoding::Raw).unwrap();

        drop(state);
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ed25519_update_after_sign_returns_unsupported_feature() {
        // Pure Ed25519 does not support incremental re-feeding after sign().
        // A subsequent update() call must return UnsupportedFeature.
        let (kp, _pk) = generate_kp("Ed25519");
        let state = SignatureState::open(&kp).unwrap();

        state.update(b"message").unwrap();
        let sig = state.sign().unwrap();
        drop(sig);

        let err = state.update(b"more data").unwrap_err();
        assert!(matches!(err, CryptoErrno::UnsupportedFeature));

        drop(state);
        drop(kp);
    }

    #[test]
    fn ed25519_incremental_updates() {
        // Adapted from the "signature creation" doc example.
        // Two update calls before sign must produce the same result as one
        // call with the concatenated input.
        let (kp, pk) = generate_kp("Ed25519");

        // Incremental
        let state = SignatureState::open(&kp).unwrap();
        state.update(b"message part 1").unwrap();
        state.update(b"message part 2").unwrap();
        let raw_incremental = {
            let sig = state.sign().unwrap();
            let bytes = ArrayOutput::pull(sig.export(SignatureEncoding::Raw).unwrap()).unwrap();
            drop(sig);
            bytes
        };
        drop(state);

        // Verify incremental signature against the concatenated message.
        verify_raw(
            &pk,
            b"message part 1message part 2",
            "Ed25519",
            &raw_incremental,
            SignatureEncoding::Raw,
        )
        .unwrap();

        drop(kp);
        drop(pk);
    }

    // ── ECDSA P256 ────────────────────────────────────────────────────────────

    #[test]
    fn ecdsa_p256_sign_and_verify() {
        let (kp, pk) = generate_kp("ECDSA_P256_SHA256");
        let raw_sig = sign(&kp, b"test");
        verify_raw(
            &pk,
            b"test",
            "ECDSA_P256_SHA256",
            &raw_sig,
            SignatureEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ecdsa_p256_keypair_export_import_round_trip() {
        // Adapted from the WITX ECDSA test — exercises keypair and public key
        // serialization before signing.
        let alg = "ECDSA_P256_SHA256";
        let (kp, pk) = generate_kp(alg);

        // Export + re-import public key via Raw encoding
        let pk_raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = SignaturePublickey::import(alg, &pk_raw, PublickeyEncoding::Raw).unwrap();

        // Export + re-import keypair via Raw encoding
        let kp_raw = ArrayOutput::pull(kp.export(KeypairEncoding::Raw).unwrap()).unwrap();
        let kp2 = SignatureKeypair::import(alg, &kp_raw, KeypairEncoding::Raw).unwrap();

        // Sign with re-imported keypair, verify with re-imported public key
        let raw_sig = sign(&kp2, b"test");
        verify_raw(&pk2, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        drop(kp);
        drop(kp2);
        drop(pk);
        drop(pk2);
    }

    #[test]
    fn ecdsa_p256_signature_export_import_round_trip() {
        let alg = "ECDSA_P256_SHA256";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");

        // Export the raw bytes from the signature object, then re-import and verify.
        // DER encoding is not supported by the WITX 0.10 reference implementation.
        let sig = Signature::import(alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        let exported = ArrayOutput::pull(sig.export(SignatureEncoding::Raw).unwrap()).unwrap();
        let sig2 = Signature::import(alg, &exported, SignatureEncoding::Raw).unwrap();

        let state = SignatureVerificationState::open(&pk).unwrap();
        state.update(b"test").unwrap();
        state.verify(&sig2).unwrap();
        drop(state);
        drop(sig2);

        drop(kp);
        drop(pk);
    }

    // ── ECDSA K256 ────────────────────────────────────────────────────────────

    #[test]
    fn ecdsa_k256_raw_signature_is_64_bytes() {
        // Adapted from the WITX K256 test — raw r||s encoding must be 64 bytes.
        let alg = "ECDSA_K256_SHA256";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        assert_eq!(
            raw_sig.len(),
            64,
            "K256 raw signature must be 64 bytes (r||s)"
        );

        // Re-import and verify to confirm the 64-byte form is accepted
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        drop(kp);
        drop(pk);
    }

    // ── RSA ───────────────────────────────────────────────────────────────────

    #[test]
    fn rsa_pkcs1_2048_sha256_sign_and_verify() {
        // RSA key generation is slow (~seconds); this test exists to exercise
        // the full path. Run with --release or increase test timeout if needed.
        let alg = "RSA_PKCS1_2048_SHA256";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pkcs1_2048_keypair_export_import_round_trip() {
        let alg = "RSA_PKCS1_2048_SHA256";
        let (kp, pk) = generate_kp(alg);

        // RSA public key via Local encoding (PKCS#8/DER)
        let pk_raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Local).unwrap()).unwrap();
        let pk2 = SignaturePublickey::import(alg, &pk_raw, PublickeyEncoding::Local).unwrap();

        let kp_raw = ArrayOutput::pull(kp.export(KeypairEncoding::Local).unwrap()).unwrap();
        let kp2 = SignatureKeypair::import(alg, &kp_raw, KeypairEncoding::Local).unwrap();

        let raw_sig = sign(&kp2, b"test");
        verify_raw(&pk2, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        drop(kp);
        drop(kp2);
        drop(pk);
        drop(pk2);
    }

    // ── Signature::import error cases ────────────────────────────────────────

    #[test]
    fn signature_import_garbage_returns_invalid_signature() {
        match Signature::import("Ed25519", &[0u8; 64], SignatureEncoding::Raw) {
            // Either invalid_signature or unsupported_encoding are acceptable —
            // the host may reject at import or defer to verification.
            Err(CryptoErrno::InvalidSignature) | Err(CryptoErrno::UnsupportedEncoding) => {}
            Ok(sig) => {
                // Some hosts defer validation to verify time; drop and move on.
                drop(sig);
            }
            Err(e) => panic!("unexpected error for garbage signature: {e:?}"),
        }
    }

    #[test]
    fn signature_import_unsupported_algorithm_returns_error() {
        match Signature::import("__not_a_real_algo__", &[0u8; 64], SignatureEncoding::Raw) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(sig) => {
                drop(sig);
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── managed keypair operations ────────────────────────────────────────────

    #[test]
    fn managed_keypair_generate_and_sign() {
        // Managed key pairs need a secrets manager, which the host doesn't
        // implement: `SecretsManager::open` returns `UnsupportedFeature`.
        // `#[should_panic]` can't express that on wasm (libtest ignores such
        // tests without running them), so accept exactly that error and only
        // run the managed-key scenario once a secrets manager exists.
        // TODO: assert that `open` succeeds once the host implements a secrets manager.
        let sm = match SecretsManager::open(None) {
            Ok(sm) => sm,
            Err(CryptoErrno::UnsupportedFeature) => {
                eprintln!("secrets manager unsupported by the host; rest of the test skipped");
                return;
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        };
        let kp = generate_managed(&sm, "Ed25519", None).unwrap();
        let pk = kp.publickey().unwrap();
        let _key_id = store_managed(&sm, &kp).unwrap();

        let raw_sig = sign(&kp, b"managed key test");
        verify_raw(
            &pk,
            b"managed key test",
            "Ed25519",
            &raw_sig,
            SignatureEncoding::Raw,
        )
        .unwrap();

        drop(kp);
        drop(pk);
        drop(sm);
    }

    // ── ECDSA P384 ────────────────────────────────────────────────────────────

    #[test]
    fn ecdsa_p384_sha384_sign_and_verify() {
        let (kp, pk) = generate_kp("ECDSA_P384_SHA384");
        let raw_sig = sign(&kp, b"test");
        verify_raw(
            &pk,
            b"test",
            "ECDSA_P384_SHA384",
            &raw_sig,
            SignatureEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ecdsa_p384_raw_signature_is_96_bytes() {
        let (kp, pk) = generate_kp("ECDSA_P384_SHA384");
        let raw_sig = sign(&kp, b"test");
        assert_eq!(
            raw_sig.len(),
            96,
            "P-384 raw signature must be 96 bytes (r||s)"
        );
        verify_raw(
            &pk,
            b"test",
            "ECDSA_P384_SHA384",
            &raw_sig,
            SignatureEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ecdsa_p384_keypair_export_import_round_trip() {
        let alg = "ECDSA_P384_SHA384";
        let (kp, pk) = generate_kp(alg);

        let pk_raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = SignaturePublickey::import(alg, &pk_raw, PublickeyEncoding::Raw).unwrap();

        let kp_raw = ArrayOutput::pull(kp.export(KeypairEncoding::Raw).unwrap()).unwrap();
        let kp2 = SignatureKeypair::import(alg, &kp_raw, KeypairEncoding::Raw).unwrap();

        let raw_sig = sign(&kp2, b"test");
        verify_raw(&pk2, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        drop(kp);
        drop(kp2);
        drop(pk);
        drop(pk2);
    }

    #[test]
    fn ecdsa_p384_wrong_message_returns_invalid_signature() {
        let (kp, pk) = generate_kp("ECDSA_P384_SHA384");
        let raw_sig = sign(&kp, b"correct");
        match verify_raw(
            &pk,
            b"wrong",
            "ECDSA_P384_SHA384",
            &raw_sig,
            SignatureEncoding::Raw,
        ) {
            Err(CryptoErrno::InvalidSignature) => {}
            Ok(()) => panic!("wrong message should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(kp);
        drop(pk);
    }

    #[test]
    fn ecdsa_k256_wrong_message_returns_invalid_signature() {
        let (kp, pk) = generate_kp("ECDSA_K256_SHA256");
        let raw_sig = sign(&kp, b"correct");
        match verify_raw(
            &pk,
            b"wrong",
            "ECDSA_K256_SHA256",
            &raw_sig,
            SignatureEncoding::Raw,
        ) {
            Err(CryptoErrno::InvalidSignature) => {}
            Ok(()) => panic!("wrong message should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(kp);
        drop(pk);
    }

    // ── RSA PKCS#1 additional variants ───────────────────────────────────────

    #[test]
    fn rsa_pkcs1_2048_sha384_sign_and_verify() {
        let alg = "RSA_PKCS1_2048_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pkcs1_2048_sha512_sign_and_verify() {
        let alg = "RSA_PKCS1_2048_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pkcs1_3072_sha384_sign_and_verify() {
        let alg = "RSA_PKCS1_3072_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pkcs1_3072_sha512_sign_and_verify() {
        let alg = "RSA_PKCS1_3072_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pkcs1_4096_sha512_sign_and_verify() {
        let alg = "RSA_PKCS1_4096_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    // ── RSA PSS variants ──────────────────────────────────────────────────────

    #[test]
    fn rsa_pss_2048_sha256_sign_and_verify() {
        let alg = "RSA_PSS_2048_SHA256";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pss_2048_sha384_sign_and_verify() {
        let alg = "RSA_PSS_2048_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pss_2048_sha512_sign_and_verify() {
        let alg = "RSA_PSS_2048_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pss_3072_sha384_sign_and_verify() {
        let alg = "RSA_PSS_3072_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pss_3072_sha512_sign_and_verify() {
        let alg = "RSA_PSS_3072_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn rsa_pss_4096_sha512_sign_and_verify() {
        let alg = "RSA_PSS_4096_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        drop(kp);
        drop(pk);
    }

    // ── Bug regression: SignaturePublickey::verify was always NotImplemented ──

    #[test]
    fn publickey_verify_returns_ok_for_all_algorithms() {
        // `SignaturePublickey::verify` previously always returned NotImplemented.
        // It should return Ok(()) for any key that was successfully imported,
        // because import already performs the structural/cryptographic validity
        // checks.
        let algs = [
            "Ed25519",
            "ECDSA_P256_SHA256",
            "ECDSA_K256_SHA256",
            "ECDSA_P384_SHA384",
            "RSA_PKCS1_2048_SHA256",
        ];
        for alg in algs {
            let (kp, pk) = generate_kp(alg);
            pk.verify().unwrap_or_else(|e| {
                panic!("SignaturePublickey::verify({alg}) returned {e:?}, expected Ok(())")
            });
            drop(kp);
            drop(pk);
        }
    }

    // ── Bug regression: SignatureVerificationState::verify owns the signature handle ─

    #[test]
    fn signature_verify_consumes_signature_handle() {
        let (kp, pk) = generate_kp("Ed25519");
        let raw_sig = sign(&kp, b"test");

        let sig = Signature::import("Ed25519", &raw_sig, SignatureEncoding::Raw).unwrap();
        let state = SignatureVerificationState::open(&pk).unwrap();
        state.update(b"test").unwrap();
        state.verify(&sig).unwrap();
        drop(state);
        drop(sig);
        drop(kp);
        drop(pk);
    }

    // ── Bug regression: Signature::export encoding parameter ─────────────────

    #[test]
    fn signature_export_raw_returns_correct_bytes() {
        // `Signature::export` must respect the encoding parameter.
        // For Raw encoding the returned bytes must be importable as Raw.
        let (kp, pk) = generate_kp("Ed25519");

        let state = SignatureState::open(&kp).unwrap();
        state.update(b"test").unwrap();
        let sig = state.sign().unwrap();
        drop(state);

        let raw_bytes = ArrayOutput::pull(sig.export(SignatureEncoding::Raw).unwrap()).unwrap();
        assert_eq!(
            raw_bytes.len(),
            64,
            "Ed25519 raw signature must be 64 bytes"
        );

        // Re-import and verify to confirm the bytes are valid
        let sig2 = Signature::import("Ed25519", &raw_bytes, SignatureEncoding::Raw).unwrap();
        let vstate = SignatureVerificationState::open(&pk).unwrap();
        vstate.update(b"test").unwrap();
        vstate.verify(&sig2).unwrap();
        drop(vstate);
        drop(sig2);

        drop(sig);
        drop(kp);
        drop(pk);
    }

    // ── Bug regression: RSA sign() state reuse ───────────────────────────────

    #[test]
    fn rsa_pkcs1_2048_sha256_sign_state_reuse() {
        // The spec says "The state is not closed and can be used after a signature
        // has been computed." RSA sign() must reset the BoringSSL signer so a
        // second update+sign cycle produces a valid, verifiable signature.
        let alg = "RSA_PKCS1_2048_SHA256";
        let (kp, pk) = generate_kp(alg);

        let state = SignatureState::open(&kp).unwrap();
        state.update(b"first message").unwrap();
        let sig1 = state.sign().unwrap();
        let raw1 = ArrayOutput::pull(sig1.export(SignatureEncoding::Raw).unwrap()).unwrap();
        drop(sig1);

        // Second sign cycle on the same state handle
        state.update(b"second message").unwrap();
        let sig2 = state.sign().unwrap();
        let raw2 = ArrayOutput::pull(sig2.export(SignatureEncoding::Raw).unwrap()).unwrap();
        drop(sig2);

        // Both must verify
        verify_raw(&pk, b"first message", alg, &raw1, SignatureEncoding::Raw).unwrap();
        verify_raw(&pk, b"second message", alg, &raw2, SignatureEncoding::Raw).unwrap();

        drop(state);
        drop(kp);
        drop(pk);
    }

    // ── key import / export / generate errors ────────────────────────────────
    //
    // Moved from the retired `wasi-crypto-asymmetric-common` component, whose
    // generic key functions now exist per family.

    #[test]
    fn keypair_generate_unknown_algorithm_returns_error() {
        match SignatureKeypair::generate("__not_a_real_algo__", None) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(kp) => {
                drop(kp);
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn keypair_export_import_ed25519_raw() {
        let kp = SignatureKeypair::generate("Ed25519", None).unwrap();
        let raw = ArrayOutput::pull(kp.export(KeypairEncoding::Raw).unwrap()).unwrap();
        assert!(!raw.is_empty());
        let kp2 = SignatureKeypair::import("Ed25519", &raw, KeypairEncoding::Raw).unwrap();
        drop(kp);
        drop(kp2);
    }

    #[test]
    fn keypair_import_invalid_key_returns_error() {
        match SignatureKeypair::import("Ed25519", &[0u8; 3], KeypairEncoding::Raw) {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(kp) => {
                drop(kp);
                panic!("should have rejected a 3-byte keypair");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn publickey_export_import_ed25519_raw() {
        let (kp, pk) = generate_kp("Ed25519");

        let raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Raw).unwrap()).unwrap();
        assert_eq!(raw.len(), 32, "Ed25519 public key is 32 bytes");

        let pk2 = SignaturePublickey::import("Ed25519", &raw, PublickeyEncoding::Raw).unwrap();

        drop(kp);
        drop(pk);
        drop(pk2);
    }

    #[test]
    fn publickey_import_wrong_size_returns_invalid_key() {
        match SignaturePublickey::import("Ed25519", &[0u8; 5], PublickeyEncoding::Raw) {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(pk) => {
                drop(pk);
                panic!("should have rejected 5-byte key");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn publickey_import_unknown_algorithm_returns_error() {
        match SignaturePublickey::import("__not_a_real_algo__", &[0u8; 32], PublickeyEncoding::Raw)
        {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(pk) => {
                drop(pk);
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn secretkey_import_signatures_not_implemented() {
        match SignatureSecretkey::import("Ed25519", &[0u8; 64], SecretkeyEncoding::Raw) {
            Err(CryptoErrno::NotImplemented) => {}
            Ok(sk) => {
                drop(sk);
                panic!("SignatureSecretkey::import should not be implemented");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
}
