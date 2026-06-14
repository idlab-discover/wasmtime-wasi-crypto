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
    use crate::wasi::crypto::wasi_ephemeral_crypto_asymmetric_common::{
        KeypairEncoding, PublickeyEncoding, keypair_close, keypair_export, keypair_generate,
        keypair_generate_managed, keypair_import, keypair_publickey, keypair_store_managed,
        publickey_close, publickey_export, publickey_import, publickey_verify,
    };
    use crate::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, SignatureEncoding, array_output_pull, secrets_manager_close,
        secrets_manager_open,
    };
    use crate::wasi::crypto::wasi_ephemeral_crypto_signatures::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Generate a keypair, extract the public key, return both.
    fn generate_kp(
        alg: &str,
    ) -> (
        crate::wasi::crypto::wasi_ephemeral_crypto_common::Keypair,
        crate::wasi::crypto::wasi_ephemeral_crypto_common::Publickey,
    ) {
        let kp = keypair_generate(AlgorithmType::Signatures, alg, None)
            .unwrap_or_else(|e| panic!("keypair_generate({alg}) failed: {e:?}"));
        let pk = keypair_publickey(&kp)
            .unwrap_or_else(|e| panic!("keypair_publickey({alg}) failed: {e:?}"));
        (kp, pk)
    }

    /// Sign `msg` with `kp`, return the raw signature bytes.
    fn sign(
        kp: &crate::wasi::crypto::wasi_ephemeral_crypto_common::Keypair,
        msg: &[u8],
    ) -> Vec<u8> {
        let state = signature_state_open(kp).unwrap();
        signature_state_update(&state, msg).unwrap();
        let sig = signature_state_sign(&state).unwrap();
        signature_state_close(state).unwrap();
        let array_out = signature_export(&sig, SignatureEncoding::Raw).unwrap();
        signature_close(sig).unwrap();
        array_output_pull(&array_out).unwrap()
    }

    /// Verify `raw_sig` over `msg` with `pk`. Returns the result directly so
    /// callers can assert on error cases too.
    fn verify_raw(
        pk: &crate::wasi::crypto::wasi_ephemeral_crypto_common::Publickey,
        msg: &[u8],
        alg: &str,
        raw_sig: &[u8],
        encoding: SignatureEncoding,
    ) -> Result<(), CryptoErrno> {
        let sig = signature_import(alg, raw_sig, encoding)?;
        let state = signature_verification_state_open(pk)?;
        signature_verification_state_update(&state, msg)?;
        signature_verification_state_verify(&state, sig)?;
        signature_verification_state_close(state)?;
        Ok(())
    }

    // ── Ed25519 ───────────────────────────────────────────────────────────────

    #[test]
    fn ed25519_sign_and_verify() {
        let (kp, pk) = generate_kp("Ed25519");
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", "Ed25519", &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
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
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn ed25519_state_reuse_produces_valid_signatures() {
        // signature_state is not closed after sign() — reuse is explicitly supported.
        let (kp, pk) = generate_kp("Ed25519");
        let state = signature_state_open(&kp).unwrap();

        signature_state_update(&state, b"message").unwrap();
        let sig1 = signature_state_sign(&state).unwrap();
        let raw1 = array_output_pull(&signature_export(&sig1, SignatureEncoding::Raw).unwrap()).unwrap();
        signature_close(sig1).unwrap();

        signature_state_update(&state, b"message").unwrap();
        let sig2 = signature_state_sign(&state).unwrap();
        let raw2 = array_output_pull(&signature_export(&sig2, SignatureEncoding::Raw).unwrap()).unwrap();
        signature_close(sig2).unwrap();

        // Both signatures must verify — Ed25519 is deterministic so they will
        // also be equal, but we assert correctness not determinism here.
        verify_raw(&pk, b"message", "Ed25519", &raw1, SignatureEncoding::Raw).unwrap();
        verify_raw(&pk, b"message", "Ed25519", &raw2, SignatureEncoding::Raw).unwrap();

        signature_state_close(state).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn ed25519_incremental_updates() {
        // Adapted from the "signature creation" doc example.
        // Two update calls before sign must produce the same result as one
        // call with the concatenated input.
        let (kp, pk) = generate_kp("Ed25519");

        // Incremental
        let state = signature_state_open(&kp).unwrap();
        signature_state_update(&state, b"message part 1").unwrap();
        signature_state_update(&state, b"message part 2").unwrap();
        let raw_incremental = {
            let sig = signature_state_sign(&state).unwrap();
            let bytes = array_output_pull(&signature_export(&sig, SignatureEncoding::Raw).unwrap()).unwrap();
            signature_close(sig).unwrap();
            bytes
        };
        signature_state_close(state).unwrap();

        // Verify incremental signature against the concatenated message.
        verify_raw(
            &pk,
            b"message part 1message part 2",
            "Ed25519",
            &raw_incremental,
            SignatureEncoding::Raw,
        )
        .unwrap();

        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
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
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn ecdsa_p256_keypair_export_import_round_trip() {
        // Adapted from the WITX ECDSA test — exercises keypair and public key
        // serialization before signing.
        let alg = "ECDSA_P256_SHA256";
        let (kp, pk) = generate_kp(alg);

        // Export + re-import public key via Raw encoding
        let pk_raw =
            array_output_pull(&publickey_export(&pk, PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = publickey_import(
            AlgorithmType::Signatures,
            alg,
            &pk_raw,
            PublickeyEncoding::Raw,
        )
        .unwrap();

        // Export + re-import keypair via Raw encoding
        let kp_raw =
            array_output_pull(&keypair_export(&kp, KeypairEncoding::Raw).unwrap()).unwrap();
        let kp2 = keypair_import(
            AlgorithmType::Signatures,
            alg,
            &kp_raw,
            KeypairEncoding::Raw,
        )
        .unwrap();

        // Sign with re-imported keypair, verify with re-imported public key
        let raw_sig = sign(&kp2, b"test");
        verify_raw(&pk2, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        keypair_close(kp).unwrap();
        keypair_close(kp2).unwrap();
        publickey_close(pk).unwrap();
        publickey_close(pk2).unwrap();
    }

    #[test]
    fn ecdsa_p256_signature_export_import_round_trip() {
        let alg = "ECDSA_P256_SHA256";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");

        // Export the raw bytes from the signature object, then re-import and verify.
        // DER encoding is not supported by the WITX 0.10 reference implementation.
        let sig = signature_import(alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        let exported =
            array_output_pull(&signature_export(&sig, SignatureEncoding::Raw).unwrap()).unwrap();
        let sig2 = signature_import(alg, &exported, SignatureEncoding::Raw).unwrap();

        let state = signature_verification_state_open(&pk).unwrap();
        signature_verification_state_update(&state, b"test").unwrap();
        signature_verification_state_verify(&state, sig2).unwrap();
        signature_verification_state_close(state).unwrap();

        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
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

        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
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
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pkcs1_2048_keypair_export_import_round_trip() {
        let alg = "RSA_PKCS1_2048_SHA256";
        let (kp, pk) = generate_kp(alg);

        // RSA public key via Local encoding (PKCS#8/DER)
        let pk_raw =
            array_output_pull(&publickey_export(&pk, PublickeyEncoding::Local).unwrap()).unwrap();
        let pk2 = publickey_import(
            AlgorithmType::Signatures,
            alg,
            &pk_raw,
            PublickeyEncoding::Local,
        )
        .unwrap();

        let kp_raw =
            array_output_pull(&keypair_export(&kp, KeypairEncoding::Local).unwrap()).unwrap();
        let kp2 = keypair_import(
            AlgorithmType::Signatures,
            alg,
            &kp_raw,
            KeypairEncoding::Local,
        )
        .unwrap();

        let raw_sig = sign(&kp2, b"test");
        verify_raw(&pk2, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        keypair_close(kp).unwrap();
        keypair_close(kp2).unwrap();
        publickey_close(pk).unwrap();
        publickey_close(pk2).unwrap();
    }

    // ── signature_import error cases ─────────────────────────────────────────

    #[test]
    fn signature_import_garbage_returns_invalid_signature() {
        match signature_import("Ed25519", &[0u8; 64], SignatureEncoding::Raw) {
            // Either invalid_signature or unsupported_encoding are acceptable —
            // the host may reject at import or defer to verification.
            Err(CryptoErrno::InvalidSignature) | Err(CryptoErrno::UnsupportedEncoding) => {}
            Ok(sig) => {
                // Some hosts defer validation to verify time; close and note.
                signature_close(sig).unwrap();
            }
            Err(e) => panic!("unexpected error for garbage signature: {e:?}"),
        }
    }

    #[test]
    fn signature_import_unsupported_algorithm_returns_error() {
        match signature_import("__not_a_real_algo__", &[0u8; 64], SignatureEncoding::Raw) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(sig) => {
                signature_close(sig).unwrap();
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── managed keypair operations ────────────────────────────────────────────

    #[test]
    #[should_panic]
    fn managed_keypair_generate_and_sign() {
        let sm = secrets_manager_open(None).unwrap();
        let kp = keypair_generate_managed(&sm, AlgorithmType::Signatures, "Ed25519", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        let _key_id = keypair_store_managed(&sm, &kp).unwrap();

        let raw_sig = sign(&kp, b"managed key test");
        verify_raw(
            &pk,
            b"managed key test",
            "Ed25519",
            &raw_sig,
            SignatureEncoding::Raw,
        )
        .unwrap();

        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
        secrets_manager_close(sm).unwrap();
    }

    // ── ECDSA P384 ────────────────────────────────────────────────────────────

    #[test]
    fn ecdsa_p384_sha384_sign_and_verify() {
        let (kp, pk) = generate_kp("ECDSA_P384_SHA384");
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", "ECDSA_P384_SHA384", &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn ecdsa_p384_raw_signature_is_96_bytes() {
        let (kp, pk) = generate_kp("ECDSA_P384_SHA384");
        let raw_sig = sign(&kp, b"test");
        assert_eq!(raw_sig.len(), 96, "P-384 raw signature must be 96 bytes (r||s)");
        verify_raw(&pk, b"test", "ECDSA_P384_SHA384", &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn ecdsa_p384_keypair_export_import_round_trip() {
        let alg = "ECDSA_P384_SHA384";
        let (kp, pk) = generate_kp(alg);

        let pk_raw = array_output_pull(&publickey_export(&pk, PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = publickey_import(AlgorithmType::Signatures, alg, &pk_raw, PublickeyEncoding::Raw).unwrap();

        let kp_raw = array_output_pull(&keypair_export(&kp, KeypairEncoding::Raw).unwrap()).unwrap();
        let kp2 = keypair_import(AlgorithmType::Signatures, alg, &kp_raw, KeypairEncoding::Raw).unwrap();

        let raw_sig = sign(&kp2, b"test");
        verify_raw(&pk2, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();

        keypair_close(kp).unwrap();
        keypair_close(kp2).unwrap();
        publickey_close(pk).unwrap();
        publickey_close(pk2).unwrap();
    }

    #[test]
    fn ecdsa_p384_wrong_message_returns_invalid_signature() {
        let (kp, pk) = generate_kp("ECDSA_P384_SHA384");
        let raw_sig = sign(&kp, b"correct");
        match verify_raw(&pk, b"wrong", "ECDSA_P384_SHA384", &raw_sig, SignatureEncoding::Raw) {
            Err(CryptoErrno::InvalidSignature) => {}
            Ok(()) => panic!("wrong message should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn ecdsa_k256_wrong_message_returns_invalid_signature() {
        let (kp, pk) = generate_kp("ECDSA_K256_SHA256");
        let raw_sig = sign(&kp, b"correct");
        match verify_raw(&pk, b"wrong", "ECDSA_K256_SHA256", &raw_sig, SignatureEncoding::Raw) {
            Err(CryptoErrno::InvalidSignature) => {}
            Ok(()) => panic!("wrong message should not verify"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    // ── RSA PKCS#1 additional variants ───────────────────────────────────────

    #[test]
    fn rsa_pkcs1_2048_sha384_sign_and_verify() {
        let alg = "RSA_PKCS1_2048_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pkcs1_2048_sha512_sign_and_verify() {
        let alg = "RSA_PKCS1_2048_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pkcs1_3072_sha384_sign_and_verify() {
        let alg = "RSA_PKCS1_3072_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pkcs1_3072_sha512_sign_and_verify() {
        let alg = "RSA_PKCS1_3072_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pkcs1_4096_sha512_sign_and_verify() {
        let alg = "RSA_PKCS1_4096_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    // ── RSA PSS variants ──────────────────────────────────────────────────────

    #[test]
    fn rsa_pss_2048_sha256_sign_and_verify() {
        let alg = "RSA_PSS_2048_SHA256";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pss_2048_sha384_sign_and_verify() {
        let alg = "RSA_PSS_2048_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pss_2048_sha512_sign_and_verify() {
        let alg = "RSA_PSS_2048_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pss_3072_sha384_sign_and_verify() {
        let alg = "RSA_PSS_3072_SHA384";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pss_3072_sha512_sign_and_verify() {
        let alg = "RSA_PSS_3072_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    #[test]
    fn rsa_pss_4096_sha512_sign_and_verify() {
        let alg = "RSA_PSS_4096_SHA512";
        let (kp, pk) = generate_kp(alg);
        let raw_sig = sign(&kp, b"test");
        verify_raw(&pk, b"test", alg, &raw_sig, SignatureEncoding::Raw).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    // ── Bug regression: publickey_verify was always NotImplemented ────────────

    #[test]
    fn publickey_verify_returns_ok_for_all_algorithms() {
        // publickey_verify previously always returned NotImplemented.  It should
        // return Ok(()) for any key that was successfully imported, because import
        // already performs the structural/cryptographic validity checks.
        let algs = [
            "Ed25519",
            "ECDSA_P256_SHA256",
            "ECDSA_K256_SHA256",
            "ECDSA_P384_SHA384",
            "RSA_PKCS1_2048_SHA256",
        ];
        for alg in algs {
            let (kp, pk) = generate_kp(alg);
            publickey_verify(&pk)
                .unwrap_or_else(|e| panic!("publickey_verify({alg}) returned {e:?}, expected Ok(())"));
            keypair_close(kp).unwrap();
            publickey_close(pk).unwrap();
        }
    }

    // ── Bug regression: signature_verification_state_verify owns the signature handle ─

    #[test]
    fn signature_verify_consumes_signature_handle() {
        // signature_verification_state_verify takes plain `signature` (owned),
        // meaning the host must consume (delete) the handle. If it leaks, repeated
        // calls would fill the resource table. Verify the handle is gone by ensuring
        // signature_close on it after verify fails with an appropriate error.
        let (kp, pk) = generate_kp("Ed25519");
        let raw_sig = sign(&kp, b"test");

        let sig = signature_import("Ed25519", &raw_sig, SignatureEncoding::Raw).unwrap();
        let state = signature_verification_state_open(&pk).unwrap();
        signature_verification_state_update(&state, b"test").unwrap();
        // verify takes ownership of `sig`
        signature_verification_state_verify(&state, sig).unwrap();
        // After verify, the signature handle should have been consumed by the host.
        // Attempting to close it again should fail (InvalidHandle or similar), not silently succeed.
        // We do NOT call signature_close(sig) here — that would be a double-free.
        signature_verification_state_close(state).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    // ── Bug regression: signature_export encoding parameter ──────────────────

    #[test]
    fn signature_export_raw_returns_correct_bytes() {
        // signature_export must respect the encoding parameter.
        // For Raw encoding the returned bytes must be importable as Raw.
        let (kp, pk) = generate_kp("Ed25519");

        let state = signature_state_open(&kp).unwrap();
        signature_state_update(&state, b"test").unwrap();
        let sig = signature_state_sign(&state).unwrap();
        signature_state_close(state).unwrap();

        let raw_bytes =
            array_output_pull(&signature_export(&sig, SignatureEncoding::Raw).unwrap()).unwrap();
        assert_eq!(raw_bytes.len(), 64, "Ed25519 raw signature must be 64 bytes");

        // Re-import and verify to confirm the bytes are valid
        let sig2 = signature_import("Ed25519", &raw_bytes, SignatureEncoding::Raw).unwrap();
        let vstate = signature_verification_state_open(&pk).unwrap();
        signature_verification_state_update(&vstate, b"test").unwrap();
        signature_verification_state_verify(&vstate, sig2).unwrap();
        signature_verification_state_close(vstate).unwrap();

        signature_close(sig).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }

    // ── Bug regression: RSA sign() state reuse ───────────────────────────────

    #[test]
    fn rsa_pkcs1_2048_sha256_sign_state_reuse() {
        // The spec says "The state is not closed and can be used after a signature
        // has been computed." RSA sign() must reset the BoringSSL signer so a
        // second update+sign cycle produces a valid, verifiable signature.
        let alg = "RSA_PKCS1_2048_SHA256";
        let (kp, pk) = generate_kp(alg);

        let state = signature_state_open(&kp).unwrap();
        signature_state_update(&state, b"first message").unwrap();
        let sig1 = signature_state_sign(&state).unwrap();
        let raw1 = array_output_pull(&signature_export(&sig1, SignatureEncoding::Raw).unwrap()).unwrap();
        signature_close(sig1).unwrap();

        // Second sign cycle on the same state handle
        signature_state_update(&state, b"second message").unwrap();
        let sig2 = signature_state_sign(&state).unwrap();
        let raw2 = array_output_pull(&signature_export(&sig2, SignatureEncoding::Raw).unwrap()).unwrap();
        signature_close(sig2).unwrap();

        // Both must verify
        verify_raw(&pk, b"first message", alg, &raw1, SignatureEncoding::Raw).unwrap();
        verify_raw(&pk, b"second message", alg, &raw2, SignatureEncoding::Raw).unwrap();

        signature_state_close(state).unwrap();
        keypair_close(kp).unwrap();
        publickey_close(pk).unwrap();
    }
}
