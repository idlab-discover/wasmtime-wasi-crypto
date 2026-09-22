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
        AlgorithmType, KeypairEncoding, PublickeyEncoding, SecretkeyEncoding, keypair_export,
        keypair_from_pk_and_sk, keypair_generate, keypair_import, keypair_publickey,
        keypair_secretkey, publickey_export, publickey_import, publickey_verify, secretkey_export,
        secretkey_import,
    };
    use crate::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, array_output_pull};

    // ── keypair_generate ──────────────────────────────────────────────────────

    #[test]
    fn keypair_generate_signatures_ed25519() {
        let kp = keypair_generate(AlgorithmType::Signatures, "Ed25519", None).unwrap();
        drop(kp);
    }

    #[test]
    fn keypair_generate_kx_x25519() {
        let kp = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        drop(kp);
    }

    #[test]
    fn keypair_generate_unknown_algorithm_returns_error() {
        match keypair_generate(AlgorithmType::Signatures, "__not_a_real_algo__", None) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(kp) => {
                drop(kp);
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── keypair_export / keypair_import ───────────────────────────────────────

    #[test]
    fn keypair_export_import_ed25519_raw() {
        let kp = keypair_generate(AlgorithmType::Signatures, "Ed25519", None).unwrap();
        let raw = array_output_pull(keypair_export(&kp, KeypairEncoding::Raw).unwrap()).unwrap();
        assert!(!raw.is_empty());
        let kp2 = keypair_import(
            AlgorithmType::Signatures,
            "Ed25519",
            &raw,
            KeypairEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(kp2);
    }

    #[test]
    fn keypair_import_invalid_key_returns_error() {
        match keypair_import(
            AlgorithmType::Signatures,
            "Ed25519",
            &[0u8; 3],
            KeypairEncoding::Raw,
        ) {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(kp) => {
                drop(kp);
                panic!("should have rejected a 3-byte keypair");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn keypair_import_kx_not_implemented_returns_error() {
        match keypair_import(
            AlgorithmType::KeyExchange,
            "X25519",
            &[0u8; 64],
            KeypairEncoding::Raw,
        ) {
            Err(CryptoErrno::InvalidOperation) | Err(CryptoErrno::NotImplemented) => {}
            Ok(kp) => {
                drop(kp);
                panic!("keypair_import for KX should not be implemented");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── keypair_publickey / keypair_secretkey ─────────────────────────────────

    #[test]
    fn keypair_publickey_returns_valid_key() {
        let kp = keypair_generate(AlgorithmType::Signatures, "Ed25519", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        drop(pk);
        drop(kp);
    }

    #[test]
    fn keypair_secretkey_returns_valid_key() {
        let kp = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        let sk = keypair_secretkey(&kp).unwrap();
        drop(sk);
        drop(kp);
    }

    // ── keypair_from_pk_and_sk ────────────────────────────────────────────────

    #[test]
    fn keypair_from_pk_and_sk_incompatible_algs_returns_error() {
        // Ed25519 pk + X25519 sk must return IncompatibleKeys (different alg domains).
        let kp_sig = keypair_generate(AlgorithmType::Signatures, "Ed25519", None).unwrap();
        let pk_sig = keypair_publickey(&kp_sig).unwrap();

        let kp_kx = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        let sk_kx = keypair_secretkey(&kp_kx).unwrap();

        match keypair_from_pk_and_sk(&pk_sig, &sk_kx) {
            Err(CryptoErrno::IncompatibleKeys) => {}
            Ok(kp) => {
                drop(kp);
                panic!("mismatched alg types should return IncompatibleKeys");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }

        drop(kp_sig);
        drop(kp_kx);
        drop(pk_sig);
        drop(sk_kx);
    }

    #[test]
    fn keypair_from_pk_and_sk_same_alg_not_implemented() {
        let kp = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        let sk = keypair_secretkey(&kp).unwrap();

        match keypair_from_pk_and_sk(&pk, &sk) {
            Err(CryptoErrno::NotImplemented) => {}
            Ok(kp2) => {
                drop(kp2);
                panic!("keypair_from_pk_and_sk should return NotImplemented");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }

        drop(kp);
        drop(pk);
        drop(sk);
    }

    // ── publickey_import / publickey_export / publickey_verify ────────────────

    #[test]
    fn publickey_export_import_ed25519_raw() {
        let kp = keypair_generate(AlgorithmType::Signatures, "Ed25519", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();

        let raw =
            array_output_pull(publickey_export(&pk, PublickeyEncoding::Raw).unwrap()).unwrap();
        assert_eq!(raw.len(), 32, "Ed25519 public key is 32 bytes");

        let pk2 = publickey_import(
            AlgorithmType::Signatures,
            "Ed25519",
            &raw,
            PublickeyEncoding::Raw,
        )
        .unwrap();

        drop(kp);
        drop(pk);
        drop(pk2);
    }

    #[test]
    fn publickey_export_import_x25519_raw() {
        let kp = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();

        let raw =
            array_output_pull(publickey_export(&pk, PublickeyEncoding::Raw).unwrap()).unwrap();
        assert_eq!(raw.len(), 32, "X25519 public key is 32 bytes");

        let pk2 = publickey_import(
            AlgorithmType::KeyExchange,
            "X25519",
            &raw,
            PublickeyEncoding::Raw,
        )
        .unwrap();
        publickey_verify(&pk2).unwrap();

        drop(kp);
        drop(pk);
        drop(pk2);
    }

    #[test]
    fn publickey_import_wrong_size_returns_invalid_key() {
        match publickey_import(
            AlgorithmType::Signatures,
            "Ed25519",
            &[0u8; 5],
            PublickeyEncoding::Raw,
        ) {
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
        match publickey_import(
            AlgorithmType::Signatures,
            "__not_a_real_algo__",
            &[0u8; 32],
            PublickeyEncoding::Raw,
        ) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(pk) => {
                drop(pk);
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── secretkey_import / secretkey_export ───────────────────────────────────

    #[test]
    fn secretkey_export_x25519_raw() {
        let kp = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        let sk = keypair_secretkey(&kp).unwrap();

        let raw =
            array_output_pull(secretkey_export(&sk, SecretkeyEncoding::Raw).unwrap()).unwrap();
        assert_eq!(raw.len(), 32, "X25519 secret key is 32 bytes");

        drop(kp);
        drop(sk);
    }

    #[test]
    fn secretkey_import_x25519_raw() {
        let kp = keypair_generate(AlgorithmType::KeyExchange, "X25519", None).unwrap();
        let sk = keypair_secretkey(&kp).unwrap();
        let raw =
            array_output_pull(secretkey_export(&sk, SecretkeyEncoding::Raw).unwrap()).unwrap();

        let sk2 = secretkey_import(
            AlgorithmType::KeyExchange,
            "X25519",
            &raw,
            SecretkeyEncoding::Raw,
        )
        .unwrap();

        drop(sk);
        drop(sk2);
        drop(kp);
    }

    #[test]
    fn secretkey_import_signatures_not_implemented() {
        match secretkey_import(
            AlgorithmType::Signatures,
            "Ed25519",
            &[0u8; 64],
            SecretkeyEncoding::Raw,
        ) {
            Err(CryptoErrno::NotImplemented) => {}
            Ok(sk) => {
                drop(sk);
                panic!("secretkey_import for Signatures should not be implemented");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── keypair_import: additional algorithm coverage ─────────────────────────

    #[test]
    fn keypair_import_ecdsa_p256_raw() {
        let kp = keypair_generate(AlgorithmType::Signatures, "ECDSA_P256_SHA256", None).unwrap();
        let raw = array_output_pull(keypair_export(&kp, KeypairEncoding::Raw).unwrap()).unwrap();
        let kp2 = keypair_import(
            AlgorithmType::Signatures,
            "ECDSA_P256_SHA256",
            &raw,
            KeypairEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(kp2);
    }

    #[test]
    fn keypair_import_ecdsa_p384_raw() {
        let kp = keypair_generate(AlgorithmType::Signatures, "ECDSA_P384_SHA384", None).unwrap();
        let raw = array_output_pull(keypair_export(&kp, KeypairEncoding::Raw).unwrap()).unwrap();
        let kp2 = keypair_import(
            AlgorithmType::Signatures,
            "ECDSA_P384_SHA384",
            &raw,
            KeypairEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(kp2);
    }

    // ── publickey_import: ECDSA compressed-point (Raw = compressed SEC1) ──────

    #[test]
    fn publickey_export_import_ecdsa_p256_raw() {
        let kp = keypair_generate(AlgorithmType::Signatures, "ECDSA_P256_SHA256", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        let raw =
            array_output_pull(publickey_export(&pk, PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = publickey_import(
            AlgorithmType::Signatures,
            "ECDSA_P256_SHA256",
            &raw,
            PublickeyEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(pk);
        drop(pk2);
    }

    #[test]
    fn publickey_export_import_ecdsa_p384_raw() {
        let kp = keypair_generate(AlgorithmType::Signatures, "ECDSA_P384_SHA384", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        let raw =
            array_output_pull(publickey_export(&pk, PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = publickey_import(
            AlgorithmType::Signatures,
            "ECDSA_P384_SHA384",
            &raw,
            PublickeyEncoding::Raw,
        )
        .unwrap();
        drop(kp);
        drop(pk);
        drop(pk2);
    }

    // ── Bug regression: publickey_verify for Signatures keys ─────────────────

    #[test]
    fn publickey_verify_ed25519_valid_key_returns_ok() {
        // SignaturePublicKey::verify was a NotImplemented stub; it must return Ok(())
        // for a freshly generated (structurally valid) Ed25519 public key.
        let kp = keypair_generate(AlgorithmType::Signatures, "Ed25519", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        publickey_verify(&pk).unwrap();
        drop(kp);
        drop(pk);
    }

    #[test]
    fn publickey_verify_ecdsa_p256_valid_key_returns_ok() {
        let kp = keypair_generate(AlgorithmType::Signatures, "ECDSA_P256_SHA256", None).unwrap();
        let pk = keypair_publickey(&kp).unwrap();
        publickey_verify(&pk).unwrap();
        drop(kp);
        drop(pk);
    }
}
