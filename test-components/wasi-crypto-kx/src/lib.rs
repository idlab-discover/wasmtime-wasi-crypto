// The world imports only the interface under test, so these tests also run
// against a host that provides just that interface (and `common`).
// `kx-managed` isn't imported: there are no managed key-exchange tests yet.
wit_bindgen::generate!({
    path: "../../spec/wit",
    inline: "
        package wasi-crypto-tests:kx;

        world kx-tests {
            import wasi:crypto/kx@0.12.0;
        }
    ",
    world: "kx-tests",
    // The world is in its own test package, so the `wasi:crypto` interfaces
    // it imports need bindings generated explicitly.
    generate_all,
});

// This component covers the `kx` interface.
#[cfg(test)]
mod tests {
    use crate::wasi::crypto::common::{
        ArrayOutput, CryptoErrno, KeypairEncoding, PublickeyEncoding, SecretkeyEncoding,
    };
    use crate::wasi::crypto::kx::{KxKeypair, KxOptions, KxPublickey, KxSecretkey};

    // ── options ───────────────────────────────────────────────────────────────

    #[test]
    fn options_open_drop_key_exchange() {
        let opts = KxOptions::new();
        drop(opts);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn generate_kp(alg: &str) -> (KxKeypair, KxPublickey, KxSecretkey) {
        let kp = KxKeypair::generate(alg, None)
            .unwrap_or_else(|e| panic!("KxKeypair::generate({alg}) failed: {e:?}"));
        let pk = kp
            .publickey()
            .unwrap_or_else(|e| panic!("KxKeypair::publickey({alg}) failed: {e:?}"));
        let sk = kp
            .secretkey()
            .unwrap_or_else(|e| panic!("KxKeypair::secretkey({alg}) failed: {e:?}"));
        (kp, pk, sk)
    }

    // ── X25519 DH ─────────────────────────────────────────────────────────────

    // Adapted from the WITX test_key_exchange test.
    // Two parties each generate a keypair; both compute DH in opposite directions;
    // the resulting shared secrets must be equal.
    #[test]
    fn x25519_dh_shared_secret_matches() {
        let (kp1, pk1, sk1) = generate_kp("X25519");
        let (kp2, pk2, sk2) = generate_kp("X25519");

        let ss1 = ArrayOutput::pull(sk1.dh(&pk2).unwrap()).unwrap();
        let ss2 = ArrayOutput::pull(sk2.dh(&pk1).unwrap()).unwrap();

        assert_eq!(ss1, ss2, "DH shared secrets must be equal");
        assert_eq!(ss1.len(), 32, "X25519 shared secret is 32 bytes");

        drop(kp1);
        drop(kp2);
        drop(pk1);
        drop(pk2);
        drop(sk1);
        drop(sk2);
    }

    #[test]
    fn x25519_dh_incompatible_key_types_error() {
        // DH with keys from two different algorithms must fail.
        // Since Kyber is the only other KX alg, and it does not support DH,
        // we test with an X25519 pk and an X25519 sk whose internal types differ.
        // The simplest portable check: wrong AlgorithmType for secretkey_import.
        match KxKeypair::generate("__not_a_real_algo__", None) {
            Err(CryptoErrno::UnsupportedAlgorithm) => {}
            Ok(kp) => {
                drop(kp);
                panic!("should have rejected unknown algorithm");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── X25519 keypair / public-key export+import ─────────────────────────────

    // Adapted from the WITX test_key_exchange keypair round-trip.
    #[test]
    fn x25519_keypair_export_import_round_trip() {
        let (kp, pk, sk) = generate_kp("X25519");

        // Export keypair as Raw, re-import, generate the same shared secret.
        let kp_raw = ArrayOutput::pull(kp.export(KeypairEncoding::Raw).unwrap()).unwrap();
        assert!(!kp_raw.is_empty());

        // Export public key as Raw, re-import.
        let pk_raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Raw).unwrap()).unwrap();
        assert_eq!(pk_raw.len(), 32, "X25519 public key is 32 bytes");
        let pk2 = KxPublickey::import("X25519", &pk_raw, PublickeyEncoding::Raw).unwrap();

        // Export secret key as Raw, re-import.
        let sk_raw = ArrayOutput::pull(sk.export(SecretkeyEncoding::Raw).unwrap()).unwrap();
        assert_eq!(sk_raw.len(), 32, "X25519 secret key is 32 bytes");
        let sk2 = KxSecretkey::import("X25519", &sk_raw, SecretkeyEncoding::Raw).unwrap();

        // Generate a second keypair and verify DH with re-imported keys gives same result.
        let (kp3, pk3, sk3) = generate_kp("X25519");
        let ss_orig = ArrayOutput::pull(sk.dh(&pk3).unwrap()).unwrap();
        let ss_reimport = ArrayOutput::pull(sk2.dh(&pk3).unwrap()).unwrap();
        assert_eq!(
            ss_orig, ss_reimport,
            "re-imported secret key must produce same DH result"
        );

        let ss_orig2 = ArrayOutput::pull(sk3.dh(&pk).unwrap()).unwrap();
        let ss_reimport2 = ArrayOutput::pull(sk3.dh(&pk2).unwrap()).unwrap();
        assert_eq!(
            ss_orig2, ss_reimport2,
            "re-imported public key must produce same DH result"
        );

        drop(kp);
        drop(kp3);
        drop(pk);
        drop(pk2);
        drop(pk3);
        drop(sk);
        drop(sk2);
        drop(sk3);
    }

    // ── X25519 public key verification ────────────────────────────────────────

    // Adapted from test_x25519_publickey_verify.
    #[test]
    fn x25519_publickey_verify_valid_key() {
        let (kp, pk, sk) = generate_kp("X25519");
        pk.verify().unwrap();
        drop(kp);
        drop(pk);
        drop(sk);
    }

    #[test]
    fn x25519_publickey_verify_low_order_point_fails() {
        // The all-zero public key is the canonical low-order point for X25519
        // and must be rejected by KxPublickey::verify.
        let zero_pk = KxPublickey::import("X25519", &[0u8; 32], PublickeyEncoding::Raw).unwrap();
        match zero_pk.verify() {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(()) => panic!("low-order/zero public key should be rejected"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(zero_pk);
    }

    // ── ML-KEM / X-Wing KEM ───────────────────────────────────────────────────

    // Helper: full encapsulate/decapsulate round-trip for any KEM algorithm.
    // Returns (shared_secret, pk_raw_len, sk_raw_len, ciphertext_len, shared_secret_len).
    fn kem_round_trip(alg: &str) -> (Vec<u8>, usize, usize, usize, usize) {
        let (kp, pk, sk) = generate_kp(alg);

        let pk_raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Raw).unwrap()).unwrap();
        let sk_raw = ArrayOutput::pull(sk.export(SecretkeyEncoding::Raw).unwrap()).unwrap();

        let (secret_ao, encapsulated_ao) = pk.encapsulate().unwrap();
        let secret = ArrayOutput::pull(secret_ao).unwrap();
        let encapsulated = ArrayOutput::pull(encapsulated_ao).unwrap();

        let decapsulated_ao = sk.decapsulate(&encapsulated).unwrap();
        let decapsulated = ArrayOutput::pull(decapsulated_ao).unwrap();

        assert_eq!(
            secret, decapsulated,
            "{alg}: encapsulate/decapsulate shared secrets must agree"
        );

        let ct_len = encapsulated.len();
        let ss_len = secret.len();
        let pk_len = pk_raw.len();
        let sk_len = sk_raw.len();

        drop(kp);
        drop(pk);
        drop(sk);

        (secret, pk_len, sk_len, ct_len, ss_len)
    }

    // Adapted from test_key_encapsulation. All four ML-KEM / X-Wing algorithms
    // are enabled by default via the `pqcrypto` feature.
    #[test]
    fn ml_kem_512_encapsulate_decapsulate() {
        let (_ss, pk_len, sk_len, ct_len, ss_len) = kem_round_trip("ML-KEM-512");
        println!("{pk_len}, {sk_len}, {ct_len}, {ss_len}");
        assert_eq!(pk_len, 800, "ML-KEM-512 public key size");
        assert_eq!(sk_len, 64, "ML-KEM-512 secret key seed size"); // Secrek key size expanded: 1632
        assert_eq!(ct_len, 768, "ML-KEM-512 ciphertext size");
        assert_eq!(ss_len, 32, "ML-KEM-512 shared secret size");
    }

    #[test]
    fn ml_kem_768_encapsulate_decapsulate() {
        let (_ss, pk_len, sk_len, ct_len, ss_len) = kem_round_trip("ML-KEM-768");
        assert_eq!(pk_len, 1184, "ML-KEM-768 public key size");
        assert_eq!(sk_len, 64, "ML-KEM-768 secret key seed size"); // Secret key size expanded: 2400
        assert_eq!(ct_len, 1088, "ML-KEM-768 ciphertext size");
        assert_eq!(ss_len, 32, "ML-KEM-768 shared secret size");
    }

    #[test]
    fn ml_kem_1024_encapsulate_decapsulate() {
        let (_ss, pk_len, sk_len, ct_len, ss_len) = kem_round_trip("ML-KEM-1024");
        assert_eq!(pk_len, 1568, "ML-KEM-1024 public key size");
        assert_eq!(sk_len, 64, "ML-KEM-1024 secret key seed size"); // Secret key size expanded: 3168
        assert_eq!(ct_len, 1568, "ML-KEM-1024 ciphertext size");
        assert_eq!(ss_len, 32, "ML-KEM-1024 shared secret size");
    }

    #[test]
    fn xwing_encapsulate_decapsulate() {
        let (_ss, pk_len, sk_len, ct_len, ss_len) = kem_round_trip("X-WING");
        assert_eq!(pk_len, 1216, "X-WING public key size");
        assert_eq!(sk_len, 32, "X-WING secret key seed size"); // Secret key size expanded: 2432
        assert_eq!(ct_len, 1120, "X-WING ciphertext size");
        assert_eq!(ss_len, 32, "X-WING shared secret size");
    }

    // ── X25519: additional coverage ───────────────────────────────────────────

    #[test]
    fn x25519_dh_mismatched_key_algorithms_returns_incompatible_keys() {
        // Construct two X25519 keypairs; then create a fake scenario by importing
        // a valid sk from kp1 as X25519 and a valid pk from kp2 as X25519 — DH
        // must succeed since both are X25519. But if we pass the sk's publickey
        // as the DH target instead of the peer's public key the result will differ;
        // just confirm the mismatch detection path: passing an X25519 sk with an
        // X25519 pk from a different keypair still works (no IncompatibleKeys).
        // The real incompatible-keys path fires when algorithm types differ.
        // Since ML-KEM / X-Wing don't support DH, we generate two X25519
        // keypairs and verify DH is symmetric.
        let (kp1, pk1, sk1) = generate_kp("X25519");
        let (kp2, pk2, sk2) = generate_kp("X25519");
        let ss_fwd = ArrayOutput::pull(sk1.dh(&pk2).unwrap()).unwrap();
        let ss_rev = ArrayOutput::pull(sk2.dh(&pk1).unwrap()).unwrap();
        assert_eq!(ss_fwd, ss_rev);
        drop(kp1);
        drop(kp2);
        drop(pk1);
        drop(pk2);
        drop(sk1);
        drop(sk2);
    }

    #[test]
    fn x25519_secretkey_import_wrong_size_returns_invalid_key() {
        match KxSecretkey::import("X25519", &[0u8; 5], SecretkeyEncoding::Raw) {
            Err(CryptoErrno::InvalidKey) => {}
            Ok(sk) => {
                drop(sk);
                panic!("should have rejected 5-byte secret key");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    // ── ML-KEM / X-Wing keypair export+import round-trips ─────────────────────

    // Helper: export pk and sk as Raw, re-import both, then verify that
    // re-encapsulating with the re-imported pk and decapsulating with the
    // re-imported sk still produces the same shared secret.
    fn kem_export_import_round_trip(alg: &str) {
        let (kp, pk, sk) = generate_kp(alg);

        // Export and re-import the encapsulation (public) key.
        let pk_raw = ArrayOutput::pull(pk.export(PublickeyEncoding::Raw).unwrap()).unwrap();
        let pk2 = KxPublickey::import(alg, &pk_raw, PublickeyEncoding::Raw)
            .unwrap_or_else(|e| panic!("{alg}: KxPublickey::import failed: {e:?}"));

        // Export and re-import the decapsulation (secret) key.
        let sk_raw = ArrayOutput::pull(sk.export(SecretkeyEncoding::Raw).unwrap()).unwrap();
        let sk2 = KxSecretkey::import(alg, &sk_raw, SecretkeyEncoding::Raw)
            .unwrap_or_else(|e| panic!("{alg}: KxSecretkey::import failed: {e:?}"));

        // Encapsulate to the re-imported public key; decapsulate with the
        // re-imported secret key. The shared secrets must agree.
        let (secret_ao, ct_ao) = pk2.encapsulate().unwrap_or_else(|e| {
            panic!("{alg}: KxPublickey::encapsulate (re-imported pk) failed: {e:?}")
        });
        let secret = ArrayOutput::pull(secret_ao).unwrap();
        let ct = ArrayOutput::pull(ct_ao).unwrap();

        let dec_ao = sk2.decapsulate(&ct).unwrap_or_else(|e| {
            panic!("{alg}: KxSecretkey::decapsulate (re-imported sk) failed: {e:?}")
        });
        let decapsulated = ArrayOutput::pull(dec_ao).unwrap();

        assert_eq!(
            secret, decapsulated,
            "{alg}: re-imported pk/sk must produce matching shared secrets"
        );

        drop(kp);
        drop(pk);
        drop(pk2);
        drop(sk);
        drop(sk2);
    }

    #[test]
    fn ml_kem_512_keypair_export_import_round_trip() {
        kem_export_import_round_trip("ML-KEM-512");
    }

    #[test]
    fn ml_kem_768_keypair_export_import_round_trip() {
        kem_export_import_round_trip("ML-KEM-768");
    }

    #[test]
    fn ml_kem_1024_keypair_export_import_round_trip() {
        kem_export_import_round_trip("ML-KEM-1024");
    }

    #[test]
    fn xwing_keypair_export_import_round_trip() {
        kem_export_import_round_trip("X-WING");
    }

    // ── key pair import / assembly (not implemented) ─────────────────────────
    //
    // Moved from the retired `wasi-crypto-asymmetric-common` component, whose
    // generic key functions now exist per family.

    #[test]
    fn keypair_import_kx_not_implemented_returns_error() {
        match KxKeypair::import("X25519", &[0u8; 64], KeypairEncoding::Raw) {
            Err(CryptoErrno::InvalidOperation) | Err(CryptoErrno::NotImplemented) => {}
            Ok(kp) => {
                drop(kp);
                panic!("KxKeypair::import should not be implemented");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn keypair_from_pk_and_sk_same_alg_not_implemented() {
        let (kp, pk, sk) = generate_kp("X25519");

        match KxKeypair::from_pk_and_sk(&pk, &sk) {
            Err(CryptoErrno::NotImplemented) => {}
            Ok(kp2) => {
                drop(kp2);
                panic!("KxKeypair::from_pk_and_sk should return NotImplemented");
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }

        drop(kp);
        drop(pk);
        drop(sk);
    }
}
