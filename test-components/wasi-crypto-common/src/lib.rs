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
    use crate::wasi::crypto::wasi_ephemeral_crypto_common::*;

    #[test]
    fn options_open_drop_symmetric() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        drop(opts);
    }

    #[test]
    fn options_open_drop_signatures() {
        let opts = options_open(AlgorithmType::Signatures).unwrap();
        drop(opts);
    }

    #[test]
    fn options_open_drop_key_exchange() {
        let opts = options_open(AlgorithmType::KeyExchange).unwrap();
        drop(opts);
    }

    #[test]
    fn options_set_u64_threads() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        match options_set_u64(&opts, "threads", 1) {
            Ok(()) | Err(CryptoErrno::UnsupportedOption) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(opts);
    }

    #[test]
    fn options_set_context_bytes() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        match options_set(&opts, "context", b"test-context") {
            Ok(()) | Err(CryptoErrno::UnsupportedOption) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(opts);
    }

    #[test]
    fn options_set_rejects_garbage_name() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        match options_set_u64(&opts, "__not_a_real_option__", 0) {
            Err(CryptoErrno::UnsupportedOption) => {}
            Ok(()) => panic!("host accepted garbage option name"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(opts);
    }

    // ── secrets manager ───────────────────────────────────────────────────────
    //
    // The host doesn't implement a secrets manager (neither does the WITX
    // reference), so `secrets_manager_open` returns `UnsupportedFeature`.
    // `#[should_panic]` can't express that on wasm: libtest ignores such tests
    // without running them, and the runner reports the ignored test as passed.
    // So these tests run, accept exactly `UnsupportedFeature` from `open`, and
    // only exercise the rest of their scenario once a secrets manager exists.

    /// Opens a secrets manager, or returns `None` when the host reports
    /// `UnsupportedFeature`. Any other error fails the test.
    // TODO: assert that `open` succeeds once the host implements a secrets manager.
    fn open_secrets_manager() -> Option<SecretsManager> {
        match secrets_manager_open(None) {
            Ok(sm) => Some(sm),
            Err(CryptoErrno::UnsupportedFeature) => {
                eprintln!("secrets manager unsupported by the host; rest of the test skipped");
                None
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn secrets_manager_open_drop() {
        let Some(sm) = open_secrets_manager() else {
            return;
        };
        drop(sm);
    }

    #[test]
    fn secrets_manager_invalidate_not_found() {
        let Some(sm) = open_secrets_manager() else {
            return;
        };
        match secrets_manager_invalidate(&sm, &[], Version::Latest) {
            Err(CryptoErrno::NotFound) => {}
            Ok(()) => panic!("invalidating nonexistent key should return not-found"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(sm);
    }

    #[test]
    fn secrets_manager_invalidate_all_versions_not_found() {
        let Some(sm) = open_secrets_manager() else {
            return;
        };
        match secrets_manager_invalidate(&sm, &[], Version::All) {
            Err(CryptoErrno::NotFound) => {}
            Ok(()) => panic!("invalidating nonexistent key should return not-found"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(sm);
    }
}
