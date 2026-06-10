wit_bindgen::generate!({
    world: "bindings",
    path: "../wit",
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
    fn options_open_close_symmetric() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        options_close(opts).unwrap();
    }

    #[test]
    fn options_open_close_signatures() {
        let opts = options_open(AlgorithmType::Signatures).unwrap();
        options_close(opts).unwrap();
    }

    #[test]
    fn options_open_close_key_exchange() {
        let opts = options_open(AlgorithmType::KeyExchange).unwrap();
        options_close(opts).unwrap();
    }

    #[test]
    fn options_set_u64_threads() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        match options_set_u64(&opts, "threads", 1) {
            Ok(()) | Err(CryptoErrno::UnsupportedOption) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        options_close(opts).unwrap();
    }

    #[test]
    fn options_set_context_bytes() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        match options_set(&opts, "context", b"test-context") {
            Ok(()) | Err(CryptoErrno::UnsupportedOption) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        options_close(opts).unwrap();
    }

    #[test]
    fn options_set_rejects_garbage_name() {
        let opts = options_open(AlgorithmType::Symmetric).unwrap();
        match options_set_u64(&opts, "__not_a_real_option__", 0) {
            Err(CryptoErrno::UnsupportedOption) => {}
            Ok(()) => panic!("host accepted garbage option name"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        options_close(opts).unwrap();
    }

    #[test]
    #[should_panic] // TODO: this is the same as the WITX version, but should probably be implemented down the line
    fn secrets_manager_open_close() {
        let sm = secrets_manager_open(None).unwrap();
        secrets_manager_close(sm).unwrap();
    }

    #[test]
    #[should_panic] // TODO: this is the same as the WITX version, but should probably be implemented down the line
    fn secrets_manager_invalidate_not_found() {
        let sm = secrets_manager_open(None).unwrap();
        match secrets_manager_invalidate(&sm, &[], Version::Latest) {
            Err(CryptoErrno::NotFound) => {}
            Ok(()) => panic!("invalidating nonexistent key should return not-found"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        secrets_manager_close(sm).unwrap();
    }

    #[test]
    #[should_panic] // TODO: this is the same as the WITX version, but should probably be implemented down the line
    fn secrets_manager_invalidate_all_versions_not_found() {
        let sm = secrets_manager_open(None).unwrap();
        match secrets_manager_invalidate(&sm, &[], Version::All) {
            Err(CryptoErrno::NotFound) => {}
            Ok(()) => panic!("invalidating nonexistent key should return not-found"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        secrets_manager_close(sm).unwrap();
    }
}
