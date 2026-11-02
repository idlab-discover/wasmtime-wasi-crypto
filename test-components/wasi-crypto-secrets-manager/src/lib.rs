// The world imports only the interface under test, so these tests also run
// against a host that provides just that interface (and `common`).
wit_bindgen::generate!({
    path: "../../spec/wit",
    inline: "
        package wasi-crypto-tests:secrets-manager;

        world secrets-manager-tests {
            import wasi:crypto/secrets-manager@0.12.0;
        }
    ",
    world: "secrets-manager-tests",
    // The world is in its own test package, so the `wasi:crypto` interfaces
    // it imports need bindings generated explicitly.
    generate_all,
});

// This component covers the `secrets-manager` interface.
#[cfg(test)]
mod tests {
    // wit-bindgen re-exports every `use`d type inside each interface module,
    // so each type is imported from the interface that declares it; glob
    // imports from several modules would be ambiguous.
    use crate::wasi::crypto::common::{CryptoErrno, Version};
    use crate::wasi::crypto::secrets_manager::SecretsManager;

    // The host doesn't implement a secrets manager (neither does the WITX
    // reference), so `SecretsManager::open` returns `UnsupportedFeature`.
    // `#[should_panic]` can't express that on wasm: libtest ignores such tests
    // without running them, and the runner reports the ignored test as passed.
    // So these tests run, accept exactly `UnsupportedFeature` from `open`, and
    // only exercise the rest of their scenario once a secrets manager exists.

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
        match sm.invalidate(&[], Version::Latest) {
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
        match sm.invalidate(&[], Version::All) {
            Err(CryptoErrno::NotFound) => {}
            Ok(()) => panic!("invalidating nonexistent key should return not-found"),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
        drop(sm);
    }
}
