// The world imports only the interfaces under test, so these tests also run
// against a host that provides just those. `common` can't create an
// `array-output` by itself; only the family interfaces return one, so
// `symmetric` is imported as the producer (key export is deterministic).
wit_bindgen::generate!({
    path: "../../spec/wit",
    inline: "
        package wasi-crypto-tests:common;

        world common-tests {
            import wasi:crypto/common@0.12.0;
            import wasi:crypto/symmetric@0.12.0;
        }
    ",
    world: "common-tests",
    // The world is in its own test package, so the `wasi:crypto` interfaces
    // it imports need bindings generated explicitly.
    generate_all,
});

// This component covers the `common` interface: the `array-output` resource.
#[cfg(test)]
mod tests {
    use crate::wasi::crypto::common::ArrayOutput;
    use crate::wasi::crypto::symmetric::SymmetricKey;

    const RAW_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    /// Produces an `array-output` holding exactly `RAW_KEY`.
    fn exported_key() -> ArrayOutput {
        let key = SymmetricKey::import("HMAC/SHA-256", RAW_KEY)
            .unwrap_or_else(|e| panic!("SymmetricKey::import failed: {e:?}"));
        key.export()
            .unwrap_or_else(|e| panic!("SymmetricKey::export failed: {e:?}"))
    }

    #[test]
    fn array_output_len_returns_content_length() {
        let output = exported_key();
        assert_eq!(output.len().unwrap(), RAW_KEY.len() as u32);
        drop(output);
    }

    #[test]
    fn array_output_pull_returns_contents() {
        let output = exported_key();
        let bytes = ArrayOutput::pull(output).unwrap();
        assert_eq!(bytes, RAW_KEY);
    }
}
