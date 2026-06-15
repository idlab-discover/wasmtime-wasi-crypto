use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, Options, SecretsManager, Size, SymmetricKey, SymmetricState,
    SymmetricTag, U64, Version,
};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_symmetric::{Host, StoredKeyId};

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    #[doc = "/ Generate a new symmetric key for a given algorithm."]
    #[doc = "/ "]
    #[doc = "/ `options` can be `None` to use the default parameters, or an algorithm-specific set of parameters to override."]
    #[doc = "/ "]
    #[doc = "/ This function may return `unsupported_feature` if key generation is not supported by the host for the chosen algorithm, or `unsupported_algorithm` if the algorithm is not supported by the host."]
    fn symmetric_key_generate(
        &mut self,
        algorithm: wasmtime::component::__internal::String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> Result<wasmtime::component::Resource<SymmetricKey>, CryptoErrno> {
        let options = match options {
            Some(options_handle) => Some(
                self.table
                    .get(&options_handle)?
                    .clone() // TODO: investigate if this is necessary/valid
                    .into_symmetric()?,
            ),
            None => None,
        };

        let symmetric_key = SymmetricKey::generate(&algorithm, options)?;
        let handle = self.table.push(symmetric_key)?;
        Ok(handle)
    }

    #[doc = "/ Create a symmetric key from raw material."]
    #[doc = "/ "]
    #[doc = "/ The algorithm is internally stored along with the key, and trying to use the key with an operation expecting a different algorithm will return `invalid_key`."]
    #[doc = "/ "]
    #[doc = "/ The function may also return `unsupported_algorithm` if the algorithm is not supported by the host."]
    fn symmetric_key_import(
        &mut self,
        algorithm: wasmtime::component::__internal::String,
        raw: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<wasmtime::component::Resource<SymmetricKey>, CryptoErrno> {
        let symmetric_key = SymmetricKey::import(&algorithm, &raw)?;
        let handle = self.table.push(symmetric_key)?;
        Ok(handle)
    }

    #[doc = "/ Export a symmetric key as raw material."]
    #[doc = "/ "]
    #[doc = "/ This is mainly useful to export a managed key."]
    #[doc = "/ "]
    #[doc = "/ May return `prohibited_operation` if this operation is denied."]
    fn symmetric_key_export(
        &mut self,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        let symmetric_key = self.table.get(&symmetric_key)?;

        let raw = symmetric_key.inner().as_raw()?.to_vec();

        let array_output_handle = ArrayOutput::register(self.table, raw)?;
        Ok(array_output_handle)
    }

    #[doc = "/ Destroy a symmetric key."]
    #[doc = "/ "]
    #[doc = "/ Objects are reference counted. It is safe to close an object immediately after the last function needing it is called."]
    fn symmetric_key_close(
        &mut self,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(symmetric_key.owned());
        let _options: SymmetricKey = self.table.delete(symmetric_key)?;
        Ok(())
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Generate a new managed symmetric key."]
    #[doc = "/ "]
    #[doc = "/ The key is generated and stored by the secrets management facilities."]
    #[doc = "/ "]
    #[doc = "/ It may be used through its identifier, but the host may not allow it to be exported."]
    #[doc = "/ "]
    #[doc = "/ The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host,"]
    #[doc = "/ or `unsupported_algorithm` if a key cannot be created for the chosen algorithm."]
    #[doc = "/ "]
    #[doc = "/ The function may also return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ This is also an optional import, meaning that the function may not even exist."]
    fn symmetric_key_generate_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        algorithm: wasmtime::component::__internal::String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> Result<wasmtime::component::Resource<SymmetricKey>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Store a symmetric key into the secrets manager."]
    #[doc = "/ "]
    #[doc = "/ On success, the function returns the key identifier."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn symmetric_key_store_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> Result<StoredKeyId, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Replace a managed symmetric key."]
    #[doc = "/ "]
    #[doc = "/ This function creates a new version of a managed symmetric key, by replacing `$kp_old` with `$kp_new`."]
    #[doc = "/ "]
    #[doc = "/ It does several things:"]
    #[doc = "/ "]
    #[doc = "/ - The key identifier for `$symmetric_key_new` is set to the one of `$symmetric_key_old`."]
    #[doc = "/ - A new, unique version identifier is assigned to `$kp_new`. This version will be equivalent to using `$version_latest` until the key is replaced."]
    #[doc = "/ - The `$symmetric_key_old` handle is closed."]
    #[doc = "/ "]
    #[doc = "/ Both keys must share the same algorithm and have compatible parameters. If this is not the case, `incompatible_keys` is returned."]
    #[doc = "/ "]
    #[doc = "/ The function may also return the `unsupported_feature` error code if secrets management facilities are not supported by the host,"]
    #[doc = "/ or if keys cannot be rotated."]
    #[doc = "/ "]
    #[doc = "/ Finally, `prohibited_operation` can be returned if `$symmetric_key_new` wasn\'t created by the secrets manager, and the secrets manager prohibits imported keys."]
    #[doc = "/ "]
    #[doc = "/ If the operation succeeded, the new version is returned."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn symmetric_key_replace_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        symmetric_key_old: wasmtime::component::Resource<SymmetricKey>,
        symmetric_key_new: wasmtime::component::Resource<SymmetricKey>,
    ) -> Result<Version, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Return the key identifier and version of a managed symmetric key."]
    #[doc = "/ "]
    #[doc = "/ If the key is not managed, `unsupported_feature` is returned instead."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn symmetric_key_id(
        &mut self,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> Result<(StoredKeyId, Version), CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Return a managed symmetric key from a key identifier."]
    #[doc = "/ "]
    #[doc = "/ `kp_version` can be set to `version_latest` to retrieve the most recent version of a symmetric key."]
    #[doc = "/ "]
    #[doc = "/ If no key matching the provided information is found, `not_found` is returned instead."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn symmetric_key_from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        symmetric_key_id: StoredKeyId,
        symmetric_key_version: Version,
    ) -> Result<wasmtime::component::Resource<SymmetricKey>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ Create a new state to absorb and produce data using symmetric operations."]
    #[doc = "/ "]
    #[doc = "/ The state remains valid after every operation in order to support incremental updates."]
    #[doc = "/ "]
    #[doc = "/ The function has two optional parameters: a key and an options set."]
    #[doc = "/ "]
    #[doc = "/ It will fail with a `key_not_supported` error code if a key was provided but the chosen algorithm doesn\'t natively support keying."]
    #[doc = "/ "]
    #[doc = "/ On the other hand, if a key is required, but was not provided, a `key_required` error will be thrown."]
    #[doc = "/ "]
    #[doc = "/ Some algorithms may require additional parameters. They have to be supplied as an options set:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let options_handle = ctx.options_open()?;"]
    #[doc = "/ ctx.options_set(\"context\", b\"My application\")?;"]
    #[doc = "/ ctx.options_set_u64(\"fanout\", 16)?;"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"BLAKE2b-512\", None, Some(options_handle))?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ If some parameters are mandatory but were not set, the `parameters_missing` error code will be returned."]
    #[doc = "/ "]
    #[doc = "/ A notable exception is the `nonce` parameter, that is common to most AEAD constructions."]
    #[doc = "/ "]
    #[doc = "/ If a nonce is required but was not supplied:"]
    #[doc = "/ "]
    #[doc = "/ - If it is safe to do so, the host will automatically generate a nonce. This is true for nonces that are large enough to be randomly generated, or if the host is able to maintain a global counter."]
    #[doc = "/ - If not, the function will fail and return the dedicated `nonce_required` error code."]
    #[doc = "/ "]
    #[doc = "/ A nonce that was automatically generated can be retrieved after the function returns with `symmetric_state_get(state_handle, \"nonce\")`."]
    #[doc = "/ "]
    #[doc = "/ **Sample usage patterns:**"]
    #[doc = "/ "]
    #[doc = "/ - **Hashing**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut out = [0u8; 64];"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"SHAKE-128\", None, None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"data\")?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"more_data\")?;"]
    #[doc = "/ ctx.symmetric_state_squeeze(state_handle, &mut out)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **MAC**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut raw_tag = [0u8; 64];"]
    #[doc = "/ let key_handle = ctx.symmetric_key_import(\"HMAC/SHA-512\", b\"key\")?;"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"HMAC/SHA-512\", Some(key_handle), None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"data\")?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"more_data\")?;"]
    #[doc = "/ let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;"]
    #[doc = "/ ctx.symmetric_tag_pull(computed_tag_handle, &mut raw_tag)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ Verification:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"HMAC/SHA-512\", Some(key_handle), None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"data\")?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"more_data\")?;"]
    #[doc = "/ let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;"]
    #[doc = "/ ctx.symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **Tuple hashing**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut out = [0u8; 64];"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"TupleHashXOF256\", None, None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"value 1\")?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"value 2\")?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"value 3\")?;"]
    #[doc = "/ ctx.symmetric_state_squeeze(state_handle, &mut out)?;"]
    #[doc = "/ ```"]
    #[doc = "/ Unlike MACs and regular hash functions, inputs are domain separated instead of being concatenated."]
    #[doc = "/ "]
    #[doc = "/ - **Key derivation using extract-and-expand**"]
    #[doc = "/ "]
    #[doc = "/ Extract:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut prk = vec![0u8; 64];"]
    #[doc = "/ let key_handle = ctx.symmetric_key_import(\"HKDF-EXTRACT/SHA-512\", b\"key\")?;"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"HKDF-EXTRACT/SHA-512\", Some(key_handle), None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"salt\")?;"]
    #[doc = "/ let prk_handle = ctx.symmetric_state_squeeze_key(state_handle, \"HKDF-EXPAND/SHA-512\")?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ Expand:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut subkey = vec![0u8; 32];"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"HKDF-EXPAND/SHA-512\", Some(prk_handle), None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"info\")?;"]
    #[doc = "/ ctx.symmetric_state_squeeze(state_handle, &mut subkey)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **Key derivation using a XOF**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut subkey1 = vec![0u8; 32];"]
    #[doc = "/ let mut subkey2 = vec![0u8; 32];"]
    #[doc = "/ let key_handle = ctx.symmetric_key_import(\"BLAKE3\", b\"key\")?;"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"BLAKE3\", Some(key_handle), None)?;"]
    #[doc = "/ ctx.symmetric_absorb(state_handle, b\"context\")?;"]
    #[doc = "/ ctx.squeeze(state_handle, &mut subkey1)?;"]
    #[doc = "/ ctx.squeeze(state_handle, &mut subkey2)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **Password hashing**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut memory = vec![0u8; 1_000_000_000];"]
    #[doc = "/ let options_handle = ctx.symmetric_options_open()?;"]
    #[doc = "/ ctx.symmetric_options_set_guest_buffer(options_handle, \"memory\", &mut memory)?;"]
    #[doc = "/ ctx.symmetric_options_set_u64(options_handle, \"opslimit\", 5)?;"]
    #[doc = "/ ctx.symmetric_options_set_u64(options_handle, \"parallelism\", 8)?;"]
    #[doc = "/ "]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"ARGON2-ID-13\", None, Some(options))?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"password\")?;"]
    #[doc = "/ "]
    #[doc = "/ let pw_str_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;"]
    #[doc = "/ let mut pw_str = vec![0u8; ctx.symmetric_tag_len(pw_str_handle)?];"]
    #[doc = "/ ctx.symmetric_tag_pull(pw_str_handle, &mut pw_str)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **AEAD encryption with an explicit nonce**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let key_handle = ctx.symmetric_key_generate(\"AES-256-GCM\", None)?;"]
    #[doc = "/ let message = b\"test\";"]
    #[doc = "/ "]
    #[doc = "/ let options_handle = ctx.symmetric_options_open()?;"]
    #[doc = "/ ctx.symmetric_options_set(options_handle, \"nonce\", nonce)?;"]
    #[doc = "/ "]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"AES-256-GCM\", Some(key_handle), Some(options_handle))?;"]
    #[doc = "/ let mut ciphertext = vec![0u8; message.len() + ctx.symmetric_state_max_tag_len(state_handle)?];"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, \"additional data\")?;"]
    #[doc = "/ ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **AEAD encryption with automatic nonce generation**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let key_handle = ctx.symmetric_key_generate(\"AES-256-GCM-SIV\", None)?;"]
    #[doc = "/ let message = b\"test\";"]
    #[doc = "/ let mut nonce = [0u8; 24];"]
    #[doc = "/ "]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"AES-256-GCM-SIV\", Some(key_handle), None)?;"]
    #[doc = "/ "]
    #[doc = "/ let nonce = ctx.symmetric_state_options_get(state_handle, \"nonce\")?;"]
    #[doc = "/ "]
    #[doc = "/ let mut ciphertext = vec![0u8; message.len() + ctx.symmetric_state_max_tag_len(state_handle)?];"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, \"additional data\")?;"]
    #[doc = "/ ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, message)?;"]
    #[doc = "/ ```"]
    #[doc = "/ "]
    #[doc = "/ - **Session authenticated modes**"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let mut out = [0u8; 16];"]
    #[doc = "/ let mut out2 = [0u8; 16];"]
    #[doc = "/ let mut ciphertext = [0u8; 20];"]
    #[doc = "/ let key_handle = ctx.symmetric_key_generate(\"Xoodyak-128\", None)?;"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"Xoodyak-128\", Some(key_handle), None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"data\")?;"]
    #[doc = "/ ctx.symmetric_state_encrypt(state_handle, &mut ciphertext, b\"abcd\")?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"more data\")?;"]
    #[doc = "/ ctx.symmetric_state_squeeze(state_handle, &mut out)?;"]
    #[doc = "/ ctx.symmetric_state_squeeze(state_handle, &mut out2)?;"]
    #[doc = "/ ctx.symmetric_state_ratchet(state_handle)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"more data\")?;"]
    #[doc = "/ let next_key_handle = ctx.symmetric_state_squeeze_key(state_handle, \"Xoodyak-128\")?;"]
    #[doc = "/ // ..."]
    #[doc = "/ ```"]
    fn symmetric_state_open(
        &mut self,
        algorithm: wasmtime::component::__internal::String,
        key: Option<wasmtime::component::Resource<SymmetricKey>>,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> Result<wasmtime::component::Resource<SymmetricState>, CryptoErrno> {
        let key = match key {
            None => None,
            Some(symmetric_key_handle) => Some(self.table.get(&symmetric_key_handle)?),
        };
        let options = match options {
            None => None,
            Some(options_handle) => Some(
                self.table
                    .get(&options_handle)?
                    .clone() // TODO: investigate if this is necessary/valid
                    .into_symmetric()?,
            ),
        };
        let symmetric_state = SymmetricState::open(&algorithm, key, options.as_ref(), self.limits)?;
        let handle = self.table.push(symmetric_state)?;
        Ok(handle)
    }

    #[doc = "/ Retrieve a parameter from the current state."]
    #[doc = "/ "]
    #[doc = "/ In particular, `symmetric_state_options_get(\"nonce\")` can be used to get a nonce that as automatically generated."]
    #[doc = "/ "]
    #[doc = "/ The function may return `options_not_set` if an option was not set, which is different from an empty value."]
    #[doc = "/ "]
    #[doc = "/ It may also return `unsupported_option` if the option doesn\'t exist for the chosen algorithm."]
    fn symmetric_state_options_get(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        name: wasmtime::component::__internal::String,
    ) -> Result<Vec<u8>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        let v = symmetric_state.inner().options_get(&name)?;
        // if v_len > value.len() {
        //     return Err(CryptoErrno::Overflow);
        // }
        Ok(v)
    }

    #[doc = "/ Retrieve an integer parameter from the current state."]
    #[doc = "/ "]
    #[doc = "/ The function may return `options_not_set` if an option was not set."]
    #[doc = "/ "]
    #[doc = "/ It may also return `unsupported_option` if the option doesn\'t exist for the chosen algorithm."]
    fn symmetric_state_options_get_u64(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        name: wasmtime::component::__internal::String,
    ) -> Result<U64, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        let v = symmetric_state.inner().options_get_u64(&name)?;
        Ok(v)
    }

    #[doc = "/ Clone a symmetric state."]
    #[doc = "/ "]
    #[doc = "/ The function clones the internal state, assigns a new handle to it and returns the new handle."]
    fn symmetric_state_clone(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> Result<wasmtime::component::Resource<SymmetricState>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        let symmetric_state = symmetric_state.clone();
        let handle = self.table.push(symmetric_state)?;
        Ok(handle)
    }

    #[doc = "/ Destroy a symmetric state."]
    #[doc = "/ "]
    #[doc = "/ Objects are reference counted. It is safe to close an object immediately after the last function needing it is called."]
    fn symmetric_state_close(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(state.owned());
        let _state: SymmetricState = self.table.delete(state)?;
        Ok(())
    }

    #[doc = "/ Absorb data into the state."]
    #[doc = "/ "]
    #[doc = "/ - **Hash functions:** adds data to be hashed."]
    #[doc = "/ - **MAC functions:** adds data to be authenticated."]
    #[doc = "/ - **Tuplehash-like constructions:** adds a new tuple to the state."]
    #[doc = "/ - **Key derivation functions:** adds to the IKM or to the subkey information."]
    #[doc = "/ - **AEAD constructions:** adds additional data to be authenticated."]
    #[doc = "/ - **Stateful hash objects, permutation-based constructions:** absorbs."]
    #[doc = "/ "]
    #[doc = "/ If the chosen algorithm doesn\'t accept input data, the `invalid_operation` error code is returned."]
    #[doc = "/ "]
    #[doc = "/ If too much data has been fed for the algorithm, `overflow` may be thrown."]
    fn symmetric_state_absorb(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<(), CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.absorb(&data))
    }

    #[doc = "/ Squeeze bytes from the state."]
    #[doc = "/ "]
    #[doc = "/ - **Hash functions:** this tries to output an `out_len` bytes digest from the absorbed data. The hash function output will be truncated if necessary. If the requested size is too large, the `invalid_len` error code is returned."]
    #[doc = "/ - **Key derivation functions:** : outputs an arbitrary-long derived key."]
    #[doc = "/ - **RNGs, DRBGs, stream ciphers:**: outputs arbitrary-long data."]
    #[doc = "/ - **Stateful hash objects, permutation-based constructions:** squeeze."]
    #[doc = "/ "]
    #[doc = "/ Other kinds of algorithms may return `invalid_operation` instead."]
    #[doc = "/ "]
    #[doc = "/ For password-stretching functions, the function may return `in_progress`."]
    #[doc = "/ In that case, the guest should retry with the same parameters until the function completes."]
    fn symmetric_state_squeeze(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> Result<wasmtime::component::__internal::Vec<u8>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.squeeze_unchecked())
    }

    #[doc = "/ Compute and return a tag for all the data injected into the state so far."]
    #[doc = "/ "]
    #[doc = "/ - **MAC functions**: returns a tag authenticating the absorbed data."]
    #[doc = "/ - **Tuplehash-like constructions:** returns a tag authenticating all the absorbed tuples."]
    #[doc = "/ - **Password-hashing functions:** returns a standard string containing all the required parameters for password verification."]
    #[doc = "/ "]
    #[doc = "/ Other kinds of algorithms may return `invalid_operation` instead."]
    #[doc = "/ "]
    #[doc = "/ For password-stretching functions, the function may return `in_progress`."]
    #[doc = "/ In that case, the guest should retry with the same parameters until the function completes."]
    fn symmetric_state_squeeze_tag(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> Result<wasmtime::component::Resource<SymmetricTag>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        let tag = symmetric_state.locked(|mut state| state.squeeze_tag())?;
        let handle = self.table.push(tag)?;
        Ok(handle)
    }

    #[doc = "/ Use the current state to produce a key for a target algorithm."]
    #[doc = "/ "]
    #[doc = "/ For extract-then-expand constructions, this returns the PRK."]
    #[doc = "/ For session-based authentication encryption, this returns a key that can be used to resume a session without storing a nonce."]
    #[doc = "/ "]
    #[doc = "/ `invalid_operation` is returned for algorithms not supporting this operation."]
    fn symmetric_state_squeeze_key(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        alg_str: wasmtime::component::__internal::String,
    ) -> Result<wasmtime::component::Resource<SymmetricKey>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        let tag = symmetric_state.locked(|mut state| state.squeeze_key(&alg_str))?;
        let handle = self.table.push(tag)?;
        Ok(handle)
    }

    #[doc = "/ Return the maximum length of an authentication tag for the current algorithm."]
    #[doc = "/ "]
    #[doc = "/ This allows guests to compute the size required to store a ciphertext along with its authentication tag."]
    #[doc = "/ "]
    #[doc = "/ The returned length may include the encryption mode\'s padding requirements in addition to the actual tag."]
    #[doc = "/ "]
    #[doc = "/ For an encryption operation, the size of the output buffer should be `input_len + symmetric_state_max_tag_len()`."]
    #[doc = "/ "]
    #[doc = "/ For a decryption operation, the size of the buffer that will store the decrypted data must be `ciphertext_len - symmetric_state_max_tag_len()`."]
    fn symmetric_state_max_tag_len(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> Result<Size, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        let max_tag_len = symmetric_state.inner().max_tag_len()?;
        Ok(max_tag_len as u32)
    }

    #[doc = "/ Encrypt data with an attached tag."]
    #[doc = "/ "]
    #[doc = "/ - **Stream cipher:** adds the input to the stream cipher output. `out_len` and `data_len` can be equal, as no authentication tags will be added."]
    #[doc = "/ - **AEAD:** encrypts `data` into `out`, including the authentication tag to the output. Additional data must have been previously absorbed using `symmetric_state_absorb()`. The `symmetric_state_max_tag_len()` function can be used to retrieve the overhead of adding the tag, as well as padding if necessary."]
    #[doc = "/ - **SHOE, Xoodyak, Strobe:** encrypts data, squeezes a tag and appends it to the output."]
    #[doc = "/ "]
    #[doc = "/ The function returns the ciphertext along with the tag."]
    #[doc = "/ "]
    #[doc = "/ `invalid_operation` is returned for algorithms not supporting encryption."]
    fn symmetric_state_encrypt(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<wasmtime::component::__internal::Vec<u8>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.encrypt(&data))
    }

    #[doc = "/ Encrypt data, with a detached tag."]
    #[doc = "/ "]
    #[doc = "/ - **Stream cipher:** returns `invalid_operation` since stream ciphers do not include authentication tags."]
    #[doc = "/ - **AEAD:** encrypts `data` into `out` and returns the tag separately. Additional data must have been previously absorbed using `symmetric_state_absorb()`. The output and input buffers must be of the same length."]
    #[doc = "/ - **SHOE, Xoodyak, Strobe:** encrypts data and squeezes a tag."]
    #[doc = "/ "]
    #[doc = "/ The function returns the ciphertext and tag."]
    #[doc = "/ "]
    #[doc = "/ `invalid_operation` is returned for algorithms not supporting encryption."]
    fn symmetric_state_encrypt_detached(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<
        (
            wasmtime::component::__internal::Vec<u8>,
            wasmtime::component::Resource<SymmetricTag>,
        ),
        CryptoErrno,
    > {
        let symmetric_state = self.table.get(&state)?;
        let (out, symmetric_tag) = symmetric_state.inner().encrypt_detached(&data)?;
        let handle = self.table.push(symmetric_tag)?;
        Ok((out, handle))
    }

    #[doc = "/ - **Stream cipher:** adds the input to the stream cipher output. `out_len` and `data_len` can be equal, as no authentication tags will be added."]
    #[doc = "/ - **AEAD:** decrypts `data` into `out`. Additional data must have been previously absorbed using `symmetric_state_absorb()`."]
    #[doc = "/ - **SHOE, Xoodyak, Strobe:** decrypts data, squeezes a tag and verify that it matches the one that was appended to the ciphertext."]
    #[doc = "/ "]
    #[doc = "/ The function returns the decrypted message."]
    #[doc = "/ "]
    #[doc = "/ `invalid_tag` is returned if the tag didn\'t verify."]
    #[doc = "/ "]
    #[doc = "/ `invalid_operation` is returned for algorithms not supporting encryption."]
    fn symmetric_state_decrypt(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: wasmtime::component::__internal::Vec<u8>,
        out_len: u32,
    ) -> Result<wasmtime::component::__internal::Vec<u8>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.decrypt(&data, out_len as usize))
    }

    #[doc = "/ - **Stream cipher:** returns `invalid_operation` since stream ciphers do not include authentication tags."]
    #[doc = "/ - **AEAD:** decrypts `data` into `out`. Additional data must have been previously absorbed using `symmetric_state_absorb()`."]
    #[doc = "/ - **SHOE, Xoodyak, Strobe:** decrypts data, squeezes a tag and verify that it matches the expected one."]
    #[doc = "/ "]
    #[doc = "/ `raw_tag` is the expected tag, as raw bytes."]
    #[doc = "/ "]
    #[doc = "/ The function returns the decrypted message."]
    #[doc = "/ "]
    #[doc = "/ `invalid_tag` is returned if the tag verification failed."]
    #[doc = "/ "]
    #[doc = "/ `invalid_operation` is returned for algorithms not supporting encryption."]
    fn symmetric_state_decrypt_detached(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: wasmtime::component::__internal::Vec<u8>,
        raw_tag: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<wasmtime::component::__internal::Vec<u8>, CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.decrypt_detached(&data, &raw_tag))
    }

    #[doc = "/ Make it impossible to recover the previous state."]
    #[doc = "/ "]
    #[doc = "/ This operation is supported by some systems keeping a rolling state over an entire session, for forward security."]
    #[doc = "/ "]
    #[doc = "/ `invalid_operation` is returned for algorithms not supporting ratcheting."]
    fn symmetric_state_ratchet(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> Result<(), CryptoErrno> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.ratchet())
    }

    #[doc = "/ Return the length of an authentication tag."]
    #[doc = "/ "]
    #[doc = "/ This function can be used by a guest to allocate the correct buffer size to copy a computed authentication tag."]
    fn symmetric_tag_len(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
    ) -> Result<Size, CryptoErrno> {
        let symmetric_tag = self.table.get(&symmetric_tag)?;
        Ok(symmetric_tag.as_ref().len() as u32)
    }

    #[doc = "/ Copy an authentication tag into a guest-allocated buffer."]
    #[doc = "/ "]
    #[doc = "/ The handle automatically becomes invalid after this operation. Manually closing it is not required."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let raw_tag = ctx.symmetric_tag_pull(raw_tag_handle)?;"]
    #[doc = "/ ```"]
    fn symmetric_tag_pull(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
    ) -> Result<wasmtime::component::__internal::Vec<u8>, CryptoErrno> {
        let symmetric_tag: SymmetricTag = self.table.delete(symmetric_tag)?;
        let out = symmetric_tag.as_ref().to_vec();
        Ok(out)
    }

    #[doc = "/ Verify that a computed authentication tag matches the expected value, in constant-time."]
    #[doc = "/ "]
    #[doc = "/ The expected tag must be provided as a raw byte string."]
    #[doc = "/ "]
    #[doc = "/ The function returns `invalid_tag` if the tags don\'t match."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let key_handle = ctx.symmetric_key_import(\"HMAC/SHA-256\", b\"key\")?;"]
    #[doc = "/ let state_handle = ctx.symmetric_state_open(\"HMAC/SHA-256\", Some(key_handle), None)?;"]
    #[doc = "/ ctx.symmetric_state_absorb(state_handle, b\"data\")?;"]
    #[doc = "/ let computed_tag_handle = ctx.symmetric_state_squeeze_tag(state_handle)?;"]
    #[doc = "/ ctx.symmetric_tag_verify(computed_tag_handle, expected_raw_tag)?;"]
    #[doc = "/ ```"]
    fn symmetric_tag_verify(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
        expected_raw_tag: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<(), CryptoErrno> {
        let symmetric_tag = self.table.get(&symmetric_tag)?;
        symmetric_tag.verify(&expected_raw_tag)
    }

    #[doc = "/ Explicitly destroy an unused authentication tag."]
    #[doc = "/ "]
    #[doc = "/ This is usually not necessary, as `symmetric_tag_pull()` automatically closes a tag after it has been copied."]
    #[doc = "/ "]
    #[doc = "/ Objects are reference counted. It is safe to close an object immediately after the last function needing it is called."]
    fn symmetric_tag_close(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(symmetric_tag.owned());
        let _symmetric_tag: SymmetricTag = self.table.delete(symmetric_tag)?;
        Ok(())
    }
}
