use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::*, key_exchange::KxOptions,
    signatures::SignatureOptions, symmetric::SymmetricOptions,
};

impl HostSymmetricTag for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SymmetricTag>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSymmetricKey for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SymmetricKey>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSymmetricState for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SymmetricState>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSignatureVerificationState for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<SignatureVerificationState>,
    ) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSecretkey for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Secretkey>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostPublickey for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Publickey>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSignature for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Signature>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSignatureState for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SignatureState>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostKeypair for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Keypair>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostSecretsManager for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SecretsManager>) -> wasmtime::Result<()> {
        todo!()
    }
}
impl HostOptions for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Options>) -> wasmtime::Result<()> {
        Ok(self.options_close(rep)?)
    }
}
impl HostArrayOutput for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<ArrayOutput>) -> wasmtime::Result<()> {
        todo!()
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    #[doc = "/ Create a new object to set non-default options."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let options_handle = options_open(AlgorithmType::Symmetric)?;"]
    #[doc = "/ options_set(options_handle, \"context\", context)?;"]
    #[doc = "/ options_set_u64(options_handle, \"threads\", 4)?;"]
    #[doc = "/ let state = symmetric_state_open(\"BLAKE3\", None, Some(options_handle))?;"]
    #[doc = "/ options_close(options_handle)?;"]
    #[doc = "/ ```"]
    fn options_open(
        &mut self,
        algorithm_type: AlgorithmType,
    ) -> Result<wasmtime::component::Resource<Options>, CryptoErrno> {
        let options = match algorithm_type {
            AlgorithmType::Signatures => Options::Signatures(SignatureOptions::default()),
            AlgorithmType::Symmetric => Options::Symmetric(SymmetricOptions::default()),
            AlgorithmType::KeyExchange => Options::KeyExchange(KxOptions::default()),
        };

        let handle = self.table.push(options)?;

        Ok(handle)
    }

    #[doc = "/ Destroy an options object."]
    fn options_close(
        &mut self,
        options: wasmtime::component::Resource<Options>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(options.owned());
        let _options: Options = self.table.delete(options)?;
        Ok(())
    }

    #[doc = "/ Set or update an option."]
    #[doc = "/ "]
    #[doc = "/ This is used to set algorithm-specific parameters, but also to provide credentials for the secrets management facilities, if required."]
    #[doc = "/ "]
    #[doc = "/ This function may return `unsupported_option` if an option that doesn\'t exist for any implemented algorithms is specified."]
    fn options_set(
        &mut self,
        options: wasmtime::component::Resource<Options>,
        name: wasmtime::component::__internal::String,
        value: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<(), CryptoErrno> {
        let options = self.table.get_mut(&options)?;
        options.set(&name, &value)
    }

    #[doc = "/ Set or update an integer option."]
    #[doc = "/ "]
    #[doc = "/ This is used to set algorithm-specific parameters."]
    #[doc = "/ "]
    #[doc = "/ This function may return `unsupported_option` if an option that doesn\'t exist for any implemented algorithms is specified."]
    fn options_set_u64(
        &mut self,
        options: wasmtime::component::Resource<Options>,
        name: wasmtime::component::__internal::String,
        value: u64,
    ) -> Result<(), CryptoErrno> {
        let options = self.table.get_mut(&options)?;
        options.set_u64(&name, value)
    }

    #[doc = "/ Set or update buffer that the host can use or return data into."]
    #[doc = "/ "]
    #[doc = "/ This is for example used to set the scratch buffer required by memory-hard functions."]
    #[doc = "/ "]
    #[doc = "/ NOTE: In WITX, this was a raw pointer into guest linear memory, ensuring the allocation counted against the guest\'s memory budget."]
    #[doc = "/ This implementation using `list<u8>` does not have this guarantee and serves as a stopgap till [caller-supplied buffers](https://wasi.dev/roadmap) arrive in future WASI 0.3.x release."]
    #[doc = "/ "]
    #[doc = "/ This function may return `unsupported_option` if an option that doesn\'t exist for any implemented algorithms is specified."]
    fn options_set_guest_buffer(
        &mut self,
        options: wasmtime::component::Resource<Options>,
        name: wasmtime::component::__internal::String,
        buffer: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<(), CryptoErrno> {
        self.options_set(options, name, buffer)
    }

    #[doc = "/ Return the length of an `array_output` object."]
    #[doc = "/ "]
    #[doc = "/ This allows a guest to allocate a buffer of the correct size in order to copy the output of a function returning this object type."]
    fn array_output_len(
        &mut self,
        array_output: wasmtime::component::Resource<ArrayOutput>,
    ) -> Result<Size, CryptoErrno> {
        todo!()
    }

    #[doc = "/ Copy the content of an `array_output` object into an application-allocated buffer."]
    #[doc = "/ "]
    #[doc = "/ Multiple calls to that function can be made in order to consume the data in a streaming fashion, if necessary."]
    #[doc = "/ "]
    #[doc = "/ The function returns the copied bytes. A length of 0 means that the end of the stream has been reached."]
    #[doc = "/ "]
    #[doc = "/ The handle is automatically closed after all the data has been consumed."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let len = array_output_len(output_handle)?;"]
    #[doc = "/ let out =  array_output_pull(output_handle)?;"]
    #[doc = "/ ```"]
    fn array_output_pull(
        &mut self,
        array_output: wasmtime::component::Resource<ArrayOutput>,
    ) -> Result<wasmtime::component::__internal::Vec<u8>, CryptoErrno> {
        todo!()
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Create a context to use a secrets manager."]
    #[doc = "/ "]
    #[doc = "/ The set of required and supported options is defined by the host."]
    #[doc = "/ "]
    #[doc = "/ The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host."]
    #[doc = "/ This is also an optional import, meaning that the function may not even exist."]
    fn secrets_manager_open(
        &mut self,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> Result<wasmtime::component::Resource<SecretsManager>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Destroy a secrets manager context."]
    #[doc = "/ "]
    #[doc = "/ The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host."]
    #[doc = "/ This is also an optional import, meaning that the function may not even exist."]
    fn secrets_manager_close(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
    ) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Invalidate a managed key or key pair given an identifier and a version."]
    #[doc = "/ "]
    #[doc = "/ This asks the secrets manager to delete or revoke a stored key, a specific version of a key."]
    #[doc = "/ "]
    #[doc = "/ `key_version` can be set to a version number, to `version.latest` to invalidate the current version, or to `version.all` to invalidate all versions of a key."]
    #[doc = "/ "]
    #[doc = "/ The function returns `unsupported_feature` if this operation is not supported by the host, and `not_found` if the identifier and version don\'t match any existing key."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn secrets_manager_invalidate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        key_id: KeyId,
        key_version: Version,
    ) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }
}
