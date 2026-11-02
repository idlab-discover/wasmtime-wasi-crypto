use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::*,
    error::{CryptoError, CryptoResult},
    key_exchange::KxOptions,
    signatures::SignatureOptions,
    symmetric::SymmetricOptions,
};

impl HostSymmetricTag for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SymmetricTag>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSymmetricKey for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SymmetricKey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSymmetricState for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SymmetricState>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSignatureVerificationState for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(
        &mut self,
        rep: wasmtime::component::Resource<SignatureVerificationState>,
    ) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSecretkey for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Secretkey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostPublickey for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Publickey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSignature for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Signature>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSignatureState for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SignatureState>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostKeypair for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Keypair>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostSecretsManager for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<SecretsManager>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostOptions for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<Options>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
impl HostArrayOutput for crate::crypto::WasiCryptoCtxView<'_> {
    fn drop(&mut self, rep: wasmtime::component::Resource<ArrayOutput>) -> wasmtime::Result<()> {
        // The ArrayOutput's Drop impl will zeroize the underlying data for security.
        let _: crate::array_output::ArrayOutput = self.table.delete(rep)?;
        Ok(())
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn convert_crypto_errno(&mut self, err: CryptoError) -> wasmtime::Result<CryptoErrno> {
        err.downcast()
    }

    fn options_open(
        &mut self,
        algorithm_type: AlgorithmType,
    ) -> CryptoResult<wasmtime::component::Resource<Options>> {
        let options = match algorithm_type {
            AlgorithmType::Signatures => Options::Signatures(SignatureOptions::default()),
            AlgorithmType::Symmetric => Options::Symmetric(SymmetricOptions::default()),
            AlgorithmType::KeyExchange => Options::KeyExchange(KxOptions::default()),
        };

        let handle = self.table.push(options)?;

        Ok(handle)
    }

    fn options_set(
        &mut self,
        options: wasmtime::component::Resource<Options>,
        name: String,
        value: Vec<u8>,
    ) -> CryptoResult<()> {
        let options = self.table.get_mut(&options)?;
        options.set(&name, &value)?;
        Ok(())
    }

    fn options_set_u64(
        &mut self,
        options: wasmtime::component::Resource<Options>,
        name: String,
        value: u64,
    ) -> CryptoResult<()> {
        let options = self.table.get_mut(&options)?;
        options.set_u64(&name, value)?;
        Ok(())
    }

    fn options_set_guest_buffer(
        &mut self,
        options: wasmtime::component::Resource<Options>,
        name: String,
        buffer: Vec<u8>,
    ) -> CryptoResult<()> {
        self.options_set(options, name, buffer)
    }

    fn array_output_len(
        &mut self,
        array_output: wasmtime::component::Resource<ArrayOutput>,
    ) -> CryptoResult<Size> {
        let array_output = self.table.get(&array_output)?;
        Ok(array_output.len() as u32)
    }

    fn array_output_pull(
        &mut self,
        array_output: wasmtime::component::Resource<ArrayOutput>,
    ) -> CryptoResult<Vec<u8>> {
        let array_output_value: crate::array_output::ArrayOutput =
            self.table.delete(array_output)?;
        let len = array_output_value.len();
        let mut output = vec![0u8; len];
        array_output_value.pull(&mut output)?;
        Ok(output)
    }

    fn secrets_manager_open(
        &mut self,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<SecretsManager>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn secrets_manager_invalidate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        key_id: KeyId,
        key_version: Version,
    ) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}
