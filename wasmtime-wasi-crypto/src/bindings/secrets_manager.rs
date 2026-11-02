use crate::{
    bindings::wasi::crypto::secrets_manager::{
        CryptoErrno, Host, HostSecretsManager, HostSecretsManagerOptions, KeyId, SecretsManager,
        SecretsManagerOptions, Version,
    },
    error::CryptoResult,
    options::OptionsLike,
};
use wasmtime::component::Resource;

impl HostSecretsManagerOptions for crate::crypto::WasiCryptoCtxView<'_> {
    fn new(&mut self) -> wasmtime::Result<Resource<SecretsManagerOptions>> {
        Ok(self.table.push(SecretsManagerOptions::default())?)
    }

    fn set(
        &mut self,
        self_: Resource<SecretsManagerOptions>,
        name: String,
        value: Vec<u8>,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set(&name, &value)
    }

    fn set_u64(
        &mut self,
        self_: Resource<SecretsManagerOptions>,
        name: String,
        value: u64,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set_u64(&name, value)
    }

    fn set_guest_buffer(
        &mut self,
        self_: Resource<SecretsManagerOptions>,
        name: String,
        buffer: Vec<u8>,
    ) -> CryptoResult<()> {
        // Same as `set`, as for the other option types: a `list<u8>` can't
        // give the host a buffer in guest memory.
        self.set(self_, name, buffer)
    }

    fn drop(&mut self, rep: Resource<SecretsManagerOptions>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSecretsManager for crate::crypto::WasiCryptoCtxView<'_> {
    // TODO: implement a secrets manager. Until then `open` always fails, so no
    // `secrets-manager` handle can exist and the type stays unmapped in
    // `bindgen!`. Once one exists, give `SecretsManagerOptions` real options.
    fn open(
        &mut self,
        _options: Option<Resource<SecretsManagerOptions>>,
    ) -> CryptoResult<Resource<SecretsManager>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn invalidate(
        &mut self,
        _self_: Resource<SecretsManager>,
        _key_id: KeyId,
        _key_version: Version,
    ) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn drop(&mut self, rep: Resource<SecretsManager>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {}
