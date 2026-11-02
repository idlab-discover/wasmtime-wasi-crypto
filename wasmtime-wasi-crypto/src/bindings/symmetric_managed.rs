use crate::bindings::wasi::crypto::symmetric_managed::{
    CryptoErrno, Host, SecretsManager, SymmetricKey, SymmetricKeyId, SymmetricOptions, Version,
};
use crate::error::CryptoResult;
use wasmtime::component::Resource;

// No secrets manager is implemented (`secrets-manager.open` always fails), so
// every managed-key function returns `UnsupportedFeature`.
impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn generate_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _algorithm: String,
        _options: Option<Resource<SymmetricOptions>>,
    ) -> CryptoResult<Resource<SymmetricKey>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn store_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _symmetric_key: Resource<SymmetricKey>,
    ) -> CryptoResult<SymmetricKeyId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn replace_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _symmetric_key_old: Resource<SymmetricKey>,
        _symmetric_key_new: Resource<SymmetricKey>,
    ) -> CryptoResult<Version> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn id(
        &mut self,
        _symmetric_key: Resource<SymmetricKey>,
    ) -> CryptoResult<(SymmetricKeyId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn from_id(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _symmetric_key_id: SymmetricKeyId,
        _symmetric_key_version: Version,
    ) -> CryptoResult<Resource<SymmetricKey>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}
