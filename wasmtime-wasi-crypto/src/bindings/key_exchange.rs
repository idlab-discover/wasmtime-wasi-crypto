use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_kx::Host;

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, Publickey, Secretkey,
};
use crate::error::CryptoResult;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn kx_dh(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
        sk: wasmtime::component::Resource<Secretkey>,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let pk = self.table.get(&pk)?.clone().into_kx_public_key()?;
        let sk = self.table.get(&sk)?.clone().into_kx_secret_key()?;
        let shared_secret = sk.dh(&pk)?;
        ArrayOutput::register(self.table, shared_secret)
    }

    fn kx_encapsulate(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
    ) -> CryptoResult<(
        wasmtime::component::Resource<ArrayOutput>,
        wasmtime::component::Resource<ArrayOutput>,
    )> {
        let pk = self.table.get(&pk)?.clone().into_kx_public_key()?;
        let encapsulated_secret = pk.encapsulate()?;
        let secret_handle = ArrayOutput::register(self.table, encapsulated_secret.secret)?;
        let encapsulated_secret_handle =
            ArrayOutput::register(self.table, encapsulated_secret.encapsulated_secret)?;
        Ok((secret_handle, encapsulated_secret_handle))
    }

    fn kx_decapsulate(
        &mut self,
        sk: wasmtime::component::Resource<Secretkey>,
        encapsulated_secret: Vec<u8>,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let sk = self.table.get(&sk)?.clone().into_kx_secret_key()?;
        let shared_secret = sk.decapsulate(&encapsulated_secret)?;
        ArrayOutput::register(self.table, shared_secret)
    }
}
