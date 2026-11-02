use crate::bindings::wasi::crypto::common::{
    ArrayOutput, CryptoErrno, KeypairEncoding, PublickeyEncoding, SecretkeyEncoding,
};
use crate::bindings::wasi::crypto::kx::{
    Host, HostKxKeypair, HostKxOptions, HostKxPublickey, HostKxSecretkey, KxKeypair, KxOptions,
    KxPublickey, KxSecretkey,
};
use crate::error::CryptoResult;
use crate::key_exchange::KxAlgorithm;
use crate::options::OptionsLike;
use wasmtime::component::Resource;

impl HostKxOptions for crate::crypto::WasiCryptoCtxView<'_> {
    fn new(&mut self) -> wasmtime::Result<Resource<KxOptions>> {
        Ok(self.table.push(KxOptions::default())?)
    }

    fn set(
        &mut self,
        self_: Resource<KxOptions>,
        name: String,
        value: Vec<u8>,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set(&name, &value)
    }

    fn set_u64(
        &mut self,
        self_: Resource<KxOptions>,
        name: String,
        value: u64,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set_u64(&name, value)
    }

    fn set_guest_buffer(
        &mut self,
        self_: Resource<KxOptions>,
        name: String,
        buffer: Vec<u8>,
    ) -> CryptoResult<()> {
        // A `list<u8>` is a copy, not a buffer in guest memory, so this can
        // only behave like `set`.
        self.set(self_, name, buffer)
    }

    fn drop(&mut self, rep: Resource<KxOptions>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostKxKeypair for crate::crypto::WasiCryptoCtxView<'_> {
    fn generate(
        &mut self,
        algorithm: String,
        options: Option<Resource<KxOptions>>,
    ) -> CryptoResult<Resource<KxKeypair>> {
        let options = match options {
            None => None,
            Some(options_handle) => Some(self.table.get(&options_handle)?.clone()),
        };
        let kp = KxKeypair::generate(KxAlgorithm::try_from(algorithm.as_str())?, options)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    fn import(
        &mut self,
        _algorithm: String,
        _encoded: Vec<u8>,
        _encoding: KeypairEncoding,
    ) -> CryptoResult<Resource<KxKeypair>> {
        // TODO: key-exchange key pairs can't be imported yet (there is no
        // `KxKeyPair::import`). `InvalidOperation` is kept from before the
        // per-family split.
        Err(CryptoErrno::InvalidOperation.into())
    }

    fn from_pk_and_sk(
        &mut self,
        publickey: Resource<KxPublickey>,
        secretkey: Resource<KxSecretkey>,
    ) -> CryptoResult<Resource<KxKeypair>> {
        let pk = self.table.get(&publickey)?;
        let sk = self.table.get(&secretkey)?;
        let kp = KxKeypair::from_pk_and_sk(pk, sk)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    fn export(
        &mut self,
        self_: Resource<KxKeypair>,
        encoding: KeypairEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let kp = self.table.get(&self_)?;
        let encoded = kp.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    fn publickey(&mut self, self_: Resource<KxKeypair>) -> CryptoResult<Resource<KxPublickey>> {
        let kp = self.table.get(&self_)?;
        let pk = kp.public_key()?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    fn secretkey(&mut self, self_: Resource<KxKeypair>) -> CryptoResult<Resource<KxSecretkey>> {
        let kp = self.table.get(&self_)?;
        let sk = kp.secret_key()?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

    fn drop(&mut self, rep: Resource<KxKeypair>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostKxPublickey for crate::crypto::WasiCryptoCtxView<'_> {
    fn import(
        &mut self,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<Resource<KxPublickey>> {
        let alg = KxAlgorithm::try_from(algorithm.as_str())?;
        let pk = KxPublickey::import(alg, &encoded, encoding)?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    fn from_secretkey(
        &mut self,
        _sk: Resource<KxSecretkey>,
    ) -> CryptoResult<Resource<KxPublickey>> {
        // Also not defined in witx version
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn export(
        &mut self,
        self_: Resource<KxPublickey>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let pk = self.table.get(&self_)?;
        let encoded = pk.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    fn verify(&mut self, self_: Resource<KxPublickey>) -> CryptoResult<()> {
        self.table.get(&self_)?.verify()
    }

    fn encapsulate(
        &mut self,
        self_: Resource<KxPublickey>,
    ) -> CryptoResult<(Resource<ArrayOutput>, Resource<ArrayOutput>)> {
        let pk = self.table.get(&self_)?;
        let encapsulated_secret = pk.encapsulate()?;
        let secret_handle = ArrayOutput::register(self.table, encapsulated_secret.secret)?;
        let encapsulated_secret_handle =
            ArrayOutput::register(self.table, encapsulated_secret.encapsulated_secret)?;
        Ok((secret_handle, encapsulated_secret_handle))
    }

    fn drop(&mut self, rep: Resource<KxPublickey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostKxSecretkey for crate::crypto::WasiCryptoCtxView<'_> {
    fn import(
        &mut self,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<Resource<KxSecretkey>> {
        let alg = KxAlgorithm::try_from(algorithm.as_str())?;
        let sk = KxSecretkey::import(alg, &encoded, encoding)?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

    fn export(
        &mut self,
        self_: Resource<KxSecretkey>,
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let sk = self.table.get(&self_)?;
        let encoded = sk.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    fn dh(
        &mut self,
        self_: Resource<KxSecretkey>,
        pk: Resource<KxPublickey>,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let pk = self.table.get(&pk)?;
        let sk = self.table.get(&self_)?;
        let shared_secret = sk.dh(pk)?;
        ArrayOutput::register(self.table, shared_secret)
    }

    fn decapsulate(
        &mut self,
        self_: Resource<KxSecretkey>,
        encapsulated_secret: Vec<u8>,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let sk = self.table.get(&self_)?;
        let shared_secret = sk.decapsulate(&encapsulated_secret)?;
        ArrayOutput::register(self.table, shared_secret)
    }

    fn drop(&mut self, rep: Resource<KxSecretkey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {}
