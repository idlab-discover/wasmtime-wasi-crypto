use crate::bindings::wasi::crypto::common::{
    ArrayOutput, CryptoErrno, KeypairEncoding, PublickeyEncoding, SecretkeyEncoding,
};
use crate::bindings::wasi::crypto::signatures::{
    Host, HostSignature, HostSignatureKeypair, HostSignatureOptions, HostSignaturePublickey,
    HostSignatureSecretkey, HostSignatureState, HostSignatureVerificationState, Signature,
    SignatureEncoding, SignatureKeypair, SignatureOptions, SignaturePublickey, SignatureSecretkey,
    SignatureState, SignatureVerificationState,
};
use crate::error::CryptoResult;
use crate::options::OptionsLike;
use crate::signatures::SignatureAlgorithm;
use wasmtime::component::Resource;

impl HostSignatureOptions for crate::crypto::WasiCryptoCtxView<'_> {
    fn new(&mut self) -> wasmtime::Result<Resource<SignatureOptions>> {
        Ok(self.table.push(SignatureOptions::default())?)
    }

    fn set(
        &mut self,
        self_: Resource<SignatureOptions>,
        name: String,
        value: Vec<u8>,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set(&name, &value)
    }

    fn set_u64(
        &mut self,
        self_: Resource<SignatureOptions>,
        name: String,
        value: u64,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set_u64(&name, value)
    }

    fn set_guest_buffer(
        &mut self,
        self_: Resource<SignatureOptions>,
        name: String,
        buffer: Vec<u8>,
    ) -> CryptoResult<()> {
        // A `list<u8>` is a copy, not a buffer in guest memory, so this can
        // only behave like `set`.
        self.set(self_, name, buffer)
    }

    fn drop(&mut self, rep: Resource<SignatureOptions>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSignatureKeypair for crate::crypto::WasiCryptoCtxView<'_> {
    fn generate(
        &mut self,
        algorithm: String,
        options: Option<Resource<SignatureOptions>>,
    ) -> CryptoResult<Resource<SignatureKeypair>> {
        let options = match options {
            None => None,
            Some(options_handle) => Some(self.table.get(&options_handle)?.clone()),
        };
        let kp =
            SignatureKeypair::generate(SignatureAlgorithm::try_from(algorithm.as_str())?, options)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    fn import(
        &mut self,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: KeypairEncoding,
    ) -> CryptoResult<Resource<SignatureKeypair>> {
        let kp = SignatureKeypair::import(
            SignatureAlgorithm::try_from(algorithm.as_str())?,
            &encoded,
            encoding,
        )?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    fn from_pk_and_sk(
        &mut self,
        publickey: Resource<SignaturePublickey>,
        secretkey: Resource<SignatureSecretkey>,
    ) -> CryptoResult<Resource<SignatureKeypair>> {
        let pk = self.table.get(&publickey)?;
        let sk = self.table.get(&secretkey)?;
        let kp = SignatureKeypair::from_pk_and_sk(pk, sk)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    fn export(
        &mut self,
        self_: Resource<SignatureKeypair>,
        encoding: KeypairEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let kp = self.table.get(&self_)?;
        let encoded = kp.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    fn publickey(
        &mut self,
        self_: Resource<SignatureKeypair>,
    ) -> CryptoResult<Resource<SignaturePublickey>> {
        let kp = self.table.get(&self_)?;
        let pk = kp.public_key()?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    fn secretkey(
        &mut self,
        self_: Resource<SignatureKeypair>,
    ) -> CryptoResult<Resource<SignatureSecretkey>> {
        let kp = self.table.get(&self_)?;
        let sk = kp.secret_key()?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

    fn drop(&mut self, rep: Resource<SignatureKeypair>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSignaturePublickey for crate::crypto::WasiCryptoCtxView<'_> {
    fn import(
        &mut self,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<Resource<SignaturePublickey>> {
        let pk = SignaturePublickey::import(
            SignatureAlgorithm::try_from(algorithm.as_str())?,
            &encoded,
            encoding,
        )?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    fn from_secretkey(
        &mut self,
        _sk: Resource<SignatureSecretkey>,
    ) -> CryptoResult<Resource<SignaturePublickey>> {
        // Also not defined in witx version
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn export(
        &mut self,
        self_: Resource<SignaturePublickey>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let pk = self.table.get(&self_)?;
        let encoded = pk.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    fn verify(&mut self, self_: Resource<SignaturePublickey>) -> CryptoResult<()> {
        let pk = self.table.get(&self_)?;
        SignaturePublickey::verify(pk)
    }

    fn drop(&mut self, rep: Resource<SignaturePublickey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSignatureSecretkey for crate::crypto::WasiCryptoCtxView<'_> {
    fn import(
        &mut self,
        _algorithm: String,
        _encoded: Vec<u8>,
        _encoding: SecretkeyEncoding,
    ) -> CryptoResult<Resource<SignatureSecretkey>> {
        // TODO: no signature secret key can be imported yet. The algorithm
        // string is deliberately not parsed first, so an unknown algorithm
        // also yields `NotImplemented`, as before the per-family split.
        Err(CryptoErrno::NotImplemented.into())
    }

    fn export(
        &mut self,
        self_: Resource<SignatureSecretkey>,
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let sk = self.table.get(&self_)?;
        let encoded = sk.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    fn drop(&mut self, rep: Resource<SignatureSecretkey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSignature for crate::crypto::WasiCryptoCtxView<'_> {
    fn import(
        &mut self,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: SignatureEncoding,
    ) -> CryptoResult<Resource<Signature>> {
        let alg = SignatureAlgorithm::try_from(algorithm.as_str())?;
        let signature = match encoding {
            SignatureEncoding::Raw => Signature::from_raw(alg, &encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding.into()),
        };
        let handle = self.table.push(signature)?;
        Ok(handle)
    }

    // TODO: `encoding` is ignored and the raw signature is always returned.
    fn export(
        &mut self,
        self_: Resource<Signature>,
        _encoding: SignatureEncoding,
    ) -> CryptoResult<Resource<ArrayOutput>> {
        let signature = self.table.get(&self_)?;
        let data = signature.inner().as_ref().as_ref().to_vec();
        let array_output_handle = ArrayOutput::register(self.table, data)?;
        Ok(array_output_handle)
    }

    fn drop(&mut self, rep: Resource<Signature>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSignatureState for crate::crypto::WasiCryptoCtxView<'_> {
    fn open(&mut self, kp: Resource<SignatureKeypair>) -> CryptoResult<Resource<SignatureState>> {
        SignatureState::open(self.table, kp)
    }

    fn update(&mut self, self_: Resource<SignatureState>, input: Vec<u8>) -> CryptoResult<()> {
        let state = self.table.get(&self_)?;
        state.locked(|mut state| state.update(&input))?;
        Ok(())
    }

    fn sign(&mut self, self_: Resource<SignatureState>) -> CryptoResult<Resource<Signature>> {
        let state = self.table.get(&self_)?;
        let signature = state.locked(|mut state| state.sign())?;
        let handle = self.table.push(signature)?;
        Ok(handle)
    }

    fn drop(&mut self, rep: Resource<SignatureState>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSignatureVerificationState for crate::crypto::WasiCryptoCtxView<'_> {
    fn open(
        &mut self,
        pk: Resource<SignaturePublickey>,
    ) -> CryptoResult<Resource<SignatureVerificationState>> {
        SignatureVerificationState::open(self.table, pk)
    }

    fn update(
        &mut self,
        self_: Resource<SignatureVerificationState>,
        input: Vec<u8>,
    ) -> CryptoResult<()> {
        let state = self.table.get(&self_)?;
        state.locked(|mut state| state.update(&input))?;
        Ok(())
    }

    fn verify(
        &mut self,
        self_: Resource<SignatureVerificationState>,
        signature: Resource<Signature>,
    ) -> CryptoResult<()> {
        let state = self.table.get(&self_)?;
        let signature = self.table.get(&signature)?;
        state.locked(|state| state.verify(signature))?;
        Ok(())
    }

    fn drop(&mut self, rep: Resource<SignatureVerificationState>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {}
