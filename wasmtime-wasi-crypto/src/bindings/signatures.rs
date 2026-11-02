use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, Signature, SignatureEncoding, SignatureState,
    SignatureVerificationState,
};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_signatures::{
    Host, SignatureKeypair, SignaturePublickey,
};
use crate::error::CryptoResult;
use crate::signatures::SignatureAlgorithm;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn signature_export(
        &mut self,
        signature: wasmtime::component::Resource<Signature>,
        encoding: SignatureEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let signature = self.table.get(&signature)?;
        let data = signature.inner().as_ref().as_ref().to_vec();
        let array_output_handle = ArrayOutput::register(self.table, data)?;
        Ok(array_output_handle)
    }

    fn signature_import(
        &mut self,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: SignatureEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Signature>> {
        let alg = SignatureAlgorithm::try_from(algorithm.as_str())?;
        let signature = match encoding {
            SignatureEncoding::Raw => Signature::from_raw(alg, &encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding.into()),
        };
        let handle = self.table.push(signature)?;
        Ok(handle)
    }

    fn signature_state_open(
        &mut self,
        kp: wasmtime::component::Resource<SignatureKeypair>,
    ) -> CryptoResult<wasmtime::component::Resource<SignatureState>> {
        SignatureState::open(self.table, kp)
    }

    fn signature_state_update(
        &mut self,
        state: wasmtime::component::Resource<SignatureState>,
        input: Vec<u8>,
    ) -> CryptoResult<()> {
        let state = self.table.get(&state)?;
        state.locked(|mut state| state.update(&input))?;
        Ok(())
    }

    fn signature_state_sign(
        &mut self,
        state: wasmtime::component::Resource<SignatureState>,
    ) -> CryptoResult<wasmtime::component::Resource<Signature>> {
        let state = self.table.get(&state)?;
        let signature = state.locked(|mut state| state.sign())?;
        let handle = self.table.push(signature)?;
        Ok(handle)
    }

    fn signature_verification_state_open(
        &mut self,
        kp: wasmtime::component::Resource<SignaturePublickey>,
    ) -> CryptoResult<wasmtime::component::Resource<SignatureVerificationState>> {
        SignatureVerificationState::open(self.table, kp)
    }

    fn signature_verification_state_update(
        &mut self,
        state: wasmtime::component::Resource<SignatureVerificationState>,
        input: Vec<u8>,
    ) -> CryptoResult<()> {
        let state = self.table.get(&state)?;
        state.locked(|mut state| state.update(&input))?;
        Ok(())
    }

    fn signature_verification_state_verify(
        &mut self,
        state: wasmtime::component::Resource<SignatureVerificationState>,
        signature: wasmtime::component::Resource<Signature>,
    ) -> CryptoResult<()> {
        let state = self.table.get(&state)?;
        let signature = self.table.get(&signature)?;
        state.locked(|state| state.verify(signature))?;
        Ok(())
    }
}
