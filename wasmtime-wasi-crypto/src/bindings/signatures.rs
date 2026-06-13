use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, Signature, SignatureEncoding, SignatureState,
    SignatureVerificationState,
};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_signatures::{
    Host, SignatureKeypair, SignaturePublickey,
};
use crate::signatures::SignatureAlgorithm;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    #[doc = "/ Export a signature."]
    #[doc = "/ "]
    #[doc = "/ This function exports a signature object using the specified encoding."]
    #[doc = "/ "]
    #[doc = "/ May return `unsupported_encoding` if the signature cannot be encoded into the given format."]
    fn signature_export(
        &mut self,
        signature: wasmtime::component::Resource<Signature>,
        encoding: SignatureEncoding,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        let signature = self.table.get(&signature)?;
        let data = signature.inner().as_ref().as_ref().to_vec();
        let array_output_handle = ArrayOutput::register(self.table, data)?;
        Ok(array_output_handle)
    }

    #[doc = "/ Create a signature object."]
    #[doc = "/ "]
    #[doc = "/ This object can be used along with a public key to verify an existing signature."]
    #[doc = "/ "]
    #[doc = "/ It may return `invalid_signature` if the signature is invalid or incompatible with the specified algorithm, as well as `unsupported_encoding` if the encoding is not compatible with the signature type."]
    #[doc = "/ "]
    #[doc = "/ The function may also return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let signature_handle = ctx.signature_import(\"ECDSA_P256_SHA256\", SignatureEncoding::DER, encoded)?;"]
    #[doc = "/ ```"]
    fn signature_import(
        &mut self,
        algorithm: wasmtime::component::__internal::String,
        encoded: wasmtime::component::__internal::Vec<u8>,
        encoding: SignatureEncoding,
    ) -> Result<wasmtime::component::Resource<Signature>, CryptoErrno> {
        let alg = SignatureAlgorithm::try_from(algorithm.as_str())?;
        let signature = match encoding {
            SignatureEncoding::Raw => Signature::from_raw(alg, &encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        };
        let handle = self.table.push(signature)?;
        Ok(handle)
    }

    #[doc = "/ Create a new state to collect data to compute a signature on."]
    #[doc = "/ "]
    #[doc = "/ This function allows data to be signed to be supplied in a streaming fashion."]
    #[doc = "/ "]
    #[doc = "/ The state is not closed and can be used after a signature has been computed, allowing incremental updates by calling `signature_state_update()` again afterwards."]
    #[doc = "/ "]
    #[doc = "/ Example usage - signature creation"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let kp_handle = ctx.keypair_import(AlgorithmType::Signatures, \"Ed25519ph\", keypair, KeypairEncoding::Raw)?;"]
    #[doc = "/ let state_handle = ctx.signature_state_open(kp_handle)?;"]
    #[doc = "/ ctx.signature_state_update(state_handle, b\"message part 1\")?;"]
    #[doc = "/ ctx.signature_state_update(state_handle, b\"message part 2\")?;"]
    #[doc = "/ let sig_handle = ctx.signature_state_sign(state_handle)?;"]
    #[doc = "/ let raw_sig = ctx.signature_export(sig_handle, SignatureEncoding::Raw)?;"]
    #[doc = "/ ```"]
    fn signature_state_open(
        &mut self,
        kp: wasmtime::component::Resource<SignatureKeypair>,
    ) -> Result<wasmtime::component::Resource<SignatureState>, CryptoErrno> {
        SignatureState::open(self.table, kp)
    }

    #[doc = "/ Absorb data into the signature state."]
    #[doc = "/ This function may return `unsupported_feature` if the selected algorithm doesn\'t support incremental updates."]
    #[doc = "/ "]
    fn signature_state_update(
        &mut self,
        state: wasmtime::component::Resource<SignatureState>,
        input: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<(), CryptoErrno> {
        let state = self.table.get(&state)?;
        state.locked(|mut state| state.update(&input))
    }

    #[doc = "/ Compute a signature for all the data collected up to that point."]
    #[doc = "/ "]
    #[doc = "/ The function can be called multiple times for incremental signing."]
    fn signature_state_sign(
        &mut self,
        state: wasmtime::component::Resource<SignatureState>,
    ) -> std::result::Result<wasmtime::component::Resource<Signature>, CryptoErrno> {
        let state = self.table.get(&state)?;
        let signature = state.locked(|mut state| state.sign())?;
        let handle = self.table.push(signature)?;
        Ok(handle)
    }

    #[doc = "/ Destroy a signature state."]
    #[doc = "/ "]
    #[doc = "/ Objects are reference counted. It is safe to close an object immediately after the last function needing it is called."]
    #[doc = "/ "]
    #[doc = "/ Note that closing a signature state doesn\'t close or invalidate the key pair object, that can be reused for further signatures."]
    fn signature_state_close(
        &mut self,
        state: wasmtime::component::Resource<SignatureState>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(state.owned());
        let _state: SignatureState = self.table.delete(state)?;
        Ok(())
    }

    #[doc = "/ Create a new state to collect data to verify a signature on."]
    #[doc = "/ "]
    #[doc = "/ This is the verification counterpart of `signature_state`."]
    #[doc = "/ "]
    #[doc = "/ Data can be injected using `signature_verification_state_update()`, and the state is not closed after a verification, allowing incremental verification."]
    #[doc = "/ "]
    #[doc = "/ Example usage - signature verification:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let pk_handle = ctx.publickey_import(AlgorithmType::Signatures, \"ECDSA_P256_SHA256\", encoded_pk, PublicKeyEncoding::Sec)?;"]
    #[doc = "/ let signature_handle = ctx.signature_import(\"ECDSA_P256_SHA256\", encoded_sig, SignatureEncoding::Der)?;"]
    #[doc = "/ let state_handle = ctx.signature_verification_state_open(pk_handle)?;"]
    #[doc = "/ ctx.signature_verification_state_update(state_handle, \"message\")?;"]
    #[doc = "/ ctx.signature_verification_state_verify(state_handle, signature_handle)?;"]
    #[doc = "/ ```"]
    fn signature_verification_state_open(
        &mut self,
        kp: wasmtime::component::Resource<SignaturePublickey>,
    ) -> Result<wasmtime::component::Resource<SignatureVerificationState>, CryptoErrno> {
        SignatureVerificationState::open(self.table, kp)
    }

    #[doc = "/ Absorb data into the signature verification state."]
    #[doc = "/ "]
    #[doc = "/ This function may return `unsupported_feature` if the selected algorithm doesn\'t support incremental updates."]
    fn signature_verification_state_update(
        &mut self,
        state: wasmtime::component::Resource<SignatureVerificationState>,
        input: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<(), CryptoErrno> {
        let state = self.table.get(&state)?;
        state.locked(|mut state| state.update(&input))
    }

    #[doc = "/ Check that the given signature verifies for the data collected up to that point."]
    #[doc = "/ "]
    #[doc = "/ The state is not closed and can absorb more data to allow for incremental verification."]
    #[doc = "/ "]
    #[doc = "/ The function returns `invalid_signature` if the signature doesn\'t appear to be valid."]
    fn signature_verification_state_verify(
        &mut self,
        state: wasmtime::component::Resource<SignatureVerificationState>,
        signature: wasmtime::component::Resource<Signature>,
    ) -> Result<(), CryptoErrno> {
        let state = self.table.get(&state)?;
        let signature = self.table.get(&signature)?;
        state.locked(|state| state.verify(signature))
    }

    #[doc = "/ Destroy a signature verification state."]
    #[doc = "/ "]
    #[doc = "/ Objects are reference counted. It is safe to close an object immediately after the last function needing it is called."]
    #[doc = "/ "]
    #[doc = "/ Note that closing a signature state doesn\'t close or invalidate the public key object, that can be reused for further verifications."]
    fn signature_verification_state_close(
        &mut self,
        state: wasmtime::component::Resource<SignatureVerificationState>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(state.owned());
        let _state: SignatureVerificationState = self.table.delete(state)?;
        Ok(())
    }

    #[doc = "/ Destroy a signature."]
    fn signature_close(
        &mut self,
        signature: wasmtime::component::Resource<Signature>,
    ) -> Result<(), CryptoErrno> {
        debug_assert!(signature.owned());
        let _signature: Signature = self.table.delete(signature)?;
        Ok(())
    }
}
