use crate::crypto::bindings::wasi::crypto::wasi_ephemeral_crypto_kx::Host;

use crate::crypto::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, Publickey, Secretkey,
};

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    #[doc = "/ Perform a simple Diffie-Hellman key exchange."]
    #[doc = "/ "]
    #[doc = "/ Both keys must be of the same type, or else the `$crypto_errno.incompatible_keys` error is returned."]
    #[doc = "/ The algorithm also has to support this kind of key exchange. If this is not the case, the `$crypto_errno.invalid_operation` error is returned."]
    #[doc = "/ "]
    #[doc = "/ Otherwise, a raw shared key is returned, and can be imported as a symmetric key."]
    fn kx_dh(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
        sk: wasmtime::component::Resource<Secretkey>,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        todo!()
    }

    #[doc = "/ Create a shared secret and encrypt it for the given public key."]
    #[doc = "/ "]
    #[doc = "/ This operation is only compatible with specific algorithms."]
    #[doc = "/ If a selected algorithm doesn\'t support it, `$crypto_errno.invalid_operation` is returned."]
    #[doc = "/ "]
    #[doc = "/ On success, both the shared secret and its encrypted version are returned."]
    fn kx_encapsulate(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
    ) -> Result<
        (
            wasmtime::component::Resource<ArrayOutput>,
            wasmtime::component::Resource<ArrayOutput>,
        ),
        CryptoErrno,
    > {
        todo!()
    }

    #[doc = "/ Decapsulate an encapsulated secret created with `kx_encapsulate`"]
    #[doc = "/ "]
    #[doc = "/ Return the secret, or `$crypto_errno.verification_failed` on error."]
    fn kx_decapsulate(
        &mut self,
        sk: wasmtime::component::Resource<Secretkey>,
        encapsulated_secret: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        todo!()
    }
}
