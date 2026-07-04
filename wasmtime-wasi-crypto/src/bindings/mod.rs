mod asymmetric_common;
mod common;
mod external_secrets;
mod key_exchange;
mod signatures;
mod symmetric;
wasmtime::component::bindgen!(
    {
    world: "imports",
    path: "../spec/wit",
    // Interactions with `ResourceTable` can possibly trap so enable the ability
    // to return traps from generated functions.
    imports: { default: trappable },
    with : {
            "wasi:crypto/wasi-ephemeral-crypto-common.array-output": crate::array_output::ArrayOutput,
            "wasi:crypto/wasi-ephemeral-crypto-common.options": crate::options::Options,
            // "wasi:crypto/wasi-ephemeral-crypto-common.secrets-manager": ,
            "wasi:crypto/wasi-ephemeral-crypto-common.keypair": crate::keypair::KeyPair,
            "wasi:crypto/wasi-ephemeral-crypto-common.signature-state": crate::signatures::signature::SignatureState,
            "wasi:crypto/wasi-ephemeral-crypto-common.signature": crate::signatures::Signature,
            "wasi:crypto/wasi-ephemeral-crypto-common.publickey": crate::asymmetric_common::publickey::PublicKey,
            "wasi:crypto/wasi-ephemeral-crypto-common.secretkey": crate::asymmetric_common::secretkey::SecretKey,
            "wasi:crypto/wasi-ephemeral-crypto-common.signature-verification-state": crate::signatures::signature::SignatureVerificationState,
            "wasi:crypto/wasi-ephemeral-crypto-common.symmetric-state": crate::symmetric::SymmetricState,
            "wasi:crypto/wasi-ephemeral-crypto-common.symmetric-key": crate::symmetric::SymmetricKey,
            "wasi:crypto/wasi-ephemeral-crypto-common.symmetric-tag": crate::symmetric::SymmetricTag,
        },
        trappable_error_type: {
            "wasi:crypto/wasi-ephemeral-crypto-common.crypto-errno" => crate::error::CryptoError,
        }
    }
);
