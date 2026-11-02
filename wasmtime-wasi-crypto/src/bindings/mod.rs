mod common;
mod external_secrets;
mod kx;
mod kx_managed;
mod secrets_manager;
mod signatures;
mod signatures_managed;
mod symmetric;
mod symmetric_managed;
wasmtime::component::bindgen!(
    {
    world: "imports",
    path: "../spec/wit",
    // Interactions with `ResourceTable` can possibly trap so enable the ability
    // to return traps from generated functions.
    imports: { default: trappable },
    with : {
            "wasi:crypto/common.array-output": crate::array_output::ArrayOutput,
            "wasi:crypto/symmetric.symmetric-options": crate::symmetric::SymmetricOptions,
            "wasi:crypto/symmetric.symmetric-key": crate::symmetric::SymmetricKey,
            "wasi:crypto/symmetric.symmetric-state": crate::symmetric::SymmetricState,
            "wasi:crypto/symmetric.symmetric-tag": crate::symmetric::SymmetricTag,
            "wasi:crypto/signatures.signature-options": crate::signatures::SignatureOptions,
            "wasi:crypto/signatures.signature-keypair": crate::signatures::keypair::SignatureKeyPair,
            "wasi:crypto/signatures.signature-publickey": crate::signatures::publickey::SignaturePublicKey,
            "wasi:crypto/signatures.signature-secretkey": crate::signatures::secretkey::SignatureSecretKey,
            "wasi:crypto/signatures.signature": crate::signatures::Signature,
            "wasi:crypto/signatures.signature-state": crate::signatures::signature::SignatureState,
            "wasi:crypto/signatures.signature-verification-state": crate::signatures::signature::SignatureVerificationState,
            "wasi:crypto/kx.kx-options": crate::key_exchange::KxOptions,
            "wasi:crypto/kx.kx-keypair": crate::key_exchange::keypair::KxKeyPair,
            "wasi:crypto/kx.kx-publickey": crate::key_exchange::publickey::KxPublicKey,
            "wasi:crypto/kx.kx-secretkey": crate::key_exchange::secretkey::KxSecretKey,
            "wasi:crypto/secrets-manager.secrets-manager-options": crate::secrets_manager::SecretsManagerOptions,
            // "wasi:crypto/secrets-manager.secrets-manager" stays unmapped: there
            // is no backing type yet, since `secrets-manager.open` always fails.
        },
        trappable_error_type: {
            "wasi:crypto/common.crypto-errno" => crate::error::CryptoError,
        }
    }
);
