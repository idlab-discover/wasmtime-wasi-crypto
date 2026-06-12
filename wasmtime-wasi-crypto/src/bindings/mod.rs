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
    with : {
            "wasi:crypto/wasi-ephemeral-crypto-common.options": crate::options::Options,
            "wasi:crypto/wasi-ephemeral-crypto-common.symmetric-key": crate::symmetric::SymmetricKey,
            "wasi:crypto/wasi-ephemeral-crypto-common.array-output": crate::array_output::ArrayOutput,
            "wasi:crypto/wasi-ephemeral-crypto-common.symmetric-state": crate::symmetric::SymmetricState,
            "wasi:crypto/wasi-ephemeral-crypto-common.symmetric-tag": crate::symmetric::SymmetricTag,
        }
    }
);
