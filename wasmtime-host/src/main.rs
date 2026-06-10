use std::error::Error;
use wasmtime::{Engine, Store, component::Component, component::Linker, error::Context};
use wasmtime_wasi::p2::bindings::Command;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_crypto::crypto::{WasiCryptoCtx, WasiCryptoView};

struct HostState {
    table: ResourceTable,
    wasi_ctx: WasiCtx,
    crypto_ctx: WasiCryptoCtx,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.table,
        }
    }
}

impl WasiCryptoView for HostState {
    fn crypto(&mut self) -> wasmtime_wasi_crypto::crypto::WasiCryptoCtxView<'_> {
        wasmtime_wasi_crypto::crypto::WasiCryptoCtxView {
            ctx: &mut self.crypto_ctx,
            table: &mut self.table,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let component_path = args
        .get(1)
        .expect("Usage: wasmtime-host <component.wasm> [args...]");
    let wasi_args: Vec<&str> = args[2..].iter().map(String::as_str).collect();

    let engine = Engine::default();
    let mut linker: Linker<HostState> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_crypto::crypto::add_to_linker(&mut linker)?;

    let mut wasi_ctx_builder = WasiCtxBuilder::new();
    wasi_ctx_builder
        .inherit_stdio()
        .inherit_env()
        .args(&wasi_args); // forward test filter args so `cargo test mytest` works

    let state = HostState {
        table: ResourceTable::new(),
        wasi_ctx: wasi_ctx_builder.build(),
        crypto_ctx: WasiCryptoCtx::default(),
    };

    let mut store = Store::new(&engine, state);
    let component = Component::from_file(&engine, component_path)
        .context("Failed to load WebAssembly component")?;

    let command = Command::instantiate_async(&mut store, &component, &linker).await?;
    let _ = command.wasi_cli_run().call_run(&mut store).await?;

    Ok(())
}
