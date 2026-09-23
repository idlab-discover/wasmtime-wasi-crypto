use std::path::Path;
use wasmtime::error::Context;
use wasmtime::{Engine, Store, component::Component, component::Linker};
use wasmtime_wasi::p2::bindings::Command;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_crypto::crypto::{WasiCryptoCtx, WasiCryptoView};
use wasmtime_wasi_crypto::limits::Limits;

pub struct HostState {
    pub(crate) table: ResourceTable,
    pub(crate) wasi_ctx: WasiCtx,
    pub(crate) crypto_ctx: WasiCryptoCtx,
    pub(crate) limits: Limits,
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
            limits: &mut self.limits,
        }
    }
}

pub fn make_linker(engine: &Engine) -> anyhow::Result<Linker<HostState>> {
    let mut linker: Linker<HostState> = Linker::new(engine);
    // https://docs.wasmtime.dev/api/wasmtime_wasi/p2/bindings/index.html
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_crypto::crypto::add_to_linker(&mut linker)?;
    Ok(linker)
}

pub fn make_store(engine: &Engine, wasi_args: &[&str]) -> Store<HostState> {
    // https://docs.wasmtime.dev/api/wasmtime_wasi/p2/bindings/struct.Command.html
    let wasi_ctx = WasiCtxBuilder::new()
        .inherit_stdio()
        .inherit_env()
        .args(wasi_args)
        .build();

    Store::new(
        engine,
        HostState {
            table: ResourceTable::new(),
            wasi_ctx,
            crypto_ctx: WasiCryptoCtx::default(),
            limits: Limits::new(),
        },
    )
}

/// Run a wasm component at `path`, forwarding `wasi_args` as the arguments
/// after the program name.
pub async fn run_component(path: &Path, wasi_args: &[&str]) -> anyhow::Result<()> {
    let engine = Engine::default();
    let linker = make_linker(&engine)?;

    // Guests treat argv[0] as the program name and skip it, so supply the
    // component path there (as the wasmtime CLI does). Otherwise the guest
    // would silently drop the first user-supplied argument.
    let program_name = path.to_string_lossy();
    let argv: Vec<&str> = std::iter::once(program_name.as_ref())
        .chain(wasi_args.iter().copied())
        .collect();
    let mut store = make_store(&engine, &argv);

    let component =
        Component::from_file(&engine, path).context("Failed to load WebAssembly component")?;

    let command = Command::instantiate_async(&mut store, &component, &linker).await?;
    command
        .wasi_cli_run()
        .call_run(&mut store)
        .await?
        .map_err(|_| anyhow::anyhow!("wasi:cli/run implementing function returned error"))?;
    Ok(())
}
