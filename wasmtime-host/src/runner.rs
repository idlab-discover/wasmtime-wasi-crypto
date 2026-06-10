use std::{error::Error, path::Path};
use wasmtime::{Engine, component::Component, error::Context};
use wasmtime_wasi::p2::bindings::Command;

use crate::host::HostState;
use wasmtime_wasi::ResourceTable;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi_crypto::crypto::WasiCryptoCtx;

/// Retrieve the list of test names from a wasm test binary by running it
/// with `-- --list`. Returns one test name per entry.
pub async fn list_tests(
    engine: &Engine,
    linker: &wasmtime::component::Linker<HostState>,
    component: &Component,
) -> Result<Vec<String>, Box<dyn Error>> {
    let stdout = MemoryOutputPipe::new(usize::MAX);

    let wasi_ctx = WasiCtxBuilder::new()
        .inherit_stderr()
        .stdout(stdout.clone())
        .args(&["--", "--list"])
        .build();

    let mut store = wasmtime::Store::new(
        engine,
        HostState {
            table: ResourceTable::new(),
            wasi_ctx,
            crypto_ctx: WasiCryptoCtx::default(),
        },
    );

    let command = Command::instantiate_async(&mut store, component, linker).await?;
    let _ = command.wasi_cli_run().call_run(&mut store).await;

    let output = String::from_utf8(stdout.contents().to_vec())?;
    let tests = output
        .lines()
        .filter(|l| l.ends_with(": test"))
        .map(|l| l.trim_end_matches(": test").trim().to_string())
        .collect();

    Ok(tests)
}

/// Spawn the current executable once per test, passing `--run <test>` so
/// each test gets a fresh wasm instance. A trap in one cannot kill others.
pub async fn run_each(component: &Path) -> Result<(), Box<dyn Error>> {
    let engine = Engine::default();
    let linker = crate::host::make_linker(&engine)?;
    let component =
        Component::from_file(&engine, component).context("Failed to load WebAssembly component")?;

    let tests = list_tests(&engine, &linker, &component).await?;

    if tests.is_empty() {
        eprintln!("no tests found");
        return Ok(());
    }

    let mut failed: Vec<String> = Vec::new();

    for test in &tests {
        // Fresh store with full stdio passthrough — let the wasm harness
        // print its own output directly, don't add our own layer on top
        let mut store = crate::host::make_store(&engine, &["--", "--exact", test, "--nocapture"]);
        let command = Command::instantiate_async(&mut store, &component, &linker).await?;

        let success = match command.wasi_cli_run().call_run(&mut store).await {
            Ok(Ok(())) => true,
            Ok(Err(())) => false,
            Err(e) => {
                if e.downcast_ref::<wasmtime::Trap>().is_some() {
                    eprintln!("trapped: {e:#}");
                }
                false
            }
        };

        if !success {
            failed.push(test.to_string());
        }
    }

    if !failed.is_empty() {
        return Err(format!("failed tests: {}", failed.join(", ")).into());
    }

    Ok(())
}
