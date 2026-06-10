mod host;
mod runner;
use clap::{Parser, Subcommand};
use std::error::Error;

#[derive(Parser)]
#[command(about = "wasmtime host with wasi-crypto support")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a wasm component directly
    Run {
        /// Path to the .wasm component
        component: std::path::PathBuf,

        /// Arguments forwarded to the component as WASI argv
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Run all tests in a wasm test binary, each in an isolated instance
    Test {
        /// Path to the .wasm test binary
        component: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { component, args } => {
            let wasi_args: Vec<&str> = args.iter().map(String::as_str).collect();
            host::run_component(&component, &wasi_args).await?;
        }

        Commands::Test { component } => {
            runner::run_each(&component).await?;
        }
    }

    Ok(())
}
