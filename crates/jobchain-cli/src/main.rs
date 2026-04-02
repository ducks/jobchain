use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "jobchain", version, about = "Verifiable employment credential toolchain")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new jobchain identity (keypair + DID document)
    Init {
        /// Domain for the did:web identifier (e.g. example.com)
        #[arg(long)]
        domain: String,

        /// Directory to write keys and DID document into [default: ~/.jobchain]
        #[arg(long)]
        output_dir: Option<String>,

        /// Overwrite existing files without prompting
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            domain,
            output_dir,
            force,
        } => commands::init::run(&domain, output_dir.as_deref(), force)?,
    }

    Ok(())
}
