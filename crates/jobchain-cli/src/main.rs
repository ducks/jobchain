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
    /// Issue a signed verifiable credential from an ExperienceItem
    Issue {
        /// Domain for the issuer DID (loads keypair from ~/.jobchain/<domain>/secret.key or --key-dir)
        #[arg(long)]
        domain: String,

        /// Path to ExperienceItem JSON file (reads from stdin if omitted)
        #[arg(long)]
        input: Option<String>,

        /// Write output to a file instead of stdout
        #[arg(long)]
        output: Option<String>,

        /// Override issuance date (RFC 3339, e.g. 2025-06-01T00:00:00Z)
        #[arg(long)]
        date: Option<String>,

        /// Directory containing the keypair [default: ~/.jobchain/<domain>]
        #[arg(long)]
        key_dir: Option<String>,
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
        Commands::Issue {
            domain,
            input,
            output,
            date,
            key_dir,
        } => commands::issue::run(&domain, input.as_deref(), output.as_deref(), date.as_deref(), key_dir.as_deref())?,
    }

    Ok(())
}
