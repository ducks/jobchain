use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{bail, Context};
use chrono::Utc;
use jobchain_core::credential::VerifiableCredential;
use jobchain_core::signing::Keypair;

fn default_key_dir(domain: &str) -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".jobchain").join(domain))
}

pub fn run(
    domain: &str,
    input: Option<&str>,
    output: Option<&str>,
    date: Option<&str>,
    key_dir: Option<&str>,
) -> anyhow::Result<()> {
    let dir = match key_dir {
        Some(p) => PathBuf::from(p),
        None => default_key_dir(domain)?,
    };

    let secret_key_path = dir.join("secret.key");
    if !secret_key_path.exists() {
        bail!(
            "keypair not found at {} (run `jobchain init --domain {}` first)",
            secret_key_path.display(),
            domain
        );
    }

    let keypair = Keypair::load(&secret_key_path)
        .with_context(|| format!("failed to load keypair from {}", secret_key_path.display()))?;

    let json_input = match input {
        Some(path) => {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read input file {path}"))?
        }
        None => {
            if io::stdin().is_terminal() {
                eprintln!("Reading ExperienceItem JSON from stdin (Ctrl-D to finish)...");
            }
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("failed to read from stdin")?;
            buf
        }
    };

    let subject: jobl::ExperienceItem =
        serde_json::from_str(&json_input).context("failed to parse ExperienceItem JSON")?;

    let issuance_date = match date {
        Some(d) => d.to_string(),
        None => Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };

    let issuer = format!("did:web:{domain}");
    let verification_method = format!("did:web:{domain}#key-0");

    let mut vc = VerifiableCredential::new(issuer, issuance_date, subject);
    vc.sign(&keypair, &verification_method)
        .context("failed to sign credential")?;

    let vc_json = serde_json::to_string_pretty(&vc).context("failed to serialize credential")?;

    match output {
        Some(path) => {
            fs::write(path, &vc_json)
                .with_context(|| format!("failed to write output file {path}"))?;
            eprintln!("Credential written to {path}");
        }
        None => {
            println!("{vc_json}");
        }
    }

    eprintln!("Issuer: {}", vc.issuer);
    eprintln!("Subject: {} at {}", vc.credential_subject.experience.title, vc.credential_subject.experience.company);

    Ok(())
}
