use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use jobchain_core::did::{did_document_to_json, generate_did_document};
use jobchain_core::signing::Keypair;

fn default_dir() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    Ok(home.join(".jobchain"))
}

pub fn run(domain: &str, output_dir: Option<&str>, force: bool) -> anyhow::Result<()> {
    let dir = match output_dir {
        Some(p) => PathBuf::from(p),
        None => default_dir()?,
    };

    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let secret_key_path = dir.join("secret.key");
    let public_key_path = dir.join("public.key");
    let did_path = dir.join("did.json");

    if !force {
        for path in [&secret_key_path, &public_key_path, &did_path] {
            if path.exists() {
                bail!(
                    "{} already exists (use --force to overwrite)",
                    path.display()
                );
            }
        }
    }

    let keypair = Keypair::generate().context("failed to generate keypair")?;

    keypair
        .save(&secret_key_path)
        .context("failed to save secret key")?;
    keypair
        .save_public_key(&public_key_path)
        .context("failed to save public key")?;

    let doc = generate_did_document(domain, &keypair.public_key_bytes());
    let json = did_document_to_json(&doc).context("failed to serialize DID document")?;
    fs::write(&did_path, &json).context("failed to write DID document")?;

    println!("Identity initialized in {}", dir.display());
    println!("  Secret key: {}", secret_key_path.display());
    println!("  Public key: {}", public_key_path.display());
    println!("  DID document: {}", did_path.display());
    println!();
    print_did_summary(&did_path)?;

    Ok(())
}

fn print_did_summary(path: &Path) -> anyhow::Result<()> {
    let contents = fs::read_to_string(path)?;
    let doc: serde_json::Value = serde_json::from_str(&contents)?;

    if let Some(id) = doc.get("id").and_then(|v| v.as_str()) {
        println!("DID: {id}");
    }
    if let Some(vms) = doc.get("verificationMethod").and_then(|v| v.as_array())
        && let Some(first) = vms.first()
        && let Some(mb) = first.get("publicKeyMultibase").and_then(|v| v.as_str())
    {
        println!("Public key (multibase): {mb}");
    }

    Ok(())
}
