use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};

use jobchain_core::amendment::Amendment;
use jobchain_core::credential::VerifiableCredential;

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub command: WalletCommands,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommands {
    /// Build a static credential wallet site
    Build(WalletBuildArgs),
}

#[derive(Debug, Args)]
pub struct WalletBuildArgs {
    /// Input directory containing .vc.json, .amend.json, and optional resume.jobl
    #[arg(long)]
    pub dir: PathBuf,

    /// Output directory for the generated static site
    #[arg(long)]
    pub out: PathBuf,

    /// Page title / holder name
    #[arg(long, default_value = "Credential Wallet")]
    pub title: String,

    /// Base URL for canonical links in index.json (e.g. "https://jake.dev/credentials")
    #[arg(long)]
    pub base_url: Option<String>,

    /// Path to a pre-built WASM pkg directory
    #[arg(long)]
    pub wasm_path: Option<PathBuf>,

    /// Allow overwriting an existing output directory
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Skip local signature verification of credentials during build
    #[arg(long, default_value_t = false)]
    pub no_verify: bool,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A credential with its associated metadata for the wallet.
pub struct CredentialEntry {
    pub credential: VerifiableCredential,
    pub source_path: PathBuf,
    pub content_hash: String,
    pub amendments: Vec<(Amendment, PathBuf)>,
    pub slug: String,
}

/// Scanned input from the credential directory.
pub struct WalletInput {
    pub credentials: Vec<CredentialEntry>,
    pub resume: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Scan a flat directory for credentials, amendments, and resume.
pub fn scan_credentials(dir: &Path) -> Result<WalletInput> {
    let mut vc_paths: Vec<PathBuf> = Vec::new();
    let mut amend_paths: Vec<PathBuf> = Vec::new();
    let mut resume: Option<PathBuf> = None;

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.ends_with(".vc.json") {
            vc_paths.push(path);
        } else if name.ends_with(".amend.json") {
            amend_paths.push(path);
        } else if name == "resume.jobl" {
            resume = Some(path);
        }
    }

    // Parse credentials
    let mut entries_out: Vec<CredentialEntry> = Vec::new();
    for vc_path in &vc_paths {
        let json_str = std::fs::read_to_string(vc_path)
            .with_context(|| format!("failed to read {}", vc_path.display()))?;
        let credential: VerifiableCredential = serde_json::from_str(&json_str)
            .with_context(|| format!("failed to parse {}", vc_path.display()))?;

        // Compute content hash from canonical bytes
        let canonical = canonical_json_bytes(&credential)?;
        let hash = sha256_hex(&canonical);

        let slug = make_slug(&credential);

        entries_out.push(CredentialEntry {
            credential,
            source_path: vc_path.clone(),
            content_hash: format!("sha256:{hash}"),
            amendments: Vec::new(),
            slug,
        });
    }

    // Parse amendments and link to credentials
    for amend_path in &amend_paths {
        let json_str = std::fs::read_to_string(amend_path)
            .with_context(|| format!("failed to read {}", amend_path.display()))?;
        let amendment: Amendment = serde_json::from_str(&json_str)
            .with_context(|| format!("failed to parse {}", amend_path.display()))?;

        let original_ref = &amendment.credential_subject.original_credential;

        // Find the parent credential
        if let Some(entry) = entries_out
            .iter_mut()
            .find(|e| &e.content_hash == original_ref)
        {
            entry.amendments.push((amendment, amend_path.clone()));
        } else {
            eprintln!(
                "Warning: amendment {} references unknown credential hash {}, skipping",
                amend_path.display(),
                original_ref
            );
        }
    }

    // Sort amendments by effective_date within each credential
    for entry in &mut entries_out {
        entry
            .amendments
            .sort_by(|a, b| a.0.effective_date.cmp(&b.0.effective_date));
    }

    // Sort credentials by issuance_date descending (most recent first)
    entries_out.sort_by(|a, b| {
        b.credential
            .issuance_date
            .cmp(&a.credential.issuance_date)
    });

    Ok(WalletInput {
        credentials: entries_out,
        resume,
    })
}

fn canonical_json_bytes(vc: &VerifiableCredential) -> Result<Vec<u8>> {
    let value = serde_json::to_value(vc)?;
    let canonical = jobchain_core::credential::canonicalize(&value);
    Ok(serde_json::to_vec(&canonical)?)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn make_slug(vc: &VerifiableCredential) -> String {
    let company = vc
        .credential_subject
        .experience
        .company
        .to_lowercase()
        .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
    let start = vc
        .credential_subject
        .experience
        .start
        .as_deref()
        .unwrap_or("unknown");
    // Take just the year portion if available
    let year = start.split('-').next().unwrap_or(start);
    format!("{company}-{year}")
}

// ---------------------------------------------------------------------------
// HTML templates
// ---------------------------------------------------------------------------

fn render_style() -> &'static str {
    r#"<style>
:root {
  --bg: #fff; --fg: #1a1a1a; --muted: #666; --border: #e0e0e0;
  --card-bg: #f8f8f8; --accent: #2563eb; --green: #16a34a; --red: #dc2626;
  --yellow: #ca8a04; --code-bg: #f1f5f9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111; --fg: #e5e5e5; --muted: #999; --border: #333;
    --card-bg: #1a1a1a; --accent: #60a5fa; --green: #4ade80; --red: #f87171;
    --yellow: #fbbf24; --code-bg: #1e293b;
  }
}
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--fg); max-width: 48rem; margin: 0 auto;
  padding: 2rem 1rem; line-height: 1.6;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { margin: 0 0 0.25rem; font-size: 1.75rem; }
.subtitle { color: var(--muted); margin-bottom: 2rem; }
.card {
  background: var(--card-bg); border: 1px solid var(--border);
  border-radius: 0.5rem; padding: 1.25rem; margin-bottom: 1rem;
}
.card h2 { margin: 0 0 0.25rem; font-size: 1.1rem; }
.card .meta { color: var(--muted); font-size: 0.875rem; }
.badge {
  display: inline-block; font-size: 0.75rem; padding: 0.125rem 0.5rem;
  border-radius: 1rem; font-weight: 600;
}
.badge-ok { background: var(--green); color: #fff; }
.badge-warn { background: var(--yellow); color: #fff; }
.badge-err { background: var(--red); color: #fff; }
.timeline { border-left: 2px solid var(--border); margin: 1rem 0; padding-left: 1.25rem; }
.timeline-item { margin-bottom: 1rem; position: relative; }
.timeline-item::before {
  content: ""; position: absolute; left: -1.55rem; top: 0.4rem;
  width: 0.6rem; height: 0.6rem; background: var(--accent);
  border-radius: 50%;
}
.timeline-date { font-size: 0.8rem; color: var(--muted); }
details { margin-top: 1rem; }
summary { cursor: pointer; font-weight: 600; }
pre {
  background: var(--code-bg); padding: 1rem; border-radius: 0.375rem;
  overflow-x: auto; font-size: 0.8rem;
}
.btn {
  display: inline-block; padding: 0.5rem 1rem; border-radius: 0.375rem;
  border: 1px solid var(--accent); color: var(--accent); background: transparent;
  cursor: pointer; font-size: 0.875rem; margin-top: 0.5rem;
}
.btn:hover { background: var(--accent); color: #fff; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; }
nav { margin-bottom: 1.5rem; }
</style>"#
}

fn render_index(
    title: &str,
    entries: &[CredentialEntry],
    has_resume: bool,
    has_wasm: bool,
) -> String {
    let mut cards = String::new();
    for entry in entries {
        let vc = &entry.credential;
        let exp = &vc.credential_subject.experience;
        let date_range = format!(
            "{} — {}",
            exp.start.as_deref().unwrap_or("?"),
            exp.end.as_deref().unwrap_or("Present")
        );
        let amend_count = entry.amendments.len();
        let amend_note = if amend_count > 0 {
            format!(
                " · {} amendment{}",
                amend_count,
                if amend_count == 1 { "" } else { "s" }
            )
        } else {
            String::new()
        };

        cards.push_str(&format!(
            r#"<div class="card">
  <h2><a href="{slug}.html">{title} at {company}</a></h2>
  <p class="meta">{date_range} · Issuer: <code>{issuer}</code>{amend_note}</p>
</div>
"#,
            slug = entry.slug,
            title = html_escape(&exp.title),
            company = html_escape(&exp.company),
            date_range = html_escape(&date_range),
            issuer = html_escape(&vc.issuer),
            amend_note = amend_note,
        ));
    }

    let resume_section = if has_resume {
        r#"<div class="card"><h2><a href="resume.jobl">Resume (jobl)</a></h2><p class="meta">Self-authored resume in jobl format</p></div>"#.to_string()
    } else {
        String::new()
    };

    let verify_all = if has_wasm {
        r#"<button class="btn" id="verify-all">Verify All</button>"#
    } else {
        ""
    };

    let wasm_script = if has_wasm {
        r#"<script type="module">
let wasmMod = null;
async function loadWasm() {
  if (wasmMod) return wasmMod;
  const mod = await import('./assets/jobchain_verify.js');
  await mod.default('./assets/jobchain_verify_bg.wasm');
  wasmMod = mod;
  return mod;
}
document.getElementById('verify-all')?.addEventListener('click', async () => {
  const btn = document.getElementById('verify-all');
  btn.textContent = 'Verifying…';
  const mod = await loadWasm();
  document.querySelectorAll('script[type="application/json"][data-credential]').forEach(el => {
    const json = el.textContent;
    const pubkey = el.dataset.pubkey || '';
    if (!pubkey) return;
    const result = JSON.parse(JSON.stringify(mod.verify_credential_json(json, pubkey)));
  });
  btn.textContent = 'Done';
});
</script>"#
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
{style}
</head>
<body>
<h1>{title}</h1>
<p class="subtitle">Verifiable credential portfolio · <a href="index.json">Machine-readable manifest</a></p>
{verify_all}
{cards}
{resume_section}
<footer>Verified with <a href="https://github.com/jakegoldsborough/jobchain">jobchain</a></footer>
{wasm_script}
</body>
</html>"#,
        title = html_escape(title),
        style = render_style(),
        verify_all = verify_all,
        cards = cards,
        resume_section = resume_section,
        wasm_script = wasm_script,
    )
}

fn render_credential_page(entry: &CredentialEntry, title: &str, has_wasm: bool) -> String {
    let vc = &entry.credential;
    let exp = &vc.credential_subject.experience;
    let cred_json = serde_json::to_string_pretty(vc).unwrap_or_default();

    let date_range = format!(
        "{} — {}",
        exp.start.as_deref().unwrap_or("?"),
        exp.end.as_deref().unwrap_or("Present")
    );

    let proof_section = if let Some(proof) = &vc.proof {
        format!(
            r#"<h3>Proof</h3>
<p><strong>Type:</strong> {}</p>
<p><strong>Verification Method:</strong> <code>{}</code></p>
<p><strong>Created:</strong> {}</p>"#,
            html_escape(&proof.r#type),
            html_escape(&proof.verification_method),
            html_escape(&proof.created),
        )
    } else {
        "<p><span class=\"badge badge-warn\">Unsigned</span></p>".to_string()
    };

    // Extract public key hex from verification method for WASM verification
    let pubkey_attr = if let Some(proof) = &vc.proof {
        // The verification method is like did:web:example.com#key-1
        // We don't have the raw key here, but we embed the verification method
        // so the JS can potentially resolve it
        format!(r#" data-verification-method="{}""#, html_escape(&proof.verification_method))
    } else {
        String::new()
    };

    let amendments_section = if entry.amendments.is_empty() {
        String::new()
    } else {
        let mut items = String::new();
        for (amendment, _) in &entry.amendments {
            let changes_str: Vec<String> = amendment
                .credential_subject
                .changes
                .iter()
                .map(|(k, v)| format!("<strong>{}:</strong> {}", html_escape(k), html_escape(&v.to_string())))
                .collect();
            items.push_str(&format!(
                r#"<div class="timeline-item">
  <div class="timeline-date">{date}</div>
  <div>{changes}</div>
  <div class="meta">Issuer: <code>{issuer}</code></div>
</div>
"#,
                date = html_escape(&amendment.effective_date),
                changes = changes_str.join(" · "),
                issuer = html_escape(&amendment.issuer),
            ));
        }
        format!(
            r#"<h3>Amendment History</h3>
<div class="timeline">
{items}</div>"#,
            items = items,
        )
    };

    let verify_button = if has_wasm {
        r#"<button class="btn" id="verify-btn">Verify Signature</button>
<span id="verify-result"></span>"#
    } else {
        ""
    };

    let wasm_script = if has_wasm {
        r#"<script type="module">
let wasmMod = null;
async function loadWasm() {
  if (wasmMod) return wasmMod;
  const mod = await import('./assets/jobchain_verify.js');
  await mod.default('./assets/jobchain_verify_bg.wasm');
  wasmMod = mod;
  return mod;
}
document.getElementById('verify-btn')?.addEventListener('click', async () => {
  const btn = document.getElementById('verify-btn');
  const result = document.getElementById('verify-result');
  btn.textContent = 'Verifying…';
  try {
    const credEl = document.querySelector('script[type="application/json"][data-credential]');
    if (!credEl) { result.textContent = ' No credential data found'; return; }
    const json = credEl.textContent;
    const pubkey = prompt('Enter issuer public key (hex):');
    if (!pubkey) { btn.textContent = 'Verify Signature'; return; }
    const mod = await loadWasm();
    const res = mod.verify_credential_json(json, pubkey);
    if (res.valid) {
      result.innerHTML = ' <span class="badge badge-ok">Valid</span>';
    } else {
      result.innerHTML = ' <span class="badge badge-err">Invalid: ' + (res.error || 'unknown') + '</span>';
    }
  } catch(e) {
    result.innerHTML = ' <span class="badge badge-err">Error: ' + e + '</span>';
  }
  btn.textContent = 'Verify Signature';
});
</script>"#
    } else {
        ""
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{exp_title} at {company} — {site_title}</title>
{style}
</head>
<body>
<nav><a href="index.html">&larr; Back to wallet</a></nav>
<h1>{exp_title} at {company}</h1>
<p class="meta">{date_range}</p>
<p><strong>Issuer:</strong> <code>{issuer}</code></p>
<p><strong>Issued:</strong> {issuance_date}</p>

{proof_section}
{verify_button}
{amendments_section}

<details>
  <summary>Raw credential JSON</summary>
  <pre><code>{cred_json_escaped}</code></pre>
</details>

<script type="application/json" data-credential{pubkey_attr}>{cred_json_raw}</script>

<footer>Verified with <a href="https://github.com/jakegoldsborough/jobchain">jobchain</a></footer>
{wasm_script}
</body>
</html>"#,
        exp_title = html_escape(&exp.title),
        company = html_escape(&exp.company),
        site_title = html_escape(title),
        style = render_style(),
        date_range = html_escape(&date_range),
        issuer = html_escape(&vc.issuer),
        issuance_date = html_escape(&vc.issuance_date),
        proof_section = proof_section,
        verify_button = verify_button,
        amendments_section = amendments_section,
        cred_json_escaped = html_escape(&cred_json),
        cred_json_raw = cred_json,
        pubkey_attr = pubkey_attr,
        wasm_script = wasm_script,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// index.json manifest
// ---------------------------------------------------------------------------

fn generate_manifest(
    title: &str,
    entries: &[CredentialEntry],
    resume: &Option<PathBuf>,
    base_url: &Option<String>,
) -> serde_json::Value {
    let url_prefix = base_url
        .as_ref()
        .map(|u| {
            let u = u.trim_end_matches('/');
            format!("{u}/")
        })
        .unwrap_or_default();

    let credentials: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let vc = &entry.credential;
            let exp = &vc.credential_subject.experience;
            let amendments: Vec<serde_json::Value> = entry
                .amendments
                .iter()
                .map(|(a, _)| {
                    serde_json::json!({
                        "effectiveDate": a.effective_date,
                        "changes": a.credential_subject.changes,
                    })
                })
                .collect();

            let vc_filename = entry
                .source_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            let mut cred = serde_json::json!({
                "id": entry.slug,
                "type": vc.r#type,
                "issuer": vc.issuer,
                "issuanceDate": vc.issuance_date,
                "credentialSubject": {
                    "title": exp.title,
                    "company": exp.company,
                },
                "credentialUrl": format!("{url_prefix}{vc_filename}"),
                "pageUrl": format!("{url_prefix}{}.html", entry.slug),
            });

            if !amendments.is_empty() {
                cred["amendments"] = serde_json::Value::Array(amendments);
            }

            cred
        })
        .collect();

    let resume_url = resume.as_ref().map(|_| {
        serde_json::Value::String(format!("{url_prefix}resume.jobl"))
    });

    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "CredentialWallet",
        "holder": title,
        "credentials": credentials,
        "resume": resume_url,
        "generatedAt": now,
    })
}

// ---------------------------------------------------------------------------
// Build command
// ---------------------------------------------------------------------------

pub fn run(args: WalletArgs) -> Result<()> {
    match args.command {
        WalletCommands::Build(build_args) => run_build(build_args),
    }
}

fn run_build(args: WalletBuildArgs) -> Result<()> {
    // Validate input directory
    if !args.dir.is_dir() {
        bail!(
            "Input directory {} does not exist or is not a directory",
            args.dir.display()
        );
    }

    // Validate output directory
    if args.out.exists() {
        if args.out.is_dir() {
            let is_empty = args
                .out
                .read_dir()
                .map(|mut d| d.next().is_none())
                .unwrap_or(false);
            if !is_empty && !args.force {
                bail!(
                    "Output directory {} is not empty. Use --force to overwrite.",
                    args.out.display()
                );
            }
            if !is_empty && args.force {
                eprintln!(
                    "Warning: overwriting existing output directory {}",
                    args.out.display()
                );
                std::fs::remove_dir_all(&args.out)
                    .with_context(|| format!("failed to remove {}", args.out.display()))?;
            }
        } else {
            bail!("{} exists and is not a directory", args.out.display());
        }
    }
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("failed to create {}", args.out.display()))?;

    // Locate WASM assets
    let has_wasm = locate_wasm(&args.wasm_path);
    if !has_wasm {
        eprintln!(
            "WASM verification module not found. Run \
             'wasm-pack build crates/jobchain-verify --target web --features wasm' \
             to enable in-browser verification. Generating site without verify buttons."
        );
    }

    // Scan credentials
    let input = scan_credentials(&args.dir)?;
    let n_creds = input.credentials.len();
    let n_amendments: usize = input.credentials.iter().map(|e| e.amendments.len()).sum();
    eprintln!("Found {n_creds} credentials, {n_amendments} amendments");

    // Optionally verify credentials locally
    if !args.no_verify {
        for entry in &input.credentials {
            let issuer = &entry.credential.issuer;
            // Try to find a local public key at ~/.jobchain/{domain}/public.key
            let domain = issuer.strip_prefix("did:web:").unwrap_or(issuer);
            let home = dirs::home_dir();
            let key_path = home.map(|h| h.join(".jobchain").join(domain).join("public.key"));

            if let Some(kp) = key_path.filter(|p| p.exists()) {
                match std::fs::read(&kp) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        match jobchain_verify::verify_credential(&entry.credential, &key) {
                            Ok(()) => eprintln!(
                                "  ✓ {} at {} — verified",
                                entry.credential.credential_subject.experience.title,
                                entry.credential.credential_subject.experience.company
                            ),
                            Err(e) => eprintln!(
                                "  ✗ {} at {} — {}",
                                entry.credential.credential_subject.experience.title,
                                entry.credential.credential_subject.experience.company,
                                e
                            ),
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Generate index.html
    let index_html = render_index(&args.title, &input.credentials, input.resume.is_some(), has_wasm);
    std::fs::write(args.out.join("index.html"), &index_html)?;

    // Generate index.json
    let manifest = generate_manifest(&args.title, &input.credentials, &input.resume, &args.base_url);
    std::fs::write(
        args.out.join("index.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    // Generate individual credential pages and copy source files
    for entry in &input.credentials {
        let page = render_credential_page(entry, &args.title, has_wasm);
        std::fs::write(args.out.join(format!("{}.html", entry.slug)), &page)?;

        // Copy .vc.json
        let dest_name = entry
            .source_path
            .file_name()
            .unwrap_or_default();
        std::fs::copy(&entry.source_path, args.out.join(dest_name))?;

        // Copy .amend.json files
        for (_, amend_path) in &entry.amendments {
            let dest_name = amend_path.file_name().unwrap_or_default();
            std::fs::copy(amend_path, args.out.join(dest_name))?;
        }
    }

    // Copy resume if present
    if let Some(resume_path) = &input.resume {
        std::fs::copy(resume_path, args.out.join("resume.jobl"))?;
    }

    // Copy WASM assets if available
    if has_wasm {
        let wasm_src = find_wasm_dir(&args.wasm_path).unwrap();
        let assets_dir = args.out.join("assets");
        std::fs::create_dir_all(&assets_dir)?;
        // Copy .wasm and .js files
        for ext in &["wasm", "js"] {
            for file in std::fs::read_dir(&wasm_src)? {
                let file = file?;
                let path = file.path();
                if path.extension().and_then(|e| e.to_str()) == Some(ext) {
                    let dest = assets_dir.join(path.file_name().unwrap());
                    std::fs::copy(&path, &dest)?;
                }
            }
        }
    }

    eprintln!("Wallet generated: {}/", args.out.display());
    eprintln!("  {} credential pages", n_creds);
    eprintln!("  index.html + index.json");
    eprintln!(
        "  {} in-browser verification",
        if has_wasm { "with" } else { "without" }
    );
    eprintln!(
        "  Deploy to any static host: cp -r {}/ your-server/",
        args.out.display()
    );

    Ok(())
}

fn locate_wasm(wasm_path: &Option<PathBuf>) -> bool {
    find_wasm_dir(wasm_path).is_some()
}

fn find_wasm_dir(wasm_path: &Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = wasm_path
        && p.is_dir()
    {
        return Some(p.clone());
    }

    // Try target/wasm-pkg relative to the workspace root
    let workspace_wasm = PathBuf::from("target/wasm-pkg");
    if workspace_wasm.is_dir() {
        return Some(workspace_wasm);
    }

    None
}
