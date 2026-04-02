use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn jobchain() -> Command {
    Command::cargo_bin("jobchain").unwrap()
}

/// Create isolated directories for keys, credentials, and wallet output.
/// Returns (TempDir, key_dir, creds_dir, wallet_dir).
/// wallet_dir is NOT created — wallet build should create it.
fn setup_dirs() -> (TempDir, PathBuf, PathBuf, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let key_dir = tmp.path().join("keys");
    let creds_dir = tmp.path().join("creds");
    let wallet_dir = tmp.path().join("wallet");

    std::fs::create_dir_all(&key_dir).unwrap();
    std::fs::create_dir_all(&creds_dir).unwrap();
    // wallet_dir intentionally NOT created

    (tmp, key_dir, creds_dir, wallet_dir)
}

fn sample_experience_json() -> &'static str {
    r#"{
  "title": "Infrastructure Engineer",
  "company": "Acme Corp",
  "start": "2023-06",
  "technologies": ["Rust", "Nix"],
  "highlights": ["Built credential system", "Automated deployments"]
}"#
}

fn sample_experience_json_2() -> &'static str {
    r#"{
  "title": "DevOps Lead",
  "company": "Acme Corp",
  "start": "2021-01",
  "end": "2023-05",
  "technologies": ["Terraform", "Ansible"],
  "highlights": ["Led platform migration"]
}"#
}

fn sample_patch_json() -> &'static str {
    r#"{"title": "Senior Infrastructure Engineer"}"#
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Compute SHA-256 of bytes as "sha256:<hex>".
fn content_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    format!("sha256:{}", digest.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Recursively sort all object keys (same as core's canonicalize).
fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            serde_json::to_value(sorted).unwrap()
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

/// Canonical JSON bytes of a value (sorted keys, compact).
fn hashable_bytes(val: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&canonicalize(val)).unwrap()
}

// ===========================================================================
// Primary end-to-end test
// ===========================================================================

#[test]
fn test_full_flow_init_issue_amend_verify_wallet() {
    let (_tmp, key_dir, creds_dir, wallet_dir) = setup_dirs();

    // -----------------------------------------------------------------------
    // a. INIT — Generate keypair and DID document
    // -----------------------------------------------------------------------
    let did_file = key_dir.join("did.json");
    jobchain()
        .args([
            "init",
            "--org", "Acme Corp",
            "--domain", "acme.example.com",
            "--key-dir", p(&key_dir),
            "--output", p(&did_file),
        ])
        .assert()
        .success();

    let domain_dir = key_dir.join("acme.example.com");
    assert!(domain_dir.join("secret.key").exists());
    assert!(domain_dir.join("public.key").exists());
    assert!(!std::fs::read(domain_dir.join("secret.key")).unwrap().is_empty());
    assert!(!std::fs::read(domain_dir.join("public.key")).unwrap().is_empty());
    assert!(did_file.exists());

    let did_doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&did_file).unwrap()).unwrap();
    assert_eq!(did_doc["id"], "did:web:acme.example.com");
    let vm = did_doc["verificationMethod"].as_array().unwrap();
    assert!(!vm.is_empty());
    assert!(vm[0]["publicKeyMultibase"].as_str().unwrap().starts_with('z'));

    // -----------------------------------------------------------------------
    // b. ISSUE — First credential (Infrastructure Engineer)
    // -----------------------------------------------------------------------
    let cred1_path = creds_dir.join("acme-2023.vc.json");
    jobchain()
        .args([
            "issue",
            "--domain", "acme.example.com",
            "--key-dir", p(&key_dir),
            "--output", p(&cred1_path),
        ])
        .write_stdin(sample_experience_json())
        .assert()
        .success();

    assert!(cred1_path.exists());
    let cred1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cred1_path).unwrap()).unwrap();

    assert!(cred1["@context"].as_array().unwrap().iter().any(|v| v == "https://www.w3.org/2018/credentials/v1"));
    let types = cred1["type"].as_array().unwrap();
    assert!(types.iter().any(|v| v == "VerifiableCredential"));
    assert!(types.iter().any(|v| v == "EmploymentCredential"));
    assert_eq!(cred1["issuer"], "did:web:acme.example.com");
    assert!(!cred1["issuanceDate"].as_str().unwrap().is_empty());
    assert_eq!(cred1["credentialSubject"]["title"], "Infrastructure Engineer");
    assert_eq!(cred1["credentialSubject"]["company"], "Acme Corp");

    let proof = &cred1["proof"];
    assert_eq!(proof["type"], "Ed25519Signature2020");
    assert!(proof["proofValue"].as_str().unwrap().starts_with('z'));
    assert!(proof["verificationMethod"].as_str().unwrap().contains("acme.example.com#key-1"));

    // -----------------------------------------------------------------------
    // c. ISSUE — Second credential (DevOps Lead)
    // -----------------------------------------------------------------------
    let cred2_path = creds_dir.join("acme-2021.vc.json");
    jobchain()
        .args([
            "issue",
            "--domain", "acme.example.com",
            "--key-dir", p(&key_dir),
            "--output", p(&cred2_path),
        ])
        .write_stdin(sample_experience_json_2())
        .assert()
        .success();

    assert!(cred2_path.exists());
    let cred2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cred2_path).unwrap()).unwrap();
    assert!(cred2["proof"].is_object());

    // -----------------------------------------------------------------------
    // d. VERIFY — Original credential (plain output)
    // -----------------------------------------------------------------------
    let pk_path = domain_dir.join("public.key");
    jobchain()
        .args([
            "verify",
            "--input", p(&cred1_path),
            "--key", p(&pk_path),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // -----------------------------------------------------------------------
    // e. VERIFY — With --json output
    // -----------------------------------------------------------------------
    let verify_output = jobchain()
        .args([
            "verify",
            "--input", p(&cred1_path),
            "--key", p(&pk_path),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(verify_output.status.success());
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify_output.stdout).unwrap();
    assert_eq!(verify_json["valid"], true);

    // -----------------------------------------------------------------------
    // f. AMEND — Promote the engineer
    // -----------------------------------------------------------------------
    let amend1_path = creds_dir.join("acme-2023-amend-1.amend.json");
    let patch_file = creds_dir.join("patch.json");
    std::fs::write(&patch_file, sample_patch_json()).unwrap();

    jobchain()
        .args([
            "amend",
            "--credential", p(&cred1_path),
            "--patch", p(&patch_file),
            "--domain", "acme.example.com",
            "--effective-date", "2025-01-15",
            "--key-dir", p(&key_dir),
            "--output", p(&amend1_path),
        ])
        .assert()
        .success();

    assert!(amend1_path.exists());
    let amend1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&amend1_path).unwrap()).unwrap();

    let amend_types = amend1["type"].as_array().unwrap();
    assert!(amend_types.iter().any(|v| v == "AmendmentCredential"));
    assert!(amend1["previousHash"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(amend1["effectiveDate"], "2025-01-15");
    assert_eq!(amend1["credentialSubject"]["type"], "AmendmentRecord");
    assert!(amend1["credentialSubject"]["originalCredential"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(amend1["credentialSubject"]["changes"]["title"], "Senior Infrastructure Engineer");
    assert!(amend1["proof"].is_object());

    // -----------------------------------------------------------------------
    // g. VERIFY — Amendment signature
    // -----------------------------------------------------------------------
    jobchain()
        .args([
            "verify",
            "--input", p(&amend1_path),
            "--key", p(&pk_path),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));

    // -----------------------------------------------------------------------
    // h. VERIFY — Amendment chain link integrity
    // -----------------------------------------------------------------------
    let cred1_hash = content_hash(&hashable_bytes(&cred1));
    assert_eq!(amend1["previousHash"].as_str().unwrap(), cred1_hash);

    // -----------------------------------------------------------------------
    // i. WALLET BUILD — Generate the static site
    // -----------------------------------------------------------------------
    jobchain()
        .args([
            "wallet", "build",
            "--dir", p(&creds_dir),
            "--out", p(&wallet_dir),
            "--title", "Acme Corp Credentials",
            "--base-url", "https://acme.example.com/credentials",
            "--no-verify",
        ])
        .assert()
        .success();

    assert!(wallet_dir.join("index.html").exists());
    assert!(wallet_dir.join("index.json").exists());

    // At least two credential detail pages
    let html_pages: Vec<_> = std::fs::read_dir(&wallet_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".html") && name != "index.html"
        })
        .collect();
    assert!(html_pages.len() >= 2, "expected at least 2 credential pages, got {}", html_pages.len());

    // .vc.json files are copied
    let vc_files: Vec<_> = std::fs::read_dir(&wallet_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".vc.json"))
        .collect();
    assert_eq!(vc_files.len(), 2);

    // .amend.json files are copied
    let amend_files: Vec<_> = std::fs::read_dir(&wallet_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".amend.json"))
        .collect();
    assert_eq!(amend_files.len(), 1);

    // -----------------------------------------------------------------------
    // j. WALLET MANIFEST validation
    // -----------------------------------------------------------------------
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(wallet_dir.join("index.json")).unwrap()).unwrap();

    assert!(manifest["@context"].is_array());
    assert_eq!(manifest["type"], "CredentialWallet");
    assert_eq!(manifest["holder"], "Acme Corp Credentials");
    assert!(manifest["generatedAt"].is_string());

    let creds = manifest["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 2, "expected 2 credentials in manifest");

    // Find the credential that was amended
    let amended_cred = creds.iter().find(|c| {
        c.get("amendments")
            .and_then(|a| a.as_array())
            .is_some_and(|arr| !arr.is_empty())
    }).expect("one credential should have amendments");

    let amendments = amended_cred["amendments"].as_array().unwrap();
    assert_eq!(amendments.len(), 1);
    assert_eq!(amendments[0]["effectiveDate"], "2025-01-15");
    assert_eq!(amendments[0]["changes"]["title"], "Senior Infrastructure Engineer");

    // credentialUrl values use base-url
    for cred in creds {
        let url = cred["credentialUrl"].as_str().unwrap();
        assert!(
            url.starts_with("https://acme.example.com/credentials/"),
            "expected base-url prefix, got: {url}"
        );
    }

    // -----------------------------------------------------------------------
    // k. WALLET HTML content validation
    // -----------------------------------------------------------------------
    let index_html = std::fs::read_to_string(wallet_dir.join("index.html")).unwrap();
    assert!(index_html.contains("Acme Corp Credentials"));
    assert!(index_html.contains("Infrastructure Engineer"));
    assert!(index_html.contains("DevOps Lead"));
    assert!(index_html.contains("acme.example.com"));

    // Read a credential detail page
    let detail_html = std::fs::read_to_string(html_pages[0].path()).unwrap();
    assert!(detail_html.contains(r#"<script type="application/json"#));
}

// ===========================================================================
// Negative path: tampered credential rejected
// ===========================================================================

#[test]
fn test_verify_rejects_tampered_credential() {
    let (_tmp, key_dir, creds_dir, _wallet_dir) = setup_dirs();

    // Init + issue
    jobchain()
        .args(["init", "--org", "A", "--domain", "acme.example.com", "--key-dir", p(&key_dir)])
        .assert()
        .success();

    let cred_path = creds_dir.join("cred.vc.json");
    jobchain()
        .args([
            "issue",
            "--domain", "acme.example.com",
            "--key-dir", p(&key_dir),
            "--output", p(&cred_path),
        ])
        .write_stdin(sample_experience_json())
        .assert()
        .success();

    // Tamper with the credential
    let mut vc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cred_path).unwrap()).unwrap();
    vc["credentialSubject"]["title"] = serde_json::Value::String("CEO".to_string());
    let tampered_path = creds_dir.join("tampered.vc.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&vc).unwrap()).unwrap();

    let pk_path = key_dir.join("acme.example.com/public.key");

    // Plain verify: should fail
    jobchain()
        .args([
            "verify",
            "--input", p(&tampered_path),
            "--key", p(&pk_path),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("INVALID"));

    // JSON verify: should report valid: false
    let output = jobchain()
        .args([
            "verify",
            "--input", p(&tampered_path),
            "--key", p(&pk_path),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["valid"], false);
}

// ===========================================================================
// Negative path: wrong key rejected
// ===========================================================================

#[test]
fn test_verify_rejects_wrong_key() {
    let (_tmp, key_dir, creds_dir, _wallet_dir) = setup_dirs();

    // Init two different domains → two different keypairs
    jobchain()
        .args(["init", "--org", "A", "--domain", "alpha.example.com", "--key-dir", p(&key_dir)])
        .assert()
        .success();
    jobchain()
        .args(["init", "--org", "B", "--domain", "beta.example.com", "--key-dir", p(&key_dir)])
        .assert()
        .success();

    // Issue with alpha's key
    let cred_path = creds_dir.join("alpha.vc.json");
    jobchain()
        .args([
            "issue",
            "--domain", "alpha.example.com",
            "--key-dir", p(&key_dir),
            "--output", p(&cred_path),
        ])
        .write_stdin(sample_experience_json())
        .assert()
        .success();

    // Verify with beta's public key → should fail
    let wrong_pk = key_dir.join("beta.example.com/public.key");
    jobchain()
        .args([
            "verify",
            "--input", p(&cred_path),
            "--key", p(&wrong_pk),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("INVALID"));
}

// ===========================================================================
// Two-amendment chain with wallet validation
// ===========================================================================

#[test]
fn test_amend_chain_two_amendments() {
    let (_tmp, key_dir, creds_dir, wallet_dir) = setup_dirs();

    // Init
    jobchain()
        .args(["init", "--org", "A", "--domain", "acme.example.com", "--key-dir", p(&key_dir)])
        .assert()
        .success();

    // Issue
    let cred_path = creds_dir.join("base.vc.json");
    jobchain()
        .args([
            "issue",
            "--domain", "acme.example.com",
            "--key-dir", p(&key_dir),
            "--output", p(&cred_path),
        ])
        .write_stdin(sample_experience_json())
        .assert()
        .success();

    let cred: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cred_path).unwrap()).unwrap();

    // Amendment 1: title change
    let amend1_path = creds_dir.join("base-amend-1.amend.json");
    jobchain()
        .args([
            "amend",
            "--credential", p(&cred_path),
            "--domain", "acme.example.com",
            "--effective-date", "2025-01-15",
            "--key-dir", p(&key_dir),
            "--output", p(&amend1_path),
        ])
        .write_stdin(r#"{"title": "Senior Infrastructure Engineer"}"#)
        .assert()
        .success();

    let amend1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&amend1_path).unwrap()).unwrap();

    // Amendment 2: add end date, chaining from amendment 1
    let amend2_path = creds_dir.join("base-amend-2.amend.json");
    jobchain()
        .args([
            "amend",
            "--credential", p(&cred_path),
            "--chain", p(&amend1_path),
            "--domain", "acme.example.com",
            "--effective-date", "2025-06-30",
            "--key-dir", p(&key_dir),
            "--output", p(&amend2_path),
        ])
        .write_stdin(r#"{"end": "2025-06"}"#)
        .assert()
        .success();

    let amend2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&amend2_path).unwrap()).unwrap();

    // Verify both amendment signatures
    let pk_path = key_dir.join("acme.example.com/public.key");
    jobchain()
        .args(["verify", "--input", p(&amend1_path), "--key", p(&pk_path)])
        .assert()
        .success();
    jobchain()
        .args(["verify", "--input", p(&amend2_path), "--key", p(&pk_path)])
        .assert()
        .success();

    // Verify chain links
    let cred_hash = content_hash(&hashable_bytes(&cred));
    assert_eq!(amend1["previousHash"].as_str().unwrap(), cred_hash);

    let amend1_hash = content_hash(&hashable_bytes(&amend1));
    assert_eq!(amend2["previousHash"].as_str().unwrap(), amend1_hash);

    // Both amendments point to same originalCredential (the base)
    assert_eq!(
        amend1["credentialSubject"]["originalCredential"],
        amend2["credentialSubject"]["originalCredential"]
    );

    // Build wallet including the credential and both amendments
    jobchain()
        .args([
            "wallet", "build",
            "--dir", p(&creds_dir),
            "--out", p(&wallet_dir),
            "--no-verify",
        ])
        .assert()
        .success();

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(wallet_dir.join("index.json")).unwrap()).unwrap();
    let creds = manifest["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    let amendments = creds[0]["amendments"].as_array().unwrap();
    assert_eq!(amendments.len(), 2, "expected 2 amendments in wallet manifest");
}

// ===========================================================================
// Stdin piping for issue
// ===========================================================================

#[test]
fn test_issue_from_stdin_pipe() {
    let (_tmp, key_dir, _creds_dir, _wallet_dir) = setup_dirs();

    jobchain()
        .args(["init", "--org", "A", "--domain", "acme.example.com", "--key-dir", p(&key_dir)])
        .assert()
        .success();

    // Issue from stdin, output to stdout
    let output = jobchain()
        .args([
            "issue",
            "--domain", "acme.example.com",
            "--key-dir", p(&key_dir),
        ])
        .write_stdin(sample_experience_json())
        .output()
        .unwrap();

    assert!(output.status.success());
    let vc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(vc["issuer"], "did:web:acme.example.com");
    assert!(vc["proof"].is_object());

    // Verify the credential piped through stdin
    let pk_path = key_dir.join("acme.example.com/public.key");
    jobchain()
        .args(["verify", "--key", p(&pk_path)])
        .write_stdin(String::from_utf8(output.stdout).unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

// ===========================================================================
// Empty wallet dir succeeds
// ===========================================================================

#[test]
fn test_wallet_empty_dir_succeeds() {
    let (_tmp, _key_dir, creds_dir, wallet_dir) = setup_dirs();

    jobchain()
        .args([
            "wallet", "build",
            "--dir", p(&creds_dir),
            "--out", p(&wallet_dir),
            "--no-verify",
        ])
        .assert()
        .success();

    assert!(wallet_dir.join("index.html").exists());
    assert!(wallet_dir.join("index.json").exists());

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(wallet_dir.join("index.json")).unwrap()).unwrap();
    let creds = manifest["credentials"].as_array().unwrap();
    assert!(creds.is_empty());
}

// ===========================================================================
// Force-overwrite guard
// ===========================================================================

#[test]
fn test_wallet_no_force_fails_on_existing_output() {
    let (_tmp, _key_dir, creds_dir, wallet_dir) = setup_dirs();

    // Pre-create non-empty output directory
    std::fs::create_dir_all(&wallet_dir).unwrap();
    std::fs::write(wallet_dir.join("existing.txt"), "not empty").unwrap();

    jobchain()
        .args([
            "wallet", "build",
            "--dir", p(&creds_dir),
            "--out", p(&wallet_dir),
            "--no-verify",
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not empty")
                .and(predicate::str::contains("--force")),
        );
}
