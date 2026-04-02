use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("jobchain").unwrap()
}

fn sample_experience_json() -> &'static str {
    r#"{
  "title": "Infrastructure Engineer",
  "company": "Discourse",
  "start": "2024-03",
  "technologies": ["Ruby", "JavaScript", "Docker"],
  "highlights": ["Led migration to containerized deployment"]
}"#
}

fn sample_experience_json_2() -> &'static str {
    r#"{
  "title": "Backend Developer",
  "company": "Acme Corp",
  "start": "2022-06",
  "end": "2024-02",
  "technologies": ["Go", "PostgreSQL"],
  "highlights": ["Built API gateway"]
}"#
}

fn init_keypair(tmp: &TempDir, domain: &str) {
    cmd()
        .args([
            "init",
            "--org",
            "TestCorp",
            "--domain",
            domain,
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

fn issue_credential(tmp: &TempDir, domain: &str, experience: &str) -> String {
    let output = cmd()
        .args([
            "issue",
            "--domain",
            domain,
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(experience)
        .output()
        .unwrap();
    assert!(output.status.success(), "issue failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

fn amend_credential(tmp: &TempDir, domain: &str, cred_path: &std::path::Path, patch: &str) -> String {
    let output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            domain,
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(patch)
        .output()
        .unwrap();
    assert!(output.status.success(), "amend failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// Set up a credential directory with the given number of credentials.
fn setup_cred_dir(tmp: &TempDir, domain: &str) -> std::path::PathBuf {
    init_keypair(tmp, domain);

    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let cred1 = issue_credential(tmp, domain, sample_experience_json());
    std::fs::write(cred_dir.join("discourse-2024.vc.json"), &cred1).unwrap();

    let cred2 = issue_credential(tmp, domain, sample_experience_json_2());
    std::fs::write(cred_dir.join("acme-2022.vc.json"), &cred2).unwrap();

    cred_dir
}

// --- Tests ---

#[test]
fn test_wallet_build_basic() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = setup_cred_dir(&tmp, "example.com");
    let out_dir = tmp.path().join("site");

    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--title",
            "Test Wallet",
            "--no-verify",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Found 2 credentials"));

    assert!(out_dir.join("index.html").exists());
    assert!(out_dir.join("index.json").exists());
    // At least two .html credential pages
    let html_files: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".html") && name != "index.html"
        })
        .collect();
    assert_eq!(html_files.len(), 2);
    // .vc.json files are copied
    let vc_files: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".vc.json"))
        .collect();
    assert_eq!(vc_files.len(), 2);
}

#[test]
fn test_wallet_build_with_amendments() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let cred = issue_credential(&tmp, "example.com", sample_experience_json());
    let cred_path = cred_dir.join("discourse-2024.vc.json");
    std::fs::write(&cred_path, &cred).unwrap();

    // Create an amendment
    let amendment = amend_credential(
        &tmp,
        "example.com",
        &cred_path,
        r#"{"title": "Senior Infrastructure Engineer"}"#,
    );
    std::fs::write(cred_dir.join("discourse-2024-amend1.amend.json"), &amendment).unwrap();

    let out_dir = tmp.path().join("site");
    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--no-verify",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 amendments"));

    // Check the credential page contains amendment info
    let pages: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".html") && name != "index.html"
        })
        .collect();
    assert_eq!(pages.len(), 1);
    let page_content = std::fs::read_to_string(pages[0].path()).unwrap();
    assert!(page_content.contains("Amendment History"));
    assert!(page_content.contains("Senior Infrastructure Engineer"));

    // Check index.json includes amendment
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("index.json")).unwrap()).unwrap();
    let creds = manifest["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert!(creds[0]["amendments"].is_array());
    assert_eq!(creds[0]["amendments"].as_array().unwrap().len(), 1);
}

#[test]
fn test_wallet_build_with_resume() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let cred = issue_credential(&tmp, "example.com", sample_experience_json());
    std::fs::write(cred_dir.join("test.vc.json"), &cred).unwrap();

    // Create a resume.jobl
    std::fs::write(cred_dir.join("resume.jobl"), "name: Test User\n").unwrap();

    let out_dir = tmp.path().join("site");
    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--no-verify",
        ])
        .assert()
        .success();

    assert!(out_dir.join("resume.jobl").exists());

    let index_html = std::fs::read_to_string(out_dir.join("index.html")).unwrap();
    assert!(index_html.contains("resume.jobl"));

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("index.json")).unwrap()).unwrap();
    assert!(manifest["resume"].is_string());
}

#[test]
fn test_wallet_build_empty_dir() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = tmp.path().join("empty");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let out_dir = tmp.path().join("site");
    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--no-verify",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Found 0 credentials"));

    assert!(out_dir.join("index.html").exists());
    assert!(out_dir.join("index.json").exists());
}

#[test]
fn test_wallet_build_output_exists_no_force() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let out_dir = tmp.path().join("site");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("existing.txt"), "not empty").unwrap();

    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--no-verify",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not empty").and(predicate::str::contains("--force")));
}

#[test]
fn test_wallet_build_output_exists_force() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let out_dir = tmp.path().join("site");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("existing.txt"), "not empty").unwrap();

    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--force",
            "--no-verify",
        ])
        .assert()
        .success();

    assert!(out_dir.join("index.html").exists());
    // Old file should be gone
    assert!(!out_dir.join("existing.txt").exists());
}

#[test]
fn test_wallet_index_json_structure() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = setup_cred_dir(&tmp, "example.com");
    let out_dir = tmp.path().join("site");

    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--title",
            "Test Wallet",
            "--no-verify",
        ])
        .assert()
        .success();

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("index.json")).unwrap()).unwrap();

    assert!(manifest["@context"].is_array());
    assert_eq!(manifest["type"], "CredentialWallet");
    assert_eq!(manifest["holder"], "Test Wallet");
    assert!(manifest["generatedAt"].is_string());

    let creds = manifest["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 2);

    for cred in creds {
        assert!(cred["id"].is_string());
        assert!(cred["issuer"].is_string());
        assert!(cred["issuanceDate"].is_string());
        assert!(cred["credentialSubject"]["title"].is_string());
        assert!(cred["credentialSubject"]["company"].is_string());
        assert!(cred["credentialUrl"].is_string());
        assert!(cred["pageUrl"].is_string());
    }
}

#[test]
fn test_wallet_index_json_base_url() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = setup_cred_dir(&tmp, "example.com");
    let out_dir = tmp.path().join("site");

    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--base-url",
            "https://jake.dev/creds",
            "--no-verify",
        ])
        .assert()
        .success();

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("index.json")).unwrap()).unwrap();

    let creds = manifest["credentials"].as_array().unwrap();
    for cred in creds {
        let url = cred["credentialUrl"].as_str().unwrap();
        assert!(
            url.starts_with("https://jake.dev/creds/"),
            "expected absolute URL, got: {url}"
        );
        let page_url = cred["pageUrl"].as_str().unwrap();
        assert!(
            page_url.starts_with("https://jake.dev/creds/"),
            "expected absolute URL, got: {page_url}"
        );
    }

    // Resume URL should also be absolute if resume exists
    let resume = &manifest["resume"];
    assert!(resume.is_null()); // no resume in this test
}

#[test]
fn test_wallet_html_contains_credential_data() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let cred = issue_credential(&tmp, "example.com", sample_experience_json());
    std::fs::write(cred_dir.join("test.vc.json"), &cred).unwrap();

    let out_dir = tmp.path().join("site");
    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--no-verify",
        ])
        .assert()
        .success();

    // Find the credential page
    let pages: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".html") && name != "index.html"
        })
        .collect();
    assert_eq!(pages.len(), 1);

    let html = std::fs::read_to_string(pages[0].path()).unwrap();
    assert!(html.contains("Infrastructure Engineer"));
    assert!(html.contains("Discourse"));
    assert!(html.contains("did:web:example.com"));
    assert!(html.contains(r#"<script type="application/json"#));
}

#[test]
fn test_wallet_no_wasm_warning() {
    let tmp = TempDir::new().unwrap();
    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    let out_dir = tmp.path().join("site");
    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--no-verify",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("WASM verification module not found"));

    let index_html = std::fs::read_to_string(out_dir.join("index.html")).unwrap();
    assert!(!index_html.contains("Verify Signature"));
    assert!(!index_html.contains("Verify All"));
}

#[test]
fn test_wallet_build_roundtrip() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "roundtrip.org");

    let cred_dir = tmp.path().join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();

    // Issue two credentials
    let cred1 = issue_credential(&tmp, "roundtrip.org", sample_experience_json());
    let cred1_path = cred_dir.join("discourse-2024.vc.json");
    std::fs::write(&cred1_path, &cred1).unwrap();

    let cred2 = issue_credential(&tmp, "roundtrip.org", sample_experience_json_2());
    std::fs::write(cred_dir.join("acme-2022.vc.json"), &cred2).unwrap();

    // Amend first credential
    let amendment = amend_credential(
        &tmp,
        "roundtrip.org",
        &cred1_path,
        r#"{"title": "Senior Infrastructure Engineer"}"#,
    );
    std::fs::write(cred_dir.join("discourse-amend.amend.json"), &amendment).unwrap();

    // Build wallet
    let out_dir = tmp.path().join("site");
    cmd()
        .args([
            "wallet",
            "build",
            "--dir",
            cred_dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
            "--title",
            "Roundtrip Test",
            "--no-verify",
        ])
        .assert()
        .success();

    // Verify index.json
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("index.json")).unwrap()).unwrap();

    assert_eq!(manifest["holder"], "Roundtrip Test");
    let creds = manifest["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 2);

    // One credential should have an amendment
    let amended: Vec<_> = creds
        .iter()
        .filter(|c| c.get("amendments").is_some())
        .collect();
    assert_eq!(amended.len(), 1);
    assert_eq!(amended[0]["amendments"].as_array().unwrap().len(), 1);

    // Verify HTML files exist
    assert!(out_dir.join("index.html").exists());
    let html_pages: Vec<_> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".html") && name != "index.html"
        })
        .collect();
    assert_eq!(html_pages.len(), 2);
}
