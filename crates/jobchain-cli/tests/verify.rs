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

/// Issue a credential and return its JSON as a string.
fn issue_credential(tmp: &TempDir, domain: &str) -> String {
    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = cmd()
        .args([
            "issue",
            "--domain",
            domain,
            "--input",
            input_file.to_str().unwrap(),
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn key_path(tmp: &TempDir, domain: &str) -> String {
    tmp.path()
        .join(domain)
        .join("public.key")
        .to_str()
        .unwrap()
        .to_string()
}

// --- Tests ---

#[test]
fn test_verify_valid_credential() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    let cred_json = issue_credential(&tmp, "example.com");

    let cred_file = tmp.path().join("credential.json");
    std::fs::write(&cred_file, &cred_json).unwrap();

    cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "example.com"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn test_verify_invalid_signature() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    let cred_json = issue_credential(&tmp, "example.com");

    // Tamper with the credential subject
    let mut vc: serde_json::Value = serde_json::from_str(&cred_json).unwrap();
    vc["credentialSubject"]["title"] = serde_json::Value::String("CEO".to_string());
    let tampered = serde_json::to_string_pretty(&vc).unwrap();

    let cred_file = tmp.path().join("tampered.json");
    std::fs::write(&cred_file, &tampered).unwrap();

    cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "example.com"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("INVALID"));
}

#[test]
fn test_verify_wrong_key() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    init_keypair(&tmp, "other.com");
    let cred_json = issue_credential(&tmp, "example.com");

    let cred_file = tmp.path().join("credential.json");
    std::fs::write(&cred_file, &cred_json).unwrap();

    cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "other.com"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("INVALID"));
}

#[test]
fn test_verify_missing_proof() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    // Create a credential with no proof
    let unsigned = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "EmploymentCredential"],
        "issuer": "did:web:example.com",
        "issuanceDate": "2024-06-01",
        "credentialSubject": {
            "type": "EmploymentRecord",
            "title": "Engineer",
            "company": "TestCorp",
            "start": "2024-01",
            "technologies": [],
            "highlights": []
        }
    });

    let cred_file = tmp.path().join("unsigned.json");
    std::fs::write(&cred_file, serde_json::to_string_pretty(&unsigned).unwrap()).unwrap();

    cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "example.com"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no proof"));
}

#[test]
fn test_verify_from_stdin() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    let cred_json = issue_credential(&tmp, "example.com");

    cmd()
        .args(["verify", "--key", &key_path(&tmp, "example.com")])
        .write_stdin(cred_json)
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn test_verify_json_output_valid() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    let cred_json = issue_credential(&tmp, "example.com");

    let cred_file = tmp.path().join("credential.json");
    std::fs::write(&cred_file, &cred_json).unwrap();

    let output = cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "example.com"),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["valid"], true);
    assert_eq!(result["issuer"], "did:web:example.com");
    assert!(result["subject"]["title"].is_string());
    assert!(result["subject"]["company"].is_string());
    assert!(result["issuanceDate"].is_string());
    assert!(result["error"].is_null());
}

#[test]
fn test_verify_json_output_invalid() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    let cred_json = issue_credential(&tmp, "example.com");

    // Tamper
    let mut vc: serde_json::Value = serde_json::from_str(&cred_json).unwrap();
    vc["credentialSubject"]["title"] = serde_json::Value::String("CEO".to_string());
    let tampered = serde_json::to_string_pretty(&vc).unwrap();

    let cred_file = tmp.path().join("tampered.json");
    std::fs::write(&cred_file, &tampered).unwrap();

    let output = cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "example.com"),
            "--json",
        ])
        .output()
        .unwrap();

    // Exit code 1
    assert!(!output.status.success());

    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["valid"], false);
    assert!(result["error"].is_string());
}

#[test]
fn test_verify_offline_without_key() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    let cred_json = issue_credential(&tmp, "example.com");

    let cred_file = tmp.path().join("credential.json");
    std::fs::write(&cred_file, &cred_json).unwrap();

    cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--offline",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--offline requires --key"));
}

#[test]
fn test_verify_nonexistent_input() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    cmd()
        .args([
            "verify",
            "--input",
            "/tmp/does-not-exist-jobchain-test.json",
            "--key",
            &key_path(&tmp, "example.com"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read input file"));
}

#[test]
fn test_verify_roundtrip_init_issue_verify() {
    let tmp = TempDir::new().unwrap();

    // Init
    init_keypair(&tmp, "roundtrip.org");

    // Issue
    let cred_json = issue_credential(&tmp, "roundtrip.org");

    // Verify
    let cred_file = tmp.path().join("rt_credential.json");
    std::fs::write(&cred_file, &cred_json).unwrap();

    cmd()
        .args([
            "verify",
            "--input",
            cred_file.to_str().unwrap(),
            "--key",
            &key_path(&tmp, "roundtrip.org"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"))
        .stdout(predicate::str::contains("roundtrip.org"));
}
