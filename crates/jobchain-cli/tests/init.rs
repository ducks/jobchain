use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn jobchain() -> Command {
    Command::cargo_bin("jobchain").unwrap()
}

#[test]
fn init_creates_files() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("identity");

    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success()
        .stdout(predicate::str::contains("Identity initialized"));

    assert!(dir.join("secret.key").exists());
    assert!(dir.join("public.key").exists());
    assert!(dir.join("did.json").exists());
}

#[test]
fn init_did_json_contains_domain() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("identity");

    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success();

    let did_json = std::fs::read_to_string(dir.join("did.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&did_json).unwrap();

    assert_eq!(doc["id"], "did:web:example.com");
    assert_eq!(doc["verificationMethod"][0]["type"], "Multikey");
}

#[test]
fn init_refuses_overwrite_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("identity");

    // First init succeeds
    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success();

    // Second init without --force fails
    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn init_force_overwrites() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("identity");

    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success();

    jobchain()
        .args([
            "init",
            "--domain",
            "other.com",
            "--output-dir",
        ])
        .arg(dir.as_os_str())
        .arg("--force")
        .assert()
        .success();

    let did_json = std::fs::read_to_string(dir.join("did.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&did_json).unwrap();
    assert_eq!(doc["id"], "did:web:other.com");
}

#[test]
fn init_secret_key_is_32_bytes() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("identity");

    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success();

    let key_bytes = std::fs::read(dir.join("secret.key")).unwrap();
    assert_eq!(key_bytes.len(), 32);

    let pub_bytes = std::fs::read(dir.join("public.key")).unwrap();
    assert_eq!(pub_bytes.len(), 32);
}

#[test]
fn init_prints_did_and_multibase_key() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("identity");

    jobchain()
        .args(["init", "--domain", "example.com", "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success()
        .stdout(predicate::str::contains("DID: did:web:example.com"))
        .stdout(predicate::str::contains("Public key (multibase): z"));
}
