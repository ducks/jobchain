use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::signing::{Keypair, SigningError};

/// Errors that can occur during credential operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("signing failed: {0}")]
    Signing(#[from] SigningError),
}

/// Ed25519Signature2020 proof block for a Verifiable Credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    pub created: String,
}

/// Credential subject wrapping a jobl `ExperienceItem`.
///
/// The `ExperienceItem` fields are flattened so they appear as top-level
/// properties in the serialized `credentialSubject` object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSubject {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(flatten)]
    pub experience: jobl::ExperienceItem,
}

/// W3C Verifiable Credential (JSON subset) wrapping a jobl employment record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// Recursively sort all object keys in a `serde_json::Value` using `BTreeMap`.
pub fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
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

impl VerifiableCredential {
    /// Create a new unsigned credential from a jobl `ExperienceItem`.
    pub fn new(
        issuer: String,
        issuance_date: String,
        subject: jobl::ExperienceItem,
    ) -> Self {
        Self {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            r#type: vec![
                "VerifiableCredential".to_string(),
                "EmploymentCredential".to_string(),
            ],
            issuer,
            issuance_date,
            credential_subject: CredentialSubject {
                r#type: "EmploymentRecord".to_string(),
                experience: subject,
            },
            proof: None,
        }
    }

    /// Produce the canonical JSON bytes to be signed.
    ///
    /// Strips the proof field, recursively sorts all object keys, then
    /// serializes to compact JSON (no whitespace).
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        let canonical = canonicalize(&value);
        serde_json::to_vec(&canonical)
    }

    /// Sign this credential, attaching an Ed25519Signature2020 proof block.
    pub fn sign(
        &mut self,
        keypair: &Keypair,
        verification_method: &str,
    ) -> Result<(), CredentialError> {
        let payload = self.signing_payload()?;
        let signature = keypair.sign(&payload);
        let proof_value = format!("z{}", bs58::encode(&signature).into_string());
        let created = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        self.proof = Some(Proof {
            r#type: "Ed25519Signature2020".to_string(),
            verification_method: verification_method.to_string(),
            proof_value,
            created,
        });
        Ok(())
    }
}

/// Create and sign a credential in one step.
pub fn issue_credential(
    issuer_did: &str,
    experience: jobl::ExperienceItem,
    issuance_date: &str,
    keypair: &Keypair,
) -> Result<VerifiableCredential, CredentialError> {
    let mut vc = VerifiableCredential::new(
        issuer_did.to_string(),
        issuance_date.to_string(),
        experience,
    );
    let verification_method = format!("{issuer_did}#key-1");
    vc.sign(keypair, &verification_method)?;
    Ok(vc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_experience() -> jobl::ExperienceItem {
        jobl::ExperienceItem {
            title: "Software Engineer".to_string(),
            company: "Discourse".to_string(),
            location: Some("Remote".to_string()),
            start: Some("2022-01-15".to_string()),
            end: None,
            summary: Some("Infrastructure team".to_string()),
            technologies: vec!["Ruby".to_string(), "JavaScript".to_string()],
            highlights: vec!["Built deployment pipeline".to_string()],
        }
    }

    #[test]
    fn test_new_credential() {
        let vc = VerifiableCredential::new(
            "did:web:discourse.org".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );

        assert_eq!(
            vc.context,
            vec!["https://www.w3.org/2018/credentials/v1"]
        );
        assert_eq!(
            vc.r#type,
            vec!["VerifiableCredential", "EmploymentCredential"]
        );
        assert_eq!(vc.issuer, "did:web:discourse.org");
        assert_eq!(
            vc.credential_subject.r#type,
            "EmploymentRecord"
        );
        assert!(vc.proof.is_none());
    }

    #[test]
    fn test_serialize_roundtrip() {
        let vc = VerifiableCredential::new(
            "did:web:discourse.org".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );

        let json = serde_json::to_string_pretty(&vc).unwrap();
        let deserialized: VerifiableCredential =
            serde_json::from_str(&json).unwrap();
        assert_eq!(vc, deserialized);
    }

    #[test]
    fn test_json_shape() {
        let vc = VerifiableCredential::new(
            "did:web:discourse.org".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );

        let value: serde_json::Value =
            serde_json::to_value(&vc).unwrap();
        let obj = value.as_object().unwrap();

        assert!(obj.contains_key("@context"));
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("issuer"));
        assert!(obj.contains_key("issuanceDate"));
        assert!(obj.contains_key("credentialSubject"));
        assert!(!obj.contains_key("proof"));

        let subject = obj["credentialSubject"].as_object().unwrap();
        assert_eq!(subject["type"], "EmploymentRecord");
        assert_eq!(subject["title"], "Software Engineer");
        assert_eq!(subject["company"], "Discourse");
    }

    #[test]
    fn test_credential_with_proof() {
        let mut vc = VerifiableCredential::new(
            "did:web:discourse.org".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );

        vc.proof = Some(Proof {
            r#type: "Ed25519Signature2020".to_string(),
            verification_method: "did:web:discourse.org#key-1".to_string(),
            proof_value: "z3hQm...".to_string(),
            created: "2025-06-01T00:00:00Z".to_string(),
        });

        let value: serde_json::Value =
            serde_json::to_value(&vc).unwrap();
        let proof = value["proof"].as_object().unwrap();

        assert_eq!(proof["type"], "Ed25519Signature2020");
        assert_eq!(
            proof["verificationMethod"],
            "did:web:discourse.org#key-1"
        );
        assert!(proof.contains_key("proofValue"));
        assert!(proof.contains_key("created"));
    }

    #[test]
    fn test_signing_payload_excludes_proof() {
        let mut vc = VerifiableCredential::new(
            "did:web:discourse.org".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );

        vc.proof = Some(Proof {
            r#type: "Ed25519Signature2020".to_string(),
            verification_method: "did:web:discourse.org#key-1".to_string(),
            proof_value: "z3hQm...".to_string(),
            created: "2025-06-01T00:00:00Z".to_string(),
        });

        let payload = vc.signing_payload().unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&payload).unwrap();

        assert!(!value.as_object().unwrap().contains_key("proof"));
    }

    #[test]
    fn test_canonicalize_sorts_keys() {
        let vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        let value = serde_json::to_value(&vc).unwrap();
        let canonical = canonicalize(&value);
        let obj = canonical.as_object().unwrap();
        let keys: Vec<&String> = obj.keys().collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys);
    }

    #[test]
    fn test_canonicalize_no_whitespace() {
        let vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        let value = serde_json::to_value(&vc).unwrap();
        let canonical = canonicalize(&value);
        let json = serde_json::to_vec(&canonical).unwrap();
        let json_str = String::from_utf8(json).unwrap();
        assert!(!json_str.contains('\n'));
    }

    #[test]
    fn test_canonicalize_determinism() {
        let vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        let value = serde_json::to_value(&vc).unwrap();
        let c1 = serde_json::to_vec(&canonicalize(&value)).unwrap();
        let c2 = serde_json::to_vec(&canonicalize(&value)).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_sign_attaches_proof() {
        let kp = Keypair::generate().unwrap();
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.sign(&kp, "did:web:example.com#key-1").unwrap();

        let proof = vc.proof.as_ref().unwrap();
        assert_eq!(proof.r#type, "Ed25519Signature2020");
        assert_eq!(proof.verification_method, "did:web:example.com#key-1");
    }

    #[test]
    fn test_proof_multibase_encoding() {
        let kp = Keypair::generate().unwrap();
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.sign(&kp, "did:web:example.com#key-1").unwrap();

        let proof = vc.proof.as_ref().unwrap();
        assert!(proof.proof_value.starts_with('z'));
        let decoded = bs58::decode(&proof.proof_value[1..]).into_vec().unwrap();
        assert_eq!(decoded.len(), 64);
    }

    #[test]
    fn test_proof_timestamp_is_iso8601() {
        let kp = Keypair::generate().unwrap();
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.sign(&kp, "did:web:example.com#key-1").unwrap();

        let proof = vc.proof.as_ref().unwrap();
        assert!(proof.created.ends_with('Z'));
        assert!(proof.created.contains('T'));
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.sign(&kp, "did:web:example.com#key-1").unwrap();

        let payload = vc.signing_payload().unwrap();
        let proof = vc.proof.as_ref().unwrap();
        let sig = bs58::decode(&proof.proof_value[1..]).into_vec().unwrap();
        kp.verify(&payload, &sig).unwrap();
    }

    #[test]
    fn test_issue_credential_convenience() {
        let kp = Keypair::generate().unwrap();
        let vc = issue_credential(
            "did:web:discourse.org",
            sample_experience(),
            "2025-06-01T00:00:00Z",
            &kp,
        )
        .unwrap();

        assert_eq!(vc.issuer, "did:web:discourse.org");
        assert_eq!(vc.issuance_date, "2025-06-01T00:00:00Z");
        assert_eq!(vc.credential_subject.r#type, "EmploymentRecord");

        let proof = vc.proof.as_ref().unwrap();
        assert_eq!(proof.r#type, "Ed25519Signature2020");
        assert_eq!(
            proof.verification_method,
            "did:web:discourse.org#key-1"
        );
        assert!(proof.proof_value.starts_with('z'));
    }

    #[test]
    fn test_tamper_detection() {
        let kp = Keypair::generate().unwrap();
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.sign(&kp, "did:web:example.com#key-1").unwrap();

        vc.credential_subject.experience.title = "CEO".to_string();

        let payload = vc.signing_payload().unwrap();
        let proof = vc.proof.as_ref().unwrap();
        let sig = bs58::decode(&proof.proof_value[1..]).into_vec().unwrap();
        assert!(kp.verify(&payload, &sig).is_err());
    }

    #[test]
    fn test_credential_subject_flattens_experience() {
        let subject = CredentialSubject {
            r#type: "EmploymentRecord".to_string(),
            experience: sample_experience(),
        };

        let value: serde_json::Value =
            serde_json::to_value(&subject).unwrap();
        let obj = value.as_object().unwrap();

        assert_eq!(obj["title"], "Software Engineer");
        assert_eq!(obj["company"], "Discourse");
        assert_eq!(obj["location"], "Remote");
        assert_eq!(obj["start"], "2022-01-15");
        assert!(obj["technologies"].is_array());
        assert!(obj["highlights"].is_array());
        assert!(!obj.contains_key("experience"));
    }
}
