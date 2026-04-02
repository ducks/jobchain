use serde::{Deserialize, Serialize};

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
    /// Strips the proof field, serializes to a `serde_json::Value` (which uses
    /// `BTreeMap` for key ordering), then converts to a byte vector.
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        serde_json::to_vec(&value)
    }
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

        // W3C VC top-level keys
        assert!(obj.contains_key("@context"));
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("issuer"));
        assert!(obj.contains_key("issuanceDate"));
        assert!(obj.contains_key("credentialSubject"));
        // No proof when None
        assert!(!obj.contains_key("proof"));

        // credentialSubject has flattened jobl fields
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
    fn test_credential_subject_flattens_experience() {
        let subject = CredentialSubject {
            r#type: "EmploymentRecord".to_string(),
            experience: sample_experience(),
        };

        let value: serde_json::Value =
            serde_json::to_value(&subject).unwrap();
        let obj = value.as_object().unwrap();

        // jobl fields at top level, not nested
        assert_eq!(obj["title"], "Software Engineer");
        assert_eq!(obj["company"], "Discourse");
        assert_eq!(obj["location"], "Remote");
        assert_eq!(obj["start"], "2022-01-15");
        assert!(obj["technologies"].is_array());
        assert!(obj["highlights"].is_array());
        // No "experience" wrapper key
        assert!(!obj.contains_key("experience"));
    }
}
