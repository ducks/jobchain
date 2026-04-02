use serde::{Deserialize, Serialize};

/// Errors that can occur during DID operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DidError {
    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// A DID document verification method (public key entry).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// A W3C DID document for did:web.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
}

/// Convert a domain (with optional port and path) to a did:web URI.
///
/// Ports are percent-encoded as `%3A`, path separators become colons.
///
/// # Examples
///
/// ```
/// use jobchain_core::did::domain_to_did;
/// assert_eq!(domain_to_did("example.com"), "did:web:example.com");
/// assert_eq!(domain_to_did("example.com:3000"), "did:web:example.com%3A3000");
/// assert_eq!(domain_to_did("example.com/path/to"), "did:web:example.com:path:to");
/// ```
pub fn domain_to_did(domain: &str) -> String {
    // Split off path first
    let (host_port, path) = match domain.split_once('/') {
        Some((hp, p)) => (hp, Some(p)),
        None => (domain, None),
    };

    // Encode port colon as %3A
    let encoded_host = host_port.replacen(':', "%3A", 1);

    match path {
        Some(p) => {
            let encoded_path = p.replace('/', ":");
            format!("did:web:{encoded_host}:{encoded_path}")
        }
        None => format!("did:web:{encoded_host}"),
    }
}

/// Generate a complete DID document for a domain and Ed25519 public key.
///
/// The public key is encoded with the multicodec Ed25519 header (`0xed 0x01`)
/// and base58btc multibase prefix (`z`).
pub fn generate_did_document(domain: &str, public_key: &[u8; 32]) -> DidDocument {
    let did = domain_to_did(domain);
    let key_id = format!("{did}#key-1");

    // Multicodec Ed25519 public key: 0xed 0x01 prefix + 32-byte key
    let mut buf = Vec::with_capacity(34);
    buf.push(0xed);
    buf.push(0x01);
    buf.extend_from_slice(public_key);
    let multibase = format!("z{}", bs58::encode(&buf).into_string());

    DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/multikey/v1".to_string(),
        ],
        id: did.clone(),
        verification_method: vec![VerificationMethod {
            id: key_id.clone(),
            r#type: "Multikey".to_string(),
            controller: did,
            public_key_multibase: multibase,
        }],
        authentication: vec![key_id.clone()],
        assertion_method: vec![key_id],
    }
}

/// Serialize a DID document to pretty-printed JSON for `.well-known/did.json`.
pub fn did_document_to_json(doc: &DidDocument) -> Result<String, DidError> {
    Ok(serde_json::to_string_pretty(doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_simple() {
        assert_eq!(domain_to_did("example.com"), "did:web:example.com");
    }

    #[test]
    fn test_domain_with_port() {
        assert_eq!(
            domain_to_did("example.com:3000"),
            "did:web:example.com%3A3000"
        );
    }

    #[test]
    fn test_domain_with_path() {
        assert_eq!(
            domain_to_did("example.com/path/to"),
            "did:web:example.com:path:to"
        );
    }

    #[test]
    fn test_domain_with_port_and_path() {
        assert_eq!(
            domain_to_did("example.com:8080/user/alice"),
            "did:web:example.com%3A8080:user:alice"
        );
    }

    #[test]
    fn test_generate_document_structure() {
        let pk = [0u8; 32];
        let doc = generate_did_document("example.com", &pk);

        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(doc.context.len(), 2);
        assert_eq!(doc.verification_method.len(), 1);

        let vm = &doc.verification_method[0];
        assert_eq!(vm.id, "did:web:example.com#key-1");
        assert_eq!(vm.r#type, "Multikey");
        assert_eq!(vm.controller, "did:web:example.com");

        assert_eq!(doc.authentication, vec!["did:web:example.com#key-1"]);
        assert_eq!(doc.assertion_method, vec!["did:web:example.com#key-1"]);
    }

    #[test]
    fn test_multibase_encoding() {
        let pk = [42u8; 32];
        let doc = generate_did_document("example.com", &pk);
        let mb = &doc.verification_method[0].public_key_multibase;

        assert!(mb.starts_with('z'));

        let decoded = bs58::decode(&mb[1..]).into_vec().unwrap();
        assert_eq!(decoded.len(), 34);
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], &[42u8; 32]);
    }

    #[test]
    fn test_json_roundtrip() {
        let pk = [7u8; 32];
        let doc = generate_did_document("example.com", &pk);
        let json = did_document_to_json(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, parsed);
    }

    #[test]
    fn test_json_field_names() {
        let pk = [0u8; 32];
        let doc = generate_did_document("example.com", &pk);
        let json = did_document_to_json(&doc).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = value.as_object().unwrap();

        assert!(obj.contains_key("@context"));
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("verificationMethod"));
        assert!(obj.contains_key("authentication"));
        assert!(obj.contains_key("assertionMethod"));

        let vm = obj["verificationMethod"][0].as_object().unwrap();
        assert!(vm.contains_key("publicKeyMultibase"));
        assert!(vm.contains_key("type"));
        assert!(vm.contains_key("controller"));
    }
}
