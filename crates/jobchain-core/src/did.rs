//! DID document generation for did:web method.

use serde::{Deserialize, Serialize};

/// Errors that can occur during DID document operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DidError {
    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid DID URI: {0}")]
    InvalidDidUri(String),

    #[error("resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("invalid document: {0}")]
    InvalidDocument(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("multibase decode error: {0}")]
    MultibaseDecodeError(String),
}

/// A W3C DID document for the did:web method.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
}

/// An Ed25519VerificationKey2020 verification method.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Convert a domain (with optional port and path) to a did:web URI.
pub fn domain_to_did(domain: &str) -> Result<String, DidError> {
    if domain.is_empty() {
        return Err(DidError::InvalidDomain("domain is empty".into()));
    }
    if domain.contains(char::is_whitespace) {
        return Err(DidError::InvalidDomain(
            "domain contains whitespace".into(),
        ));
    }
    if domain.contains('#') || domain.contains('?') {
        return Err(DidError::InvalidDomain(
            "domain contains fragment or query".into(),
        ));
    }

    // Split path from host+port
    let (host_port, path) = match domain.find('/') {
        Some(i) => (&domain[..i], Some(&domain[i + 1..])),
        None => (domain, None),
    };

    // Encode colons in port as %3A
    let encoded_host = host_port.replace(':', "%3A");

    let mut did = format!("did:web:{encoded_host}");

    // Convert path segments to colon-separated
    if let Some(path) = path {
        for segment in path.split('/') {
            if !segment.is_empty() {
                did.push(':');
                did.push_str(segment);
            }
        }
    }

    Ok(did)
}

/// Encode a raw Ed25519 public key as a multibase base58btc string.
fn encode_public_key_multibase(public_key: &[u8; 32]) -> String {
    // Multicodec ed25519-pub header: 0xed 0x01
    let mut buf = Vec::with_capacity(34);
    buf.push(0xed);
    buf.push(0x01);
    buf.extend_from_slice(public_key);
    // 'z' prefix = base58btc in multibase
    format!("z{}", bs58::encode(&buf).into_string())
}

/// Generate a DID document for a given domain and Ed25519 public key.
pub fn generate_did_document(
    domain: &str,
    public_key: &[u8; 32],
) -> Result<DidDocument, DidError> {
    let did = domain_to_did(domain)?;
    let key_id = format!("{did}#key-1");
    let multibase = encode_public_key_multibase(public_key);

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/suites/ed25519-2020/v1".into(),
        ],
        id: did.clone(),
        authentication: vec![key_id.clone()],
        assertion_method: vec![key_id.clone()],
        verification_method: vec![VerificationMethod {
            id: key_id,
            type_: "Ed25519VerificationKey2020".into(),
            controller: did,
            public_key_multibase: multibase,
        }],
    })
}

/// Serialize a DID document to pretty-printed JSON.
pub fn did_document_to_json(doc: &DidDocument) -> Result<String, DidError> {
    Ok(serde_json::to_string_pretty(doc)?)
}

/// Parse a did:web URI into the HTTPS URL where the DID document can be fetched.
///
/// Reverses the `domain_to_did()` encoding per the did:web method spec:
/// - `did:web:discourse.org` → `https://discourse.org/.well-known/did.json`
/// - `did:web:example.com:org:dept` → `https://example.com/org/dept/did.json`
/// - `did:web:localhost%3A8080` → `https://localhost:8080/.well-known/did.json`
pub fn parse_did_web_uri(did: &str) -> Result<String, DidError> {
    let method_specific_id = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidError::InvalidDidUri(format!("not a did:web URI: {did}")))?;

    if method_specific_id.is_empty() {
        return Err(DidError::InvalidDidUri("empty method-specific identifier".into()));
    }

    // Split into domain (first segment) and optional path segments
    let parts: Vec<&str> = method_specific_id.split(':').collect();

    // First part is the domain; percent-decode %3A back to colons (port)
    let domain = parts[0].replace("%3A", ":");

    if parts.len() == 1 {
        // No path components → well-known location
        Ok(format!("https://{domain}/.well-known/did.json"))
    } else {
        // Path components after the domain
        let path = parts[1..].join("/");
        Ok(format!("https://{domain}/{path}/did.json"))
    }
}

/// Decode a multibase base58btc Ed25519 public key into raw 32 bytes.
///
/// Expects the `publicKeyMultibase` format: `z` prefix (base58btc) followed by
/// a 34-byte payload (2-byte multicodec ed25519-pub header `0xed 0x01` + 32-byte key).
pub fn decode_multibase_ed25519_pubkey(multibase: &str) -> Result<[u8; 32], DidError> {
    if !multibase.starts_with('z') {
        return Err(DidError::MultibaseDecodeError(
            "missing 'z' multibase prefix".into(),
        ));
    }
    let decoded = bs58::decode(&multibase[1..])
        .into_vec()
        .map_err(|e| DidError::MultibaseDecodeError(e.to_string()))?;
    if decoded.len() != 34 {
        return Err(DidError::MultibaseDecodeError(format!(
            "expected 34 bytes (2-byte header + 32-byte key), got {} bytes",
            decoded.len()
        )));
    }
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(DidError::MultibaseDecodeError(format!(
            "expected multicodec ed25519-pub header [0xed, 0x01], got [{:#04x}, {:#04x}]",
            decoded[0], decoded[1]
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..34]);
    Ok(key)
}

/// Extract the first Ed25519 verification key from a DID document.
pub fn extract_verification_key(doc: &DidDocument) -> Result<[u8; 32], DidError> {
    let method = doc
        .verification_method
        .iter()
        .find(|vm| vm.type_ == "Ed25519VerificationKey2020")
        .ok_or_else(|| {
            DidError::KeyNotFound("no Ed25519VerificationKey2020 in document".into())
        })?;

    decode_multibase_ed25519_pubkey(&method.public_key_multibase)
}

/// Extract a verification key by its `id` from a DID document.
pub fn extract_verification_key_by_id(
    doc: &DidDocument,
    key_id: &str,
) -> Result<[u8; 32], DidError> {
    let method = doc
        .verification_method
        .iter()
        .find(|vm| vm.id == key_id)
        .ok_or_else(|| DidError::KeyNotFound(format!("no key with id {key_id}")))?;

    decode_multibase_ed25519_pubkey(&method.public_key_multibase)
}

/// Fetch and validate a DID document from the web.
#[cfg(feature = "resolve")]
pub async fn resolve_did_web(did: &str) -> Result<DidDocument, DidError> {
    let url = parse_did_web_uri(did)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(format!("jobchain/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| DidError::ResolutionFailed(e.to_string()))?;

    let response = client
        .get(&url)
        .header("Accept", "application/did+ld+json, application/json")
        .send()
        .await
        .map_err(|e| DidError::ResolutionFailed(format!("{url}: {e}")))?;

    if !response.status().is_success() {
        return Err(DidError::ResolutionFailed(format!(
            "{url}: HTTP {}",
            response.status()
        )));
    }

    let doc: DidDocument = response
        .json()
        .await
        .map_err(|e| DidError::InvalidDocument(e.to_string()))?;

    if doc.id != did {
        return Err(DidError::InvalidDocument(format!(
            "document id '{}' does not match requested DID '{did}'",
            doc.id
        )));
    }
    if doc.verification_method.is_empty() {
        return Err(DidError::InvalidDocument(
            "document has no verification methods".into(),
        ));
    }

    Ok(doc)
}

/// Resolve a did:web URI and extract the first Ed25519 public key.
#[cfg(feature = "resolve")]
pub async fn resolve_and_extract_key(did: &str) -> Result<[u8; 32], DidError> {
    let doc = resolve_did_web(did).await?;
    extract_verification_key(&doc)
}

/// Synchronous wrapper around `resolve_did_web` for non-async callers.
#[cfg(feature = "resolve")]
pub fn resolve_did_web_blocking(did: &str) -> Result<DidDocument, DidError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DidError::ResolutionFailed(format!("failed to create runtime: {e}")))?;
    rt.block_on(resolve_did_web(did))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_did_simple() {
        assert_eq!(
            domain_to_did("discourse.org").unwrap(),
            "did:web:discourse.org"
        );
    }

    #[test]
    fn test_domain_to_did_with_port() {
        assert_eq!(
            domain_to_did("localhost:8080").unwrap(),
            "did:web:localhost%3A8080"
        );
    }

    #[test]
    fn test_domain_to_did_with_path() {
        assert_eq!(
            domain_to_did("example.com/org/dept").unwrap(),
            "did:web:example.com:org:dept"
        );
    }

    #[test]
    fn test_domain_to_did_empty() {
        assert!(matches!(
            domain_to_did(""),
            Err(DidError::InvalidDomain(_))
        ));
    }

    #[test]
    fn test_generate_did_document() {
        let key = [42u8; 32];
        let doc = generate_did_document("discourse.org", &key).unwrap();

        assert_eq!(doc.id, "did:web:discourse.org");
        assert_eq!(doc.verification_method.len(), 1);

        let vm = &doc.verification_method[0];
        assert_eq!(vm.id, "did:web:discourse.org#key-1");
        assert_eq!(vm.type_, "Ed25519VerificationKey2020");
        assert_eq!(vm.controller, "did:web:discourse.org");
        assert!(vm.public_key_multibase.starts_with('z'));

        assert_eq!(doc.authentication, vec!["did:web:discourse.org#key-1"]);
        assert_eq!(doc.assertion_method, vec!["did:web:discourse.org#key-1"]);
    }

    #[test]
    fn test_did_document_json_roundtrip() {
        let key = [7u8; 32];
        let doc = generate_did_document("example.com", &key).unwrap();
        let json = did_document_to_json(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, parsed);
    }

    #[test]
    fn test_did_document_json_structure() {
        let key = [0u8; 32];
        let doc = generate_did_document("example.com", &key).unwrap();
        let json = did_document_to_json(&doc).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(value["@context"].is_array());
        let ctx = value["@context"].as_array().unwrap();
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(ctx[1], "https://w3id.org/security/suites/ed25519-2020/v1");

        assert!(value["verificationMethod"].is_array());
        assert!(value["assertionMethod"].is_array());
        assert!(value["authentication"].is_array());

        // Verify camelCase field names (not snake_case)
        assert!(value.get("assertion_method").is_none());
        assert!(value.get("verification_method").is_none());
        assert!(value.get("public_key_multibase").is_none());
    }

    #[test]
    fn test_multibase_key_encoding() {
        let key = [0u8; 32];
        let encoded = encode_public_key_multibase(&key);
        assert!(encoded.starts_with('z'));
        assert!(encoded.len() > 40);
    }

    // --- did:web resolution tests ---

    #[test]
    fn test_parse_did_web_simple() {
        assert_eq!(
            parse_did_web_uri("did:web:discourse.org").unwrap(),
            "https://discourse.org/.well-known/did.json"
        );
    }

    #[test]
    fn test_parse_did_web_with_port() {
        assert_eq!(
            parse_did_web_uri("did:web:localhost%3A8080").unwrap(),
            "https://localhost:8080/.well-known/did.json"
        );
    }

    #[test]
    fn test_parse_did_web_with_path() {
        assert_eq!(
            parse_did_web_uri("did:web:example.com:org:dept").unwrap(),
            "https://example.com/org/dept/did.json"
        );
    }

    #[test]
    fn test_parse_did_web_invalid_prefix() {
        assert!(matches!(
            parse_did_web_uri("did:key:z6Mk..."),
            Err(DidError::InvalidDidUri(_))
        ));
    }

    #[test]
    fn test_parse_did_web_empty_id() {
        assert!(matches!(
            parse_did_web_uri("did:web:"),
            Err(DidError::InvalidDidUri(_))
        ));
    }

    #[test]
    fn test_extract_key_from_document() {
        let key = [42u8; 32];
        let doc = generate_did_document("example.com", &key).unwrap();
        let extracted = extract_verification_key(&doc).unwrap();
        assert_eq!(extracted, key);
    }

    #[test]
    fn test_extract_key_no_ed25519() {
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:web:example.com".into(),
            authentication: vec![],
            assertion_method: vec![],
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                type_: "JsonWebKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_multibase: "zNotRelevant".into(),
            }],
        };
        assert!(matches!(
            extract_verification_key(&doc),
            Err(DidError::KeyNotFound(_))
        ));
    }

    #[test]
    fn test_extract_key_by_id_hit() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:web:example.com".into(),
            authentication: vec![],
            assertion_method: vec![],
            verification_method: vec![
                VerificationMethod {
                    id: "did:web:example.com#key-1".into(),
                    type_: "Ed25519VerificationKey2020".into(),
                    controller: "did:web:example.com".into(),
                    public_key_multibase: encode_public_key_multibase(&key1),
                },
                VerificationMethod {
                    id: "did:web:example.com#key-2".into(),
                    type_: "Ed25519VerificationKey2020".into(),
                    controller: "did:web:example.com".into(),
                    public_key_multibase: encode_public_key_multibase(&key2),
                },
            ],
        };
        let extracted =
            extract_verification_key_by_id(&doc, "did:web:example.com#key-2").unwrap();
        assert_eq!(extracted, key2);
    }

    #[test]
    fn test_extract_key_by_id_miss() {
        let key = [1u8; 32];
        let doc = generate_did_document("example.com", &key).unwrap();
        assert!(matches!(
            extract_verification_key_by_id(&doc, "did:web:example.com#key-99"),
            Err(DidError::KeyNotFound(_))
        ));
    }

    #[test]
    fn test_extract_key_bad_multibase() {
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:web:example.com".into(),
            authentication: vec![],
            assertion_method: vec![],
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                type_: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_multibase: "not-valid".into(),
            }],
        };
        assert!(matches!(
            extract_verification_key(&doc),
            Err(DidError::MultibaseDecodeError(_))
        ));
    }

    #[test]
    fn test_extract_key_wrong_codec() {
        let mut buf = Vec::with_capacity(34);
        buf.push(0x00);
        buf.push(0x00);
        buf.extend_from_slice(&[0u8; 32]);
        let multibase = format!("z{}", bs58::encode(&buf).into_string());

        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:web:example.com".into(),
            authentication: vec![],
            assertion_method: vec![],
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                type_: "Ed25519VerificationKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_multibase: multibase,
            }],
        };
        assert!(matches!(
            extract_verification_key(&doc),
            Err(DidError::MultibaseDecodeError(_))
        ));
    }

    #[test]
    fn test_parse_roundtrip_with_domain_to_did() {
        let domains = ["discourse.org", "localhost:8080", "example.com/org/dept"];
        for domain in domains {
            let did = domain_to_did(domain).unwrap();
            let url = parse_did_web_uri(&did).unwrap();
            // Extract domain back from URL
            let host = domain.split('/').next().unwrap();
            assert!(
                url.starts_with(&format!("https://{host}")),
                "roundtrip failed for {domain}: got {url}"
            );
            assert!(url.ends_with("did.json"));
        }
    }

    // Integration tests gated behind the resolve feature
    #[cfg(feature = "resolve")]
    mod resolve_tests {
        use super::*;

        #[tokio::test]
        #[ignore]
        async fn test_resolve_did_web_live() {
            let doc = resolve_did_web("did:web:did.actor:alice").await.unwrap();
            assert!(!doc.verification_method.is_empty());
        }

        #[tokio::test]
        #[ignore]
        async fn test_resolve_did_web_not_found() {
            let result = resolve_did_web("did:web:nonexistent.invalid").await;
            assert!(matches!(result, Err(DidError::ResolutionFailed(_))));
        }
    }
}
