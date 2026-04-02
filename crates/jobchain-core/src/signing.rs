use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Errors that can occur during signing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("signing failed: {0}")]
    Signing(String),
}

/// An Ed25519 keypair for signing credentials.
///
/// Debug output redacts the secret key material.
pub struct Keypair {
    signing_key: SigningKey,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &self.public_key_multibase())
            .finish()
    }
}

impl Keypair {
    /// Generate a fresh Ed25519 keypair using OS randomness.
    pub fn generate() -> Result<Self, SigningError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self { signing_key })
    }

    /// Return the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Return the public key as a multibase-encoded string (z-base58btc).
    ///
    /// The encoding prepends the multicodec Ed25519 public key header (0xed, 0x01)
    /// before the 32-byte key, then base58btc-encodes the result with a `z` prefix.
    pub fn public_key_multibase(&self) -> String {
        let pk_bytes = self.public_key_bytes();
        let mut buf = Vec::with_capacity(34);
        buf.push(0xed);
        buf.push(0x01);
        buf.extend_from_slice(&pk_bytes);
        format!("z{}", bs58::encode(&buf).into_string())
    }

    /// Save the 32-byte secret key seed to a file with 0o600 permissions.
    pub fn save(&self, path: &Path) -> Result<(), SigningError> {
        let seed = self.signing_key.to_bytes();

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true).mode(0o600);
            std::io::Write::write_all(&mut opts.open(path)?, &seed)?;
        }

        #[cfg(not(unix))]
        {
            fs::write(path, &seed)?;
        }

        Ok(())
    }

    /// Load a keypair from a 32-byte seed file.
    pub fn load(path: &Path) -> Result<Self, SigningError> {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(SigningError::InvalidKey(format!(
                "expected 32-byte seed, got {} bytes",
                bytes.len()
            )));
        }
        let seed: [u8; 32] = bytes.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    /// Write just the 32-byte public key to a file.
    pub fn save_public_key(&self, path: &Path) -> Result<(), SigningError> {
        fs::write(path, self.public_key_bytes())?;
        Ok(())
    }

    /// Access the underlying signing key (for signing operations in later steps).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// Load a 32-byte public key file and return a VerifyingKey.
pub fn load_public_key(
    path: &Path,
) -> Result<ed25519_dalek::VerifyingKey, SigningError> {
    let bytes = fs::read(path)?;
    if bytes.len() != 32 {
        return Err(SigningError::InvalidKey(format!(
            "expected 32-byte public key, got {} bytes",
            bytes.len()
        )));
    }
    let key_bytes: [u8; 32] = bytes.try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| SigningError::InvalidKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_keypair() {
        let kp = Keypair::generate().unwrap();
        let pk = kp.public_key_bytes();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn test_roundtrip_save_load() {
        let kp = Keypair::generate().unwrap();
        let tmp = NamedTempFile::new().unwrap();
        kp.save(tmp.path()).unwrap();

        let loaded = Keypair::load(tmp.path()).unwrap();
        assert_eq!(kp.public_key_bytes(), loaded.public_key_bytes());
    }

    #[test]
    fn test_load_invalid_file() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"too short").unwrap();

        let err = Keypair::load(tmp.path()).unwrap_err();
        assert!(matches!(err, SigningError::InvalidKey(_)));
    }

    #[test]
    fn test_public_key_export() {
        let kp = Keypair::generate().unwrap();
        let tmp = NamedTempFile::new().unwrap();
        kp.save_public_key(tmp.path()).unwrap();

        let vk = load_public_key(tmp.path()).unwrap();
        assert_eq!(vk.to_bytes(), kp.public_key_bytes());
    }

    #[test]
    fn test_multibase_encoding() {
        let kp = Keypair::generate().unwrap();
        let mb = kp.public_key_multibase();

        // Must start with 'z' (base58btc multibase prefix)
        assert!(mb.starts_with('z'));

        // Decode and verify round-trip
        let decoded = bs58::decode(&mb[1..]).into_vec().unwrap();
        assert_eq!(decoded.len(), 34); // 2-byte header + 32-byte key
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], &kp.public_key_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn test_save_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let kp = Keypair::generate().unwrap();
        let tmp = NamedTempFile::new().unwrap();
        kp.save(tmp.path()).unwrap();

        let perms = std::fs::metadata(tmp.path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
