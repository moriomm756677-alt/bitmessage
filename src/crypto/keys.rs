use k256::{
    ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer},
    SecretKey, PublicKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Signing error: {0}")]
    SigningError(String),
    #[error("Verification failed")]
    VerificationFailed,
}

/// A Bitmessage identity keypair: signing key + encryption key
#[derive(Clone)]
pub struct KeyPair {
    pub signing_secret: Vec<u8>,
    pub encryption_secret: Vec<u8>,
    pub public_signing_key: [u8; 64],   // uncompressed, without 0x04 prefix
    pub public_encryption_key: [u8; 64], // uncompressed, without 0x04 prefix
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_signing_key", &hex::encode(self.public_signing_key))
            .field("public_encryption_key", &hex::encode(self.public_encryption_key))
            .finish()
    }
}

impl KeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_sk = SecretKey::random(&mut OsRng);
        let encryption_sk = SecretKey::random(&mut OsRng);
        Self::from_secrets(
            signing_sk.to_bytes().to_vec(),
            encryption_sk.to_bytes().to_vec(),
        )
        .expect("freshly generated keys should be valid")
    }

    /// Reconstruct from raw secret key bytes
    pub fn from_secrets(signing: Vec<u8>, encryption: Vec<u8>) -> Result<Self, KeyError> {
        let signing_sk =
            SecretKey::from_slice(&signing).map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        let encryption_sk =
            SecretKey::from_slice(&encryption).map_err(|e| KeyError::InvalidKey(e.to_string()))?;

        let signing_pk = signing_sk.public_key();
        let encryption_pk = encryption_sk.public_key();

        let signing_point = signing_pk.to_encoded_point(false);
        let encryption_point = encryption_pk.to_encoded_point(false);

        let mut pub_signing = [0u8; 64];
        pub_signing.copy_from_slice(&signing_point.as_bytes()[1..65]);

        let mut pub_encryption = [0u8; 64];
        pub_encryption.copy_from_slice(&encryption_point.as_bytes()[1..65]);

        Ok(Self {
            signing_secret: signing,
            encryption_secret: encryption,
            public_signing_key: pub_signing,
            public_encryption_key: pub_encryption,
        })
    }

    /// Sign data with the signing key (ECDSA).
    /// Uses SHA-256 pre-hashing to match PyBitmessage 0.6+ default behavior.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Sha256, Digest};
        let sk = SigningKey::from_slice(&self.signing_secret)
            .map_err(|e| KeyError::SigningError(e.to_string()))?;
        let hash = Sha256::digest(data);
        let sig: Signature = sk.sign_prehash(&hash)
            .map_err(|e| KeyError::SigningError(e.to_string()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// Get the signing key for ECDSA verification
    pub fn verifying_key(&self) -> Result<VerifyingKey, KeyError> {
        let sk = SigningKey::from_slice(&self.signing_secret)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        Ok(*sk.verifying_key())
    }

    /// Get the encryption public key as a k256::PublicKey
    pub fn encryption_public_key(&self) -> Result<PublicKey, KeyError> {
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..65].copy_from_slice(&self.public_encryption_key);
        PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))
    }

    /// Get the encryption secret key
    pub fn encryption_secret_key(&self) -> Result<SecretKey, KeyError> {
        SecretKey::from_slice(&self.encryption_secret)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))
    }
}

/// Verify an ECDSA signature given raw public signing key bytes (64 bytes, no prefix).
///
/// Matches PyBitmessage behavior: tries SHA-1 digest first, then SHA-256.
/// PyBitmessage's verify() tries both algorithms for backward compatibility.
pub fn verify_signature(
    public_key_bytes: &[u8; 64],
    data: &[u8],
    signature: &[u8],
) -> Result<bool, KeyError> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha1::Sha1;
    use sha2::Sha256;
    use sha2::Digest as _;

    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(public_key_bytes);

    let vk = VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| KeyError::InvalidKey(e.to_string()))?;

    let sig_raw = Signature::from_der(signature)
        .map_err(|e| KeyError::SigningError(e.to_string()))?;

    // k256 rejects high-S signatures (BIP-0062 malleability fix), but OpenSSL
    // (used by PyBitmessage) can produce either high or low S. Normalize to low-S.
    let sig = sig_raw.normalize_s().unwrap_or(sig_raw);

    // Try SHA-1 first (older PyBitmessage versions)
    let sha1_hash = Sha1::digest(data);
    if vk.verify_prehash(&sha1_hash, &sig).is_ok() {
        return Ok(true);
    }

    // Then try SHA-256 (default in PyBitmessage 0.6+)
    let sha256_hash = Sha256::digest(data);
    if vk.verify_prehash(&sha256_hash, &sig).is_ok() {
        return Ok(true);
    }

    Ok(false)
}

/// Reconstruct a PublicKey from 64 raw bytes (x||y, no 0x04 prefix)
pub fn public_key_from_bytes(bytes: &[u8; 64]) -> Result<PublicKey, KeyError> {
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..65].copy_from_slice(bytes);
    PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| KeyError::InvalidKey(e.to_string()))
}
