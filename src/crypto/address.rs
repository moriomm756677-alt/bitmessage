use k256::SecretKey;
use sha2::{Sha512, Digest};
use ripemd::Ripemd160;
use thiserror::Error;

use crate::protocol::types::encode_varint;
use super::keys::KeyPair;

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("Invalid address: {0}")]
    Invalid(String),
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Key generation failed after max attempts")]
    GenerationFailed,
}

/// A decoded Bitmessage address
#[derive(Debug, Clone)]
pub struct BitmessageAddress {
    pub version: u64,
    pub stream: u64,
    pub ripe: Vec<u8>,
    pub tag: Option<[u8; 32]>,
    pub encoded: String,
}

impl BitmessageAddress {
    /// Generate a new random address (version 4, stream 1)
    pub fn generate_random(label: &str) -> Result<(BitmessageAddress, KeyPair), AddressError> {
        Self::generate_random_v(4, 1, label)
    }

    /// Generate a random address with specific version and stream
    pub fn generate_random_v(
        version: u64,
        stream: u64,
        _label: &str,
    ) -> Result<(BitmessageAddress, KeyPair), AddressError> {
        for _ in 0..10_000 {
            let keypair = KeyPair::generate();
            let ripe = compute_ripe(&keypair.public_signing_key, &keypair.public_encryption_key);

            // Address must have at least one leading zero byte
            if ripe[0] != 0x00 {
                continue;
            }

            let addr = encode_address(version, stream, &ripe);
            let tag = if version >= 4 {
                Some(compute_tag(version, stream, &ripe))
            } else {
                None
            };

            return Ok((
                BitmessageAddress {
                    version,
                    stream,
                    ripe: ripe.to_vec(),
                    tag,
                    encoded: addr,
                },
                keypair,
            ));
        }

        Err(AddressError::GenerationFailed)
    }

    /// Generate a deterministic address from passphrase (for channels)
    pub fn from_passphrase(passphrase: &str) -> Result<(BitmessageAddress, KeyPair), AddressError> {
        let version = 4u64;
        let stream = 1u64;

        // Derive signing and encryption keys from passphrase
        let passphrase_bytes = passphrase.as_bytes();
        let mut signing_secret = None;
        let mut encryption_secret = None;

        // Find signing key: SHA-512(passphrase + varint(nonce)) until valid
        for nonce in 0u64.. {
            let mut data = passphrase_bytes.to_vec();
            data.extend(encode_varint(nonce));
            let hash = Sha512::digest(&data);
            let key_bytes = &hash[..32];
            if SecretKey::from_slice(key_bytes).is_ok() {
                if signing_secret.is_none() {
                    signing_secret = Some(key_bytes.to_vec());
                } else {
                    encryption_secret = Some(key_bytes.to_vec());
                    break;
                }
            }
        }

        let signing = signing_secret.ok_or(AddressError::GenerationFailed)?;
        let encryption = encryption_secret.ok_or(AddressError::GenerationFailed)?;

        let keypair =
            KeyPair::from_secrets(signing, encryption).map_err(|e| AddressError::Invalid(e.to_string()))?;

        let ripe = compute_ripe(&keypair.public_signing_key, &keypair.public_encryption_key);
        let addr = encode_address(version, stream, &ripe);
        let tag = Some(compute_tag(version, stream, &ripe));

        Ok((
            BitmessageAddress {
                version,
                stream,
                ripe: ripe.to_vec(),
                tag,
                encoded: addr,
            },
            keypair,
        ))
    }

    /// Decode an encoded Bitmessage address string
    pub fn decode(address: &str) -> Result<Self, AddressError> {
        let addr = address.strip_prefix("BM-").unwrap_or(address);
        let data = bs58::decode(addr)
            .into_vec()
            .map_err(|e| AddressError::Invalid(format!("Base58 decode: {e}")))?;

        if data.len() < 6 {
            return Err(AddressError::Invalid("too short".into()));
        }

        // Last 4 bytes are checksum
        let payload = &data[..data.len() - 4];
        let checksum = &data[data.len() - 4..];

        // Verify checksum: first 4 bytes of double-SHA-512
        let hash1 = Sha512::digest(payload);
        let hash2 = Sha512::digest(hash1);
        if &hash2[..4] != checksum {
            return Err(AddressError::ChecksumMismatch);
        }

        let mut r = std::io::Cursor::new(payload);
        let version =
            crate::protocol::types::decode_varint(&mut r).map_err(|e| AddressError::Invalid(e.to_string()))?;
        let stream =
            crate::protocol::types::decode_varint(&mut r).map_err(|e| AddressError::Invalid(e.to_string()))?;

        let pos = r.position() as usize;
        let ripe_data = &payload[pos..];

        // Restore leading zeros (RIPEMD-160 produces 20 bytes)
        if ripe_data.len() > 20 {
            return Err(AddressError::Invalid("RIPE data exceeds 20 bytes".into()));
        }
        let mut ripe = vec![0u8; 20 - ripe_data.len()];
        ripe.extend_from_slice(ripe_data);

        let tag = if version >= 4 {
            Some(compute_tag(version, stream, &ripe))
        } else {
            None
        };

        Ok(BitmessageAddress {
            version,
            stream,
            ripe,
            tag,
            encoded: format!("BM-{addr}"),
        })
    }
}

/// Compute RIPEMD-160(SHA-512(\x04 || signing_key || \x04 || encryption_key))
/// Keys must include the 0x04 uncompressed point prefix for compatibility with PyBitmessage.
pub fn compute_ripe(signing_pubkey: &[u8; 64], encryption_pubkey: &[u8; 64]) -> [u8; 20] {
    let mut combined = Vec::with_capacity(130);
    combined.push(0x04);
    combined.extend_from_slice(signing_pubkey);
    combined.push(0x04);
    combined.extend_from_slice(encryption_pubkey);

    let sha_hash = Sha512::digest(&combined);
    let ripe_hash = Ripemd160::digest(&sha_hash);

    let mut result = [0u8; 20];
    result.copy_from_slice(&ripe_hash);
    result
}

/// Encode a Bitmessage address from version, stream, and ripe hash
pub fn encode_address(version: u64, stream: u64, ripe: &[u8]) -> String {
    let mut payload = encode_varint(version);
    payload.extend(encode_varint(stream));

    // Strip leading zeros from ripe
    let ripe_trimmed = ripe
        .iter()
        .position(|&b| b != 0)
        .map(|i| &ripe[i..])
        .unwrap_or(ripe);
    payload.extend_from_slice(ripe_trimmed);

    // Checksum: first 4 bytes of double-SHA-512
    let h1 = Sha512::digest(&payload);
    let h2 = Sha512::digest(h1);
    payload.extend_from_slice(&h2[..4]);

    format!("BM-{}", bs58::encode(&payload).into_string())
}

/// Compute tag for v4 addresses: bytes [32..64] of double-SHA-512(version || stream || ripe)
pub fn compute_tag(version: u64, stream: u64, ripe: &[u8]) -> [u8; 32] {
    let mut data = encode_varint(version);
    data.extend(encode_varint(stream));
    data.extend_from_slice(ripe);

    let h1 = Sha512::digest(&data);
    let h2 = Sha512::digest(h1);

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&h2[32..64]);
    tag
}

/// Compute the encryption key for v4 pubkey/broadcast decryption
/// Returns (private_key_bytes, tag)
pub fn compute_address_encryption_key(
    version: u64,
    stream: u64,
    ripe: &[u8],
) -> ([u8; 32], [u8; 32]) {
    let mut data = encode_varint(version);
    data.extend(encode_varint(stream));
    data.extend_from_slice(ripe);

    let h1 = Sha512::digest(&data);
    let h2 = Sha512::digest(h1);

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&h2[..32]);

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&h2[32..64]);

    (privkey, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_roundtrip() {
        let (addr, _keypair) = BitmessageAddress::generate_random("Test").unwrap();
        let decoded = BitmessageAddress::decode(&addr.encoded).unwrap();
        assert_eq!(decoded.version, addr.version);
        assert_eq!(decoded.stream, addr.stream);
        assert_eq!(decoded.ripe, addr.ripe);
    }
}
