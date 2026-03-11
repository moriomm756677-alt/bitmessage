use aes::Aes256;
use cbc::Encryptor as CbcEncryptor;
use cbc::Decryptor as CbcDecryptor;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use k256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand::RngCore;
use sha2::{Sha256, Sha512, Digest};
use thiserror::Error;

type Aes256CbcEnc = CbcEncryptor<Aes256>;
type Aes256CbcDec = CbcDecryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

const CURVE_TYPE: u16 = 0x02CA;

#[derive(Debug, Error)]
pub enum EciesError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("HMAC verification failed")]
    HmacMismatch,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Malformed ciphertext")]
    MalformedCiphertext,
}

/// ECIES encrypted payload as defined in the Bitmessage protocol
#[derive(Debug, Clone)]
pub struct EncryptedPayload {
    pub iv: [u8; 16],
    pub curve_type: u16,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 32],
}

impl EncryptedPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            16 + 2 + 2 + self.public_key_x.len() + 2 + self.public_key_y.len()
                + self.ciphertext.len() + 32,
        );
        buf.extend_from_slice(&self.iv);
        buf.extend_from_slice(&self.curve_type.to_be_bytes());
        buf.extend_from_slice(&(self.public_key_x.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key_x);
        buf.extend_from_slice(&(self.public_key_y.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key_y);
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&self.mac);
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, EciesError> {
        if data.len() < 16 + 2 + 2 + 2 + 32 {
            return Err(EciesError::MalformedCiphertext);
        }

        let mut pos = 0;

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        let curve_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        let x_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + x_len > data.len() {
            return Err(EciesError::MalformedCiphertext);
        }
        let public_key_x = data[pos..pos + x_len].to_vec();
        pos += x_len;

        if pos + 2 > data.len() {
            return Err(EciesError::MalformedCiphertext);
        }
        let y_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + y_len > data.len() {
            return Err(EciesError::MalformedCiphertext);
        }
        let public_key_y = data[pos..pos + y_len].to_vec();
        pos += y_len;

        if data.len() < pos + 32 {
            return Err(EciesError::MalformedCiphertext);
        }

        let ciphertext = data[pos..data.len() - 32].to_vec();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[data.len() - 32..]);

        Ok(Self {
            iv,
            curve_type,
            public_key_x,
            public_key_y,
            ciphertext,
            mac,
        })
    }
}

/// Encrypt plaintext using recipient's public key (ECIES)
pub fn encrypt(recipient_pubkey: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, EciesError> {
    let mut rng = rand::thread_rng();

    // Generate random IV
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    // Generate ephemeral keypair
    let ephemeral_sk = SecretKey::random(&mut rng);
    let ephemeral_pk = ephemeral_sk.public_key();

    // ECDH: shared_secret = ephemeral_sk * recipient_pubkey
    let shared = diffie_hellman(
        ephemeral_sk.to_nonzero_scalar(),
        recipient_pubkey.as_affine(),
    );
    let shared_x = shared.raw_secret_bytes();

    // H = SHA-512(shared_x)
    let h = Sha512::digest(shared_x);
    let key_e = &h[..32]; // encryption key
    let key_m = &h[32..]; // MAC key

    // AES-256-CBC encrypt with PKCS7 padding
    let ciphertext = Aes256CbcEnc::new_from_slices(key_e, &iv)
        .map_err(|_| EciesError::InvalidKey("AES key init failed".into()))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Serialize ephemeral public key components
    let point = ephemeral_pk.to_encoded_point(false);
    let pk_x = pad_to_32(point.x().map(|x| x.as_slice()).unwrap_or(&[]));
    let pk_y = pad_to_32(point.y().map(|y| y.as_slice()).unwrap_or(&[]));

    // Build data for HMAC: IV || curve_type || x_len || x || y_len || y || ciphertext
    let mut hmac_data = Vec::new();
    hmac_data.extend_from_slice(&iv);
    hmac_data.extend_from_slice(&CURVE_TYPE.to_be_bytes());
    hmac_data.extend_from_slice(&(pk_x.len() as u16).to_be_bytes());
    hmac_data.extend_from_slice(&pk_x);
    hmac_data.extend_from_slice(&(pk_y.len() as u16).to_be_bytes());
    hmac_data.extend_from_slice(&pk_y);
    hmac_data.extend_from_slice(&ciphertext);

    // HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(key_m)
        .map_err(|_| EciesError::InvalidKey("HMAC key init failed".into()))?;
    mac.update(&hmac_data);
    let mac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    let payload = EncryptedPayload {
        iv,
        curve_type: CURVE_TYPE,
        public_key_x: pk_x,
        public_key_y: pk_y,
        ciphertext,
        mac: mac_bytes,
    };

    Ok(payload.serialize())
}

/// Decrypt ECIES ciphertext using private key
pub fn decrypt(secret_key: &SecretKey, data: &[u8]) -> Result<Vec<u8>, EciesError> {
    let payload = EncryptedPayload::deserialize(data)?;

    // Reconstruct ephemeral public key R from x, y components
    let mut uncompressed = vec![0x04];
    let x_padded = pad_to_32(&payload.public_key_x);
    let y_padded = pad_to_32(&payload.public_key_y);
    uncompressed.extend_from_slice(&x_padded);
    uncompressed.extend_from_slice(&y_padded);

    let ephemeral_pk = PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| EciesError::InvalidKey(e.to_string()))?;

    // ECDH: shared_secret = secret_key * R
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), ephemeral_pk.as_affine());
    let shared_x = shared.raw_secret_bytes();

    // H = SHA-512(shared_x)
    let h = Sha512::digest(shared_x);
    let key_e = &h[..32];
    let key_m = &h[32..];

    // Verify HMAC
    let mut hmac_data = Vec::new();
    hmac_data.extend_from_slice(&payload.iv);
    hmac_data.extend_from_slice(&payload.curve_type.to_be_bytes());
    hmac_data.extend_from_slice(&(payload.public_key_x.len() as u16).to_be_bytes());
    hmac_data.extend_from_slice(&payload.public_key_x);
    hmac_data.extend_from_slice(&(payload.public_key_y.len() as u16).to_be_bytes());
    hmac_data.extend_from_slice(&payload.public_key_y);
    hmac_data.extend_from_slice(&payload.ciphertext);

    let mut mac = HmacSha256::new_from_slice(key_m)
        .map_err(|_| EciesError::InvalidKey("HMAC key init failed".into()))?;
    mac.update(&hmac_data);
    mac.verify_slice(&payload.mac)
        .map_err(|_| EciesError::HmacMismatch)?;

    // AES-256-CBC decrypt
    let mut ct = payload.ciphertext;
    let plaintext = Aes256CbcDec::new_from_slices(key_e, &payload.iv)
        .map_err(|_| EciesError::InvalidKey("AES key init failed".into()))?
        .decrypt_padded_vec_mut::<Pkcs7>(&mut ct)
        .map_err(|_| EciesError::DecryptionFailed)?;

    Ok(plaintext)
}

/// Left-pad bytes to 32 bytes with zeros
fn pad_to_32(input: &[u8]) -> Vec<u8> {
    if input.len() >= 32 {
        input[input.len() - 32..].to_vec()
    } else {
        let mut padded = vec![0u8; 32 - input.len()];
        padded.extend_from_slice(input);
        padded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let pk = sk.public_key();

        let plaintext = b"Hello, Bitmessage!";
        let encrypted = encrypt(&pk, plaintext).unwrap();
        let decrypted = decrypt(&sk, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
