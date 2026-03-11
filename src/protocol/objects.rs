use std::io::{self, Cursor, Read};
use super::types::*;
use super::messages::encode_message;

// --- Object header (common to all objects) ---

#[derive(Debug, Clone)]
pub struct ObjectHeader {
    pub nonce: u64,
    pub expires_time: u64,
    pub object_type: u32,
    pub version: u64,
    pub stream_number: u64,
}

impl ObjectHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&self.expires_time.to_be_bytes());
        buf.extend_from_slice(&self.object_type.to_be_bytes());
        buf.extend(encode_varint(self.version));
        buf.extend(encode_varint(self.stream_number));
        buf
    }

    pub fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut nonce_buf = [0u8; 8];
        reader.read_exact(&mut nonce_buf)?;
        let mut time_buf = [0u8; 8];
        reader.read_exact(&mut time_buf)?;
        let mut type_buf = [0u8; 4];
        reader.read_exact(&mut type_buf)?;
        let version = decode_varint(reader)?;
        let stream_number = decode_varint(reader)?;

        Ok(Self {
            nonce: u64::from_be_bytes(nonce_buf),
            expires_time: u64::from_be_bytes(time_buf),
            object_type: u32::from_be_bytes(type_buf),
            version,
            stream_number,
        })
    }

    /// Encode without nonce (for PoW computation and signing)
    pub fn encode_for_signing(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.expires_time.to_be_bytes());
        buf.extend_from_slice(&self.object_type.to_be_bytes());
        buf.extend(encode_varint(self.version));
        buf.extend(encode_varint(self.stream_number));
        buf
    }
}

/// Encode a complete object as a network message
pub fn encode_object_message(header: &ObjectHeader, object_payload: &[u8]) -> Vec<u8> {
    let mut payload = header.encode();
    payload.extend_from_slice(object_payload);
    encode_message("object", &payload)
}

// --- GetPubKey ---

#[derive(Debug, Clone)]
pub enum GetPubKey {
    /// For address version <= 3: RIPEMD-160 hash
    V3 { ripe: [u8; 20] },
    /// For address version >= 4: 32-byte tag
    V4 { tag: [u8; 32] },
}

impl GetPubKey {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            GetPubKey::V3 { ripe } => ripe.to_vec(),
            GetPubKey::V4 { tag } => tag.to_vec(),
        }
    }

    pub fn decode(data: &[u8], addr_version: u64) -> Result<Self> {
        if addr_version >= 4 {
            if data.len() < 32 {
                return Err(ProtocolError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tag too short",
                )));
            }
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&data[..32]);
            Ok(GetPubKey::V4 { tag })
        } else {
            if data.len() < 20 {
                return Err(ProtocolError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ripe too short",
                )));
            }
            let mut ripe = [0u8; 20];
            ripe.copy_from_slice(&data[..20]);
            Ok(GetPubKey::V3 { ripe })
        }
    }
}

// --- PubKey ---

#[derive(Debug, Clone)]
pub struct PubKeyData {
    pub behavior_bitfield: u32,
    pub public_signing_key: [u8; 64],
    pub public_encryption_key: [u8; 64],
    pub nonce_trials_per_byte: u64,
    pub extra_bytes: u64,
    pub signature: Vec<u8>,
}

impl PubKeyData {
    pub fn encode_v3(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(200);
        buf.extend_from_slice(&self.behavior_bitfield.to_be_bytes());
        buf.extend_from_slice(&self.public_signing_key);
        buf.extend_from_slice(&self.public_encryption_key);
        buf.extend(encode_varint(self.nonce_trials_per_byte));
        buf.extend(encode_varint(self.extra_bytes));
        buf.extend(encode_varint(self.signature.len() as u64));
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode v3 pubkey data. Returns (Self, sig_offset) where sig_offset is
    /// the byte position where the signature length varint begins.
    /// Use `data[..sig_offset]` as the unsigned payload for signature verification.
    pub fn decode_v3(data: &[u8]) -> Result<(Self, usize)> {
        let mut r = Cursor::new(data);

        let mut bf_buf = [0u8; 4];
        r.read_exact(&mut bf_buf)?;
        let behavior_bitfield = u32::from_be_bytes(bf_buf);

        let mut signing_key = [0u8; 64];
        r.read_exact(&mut signing_key)?;

        let mut encryption_key = [0u8; 64];
        r.read_exact(&mut encryption_key)?;

        let nonce_trials_per_byte = decode_varint(&mut r)?;
        let extra_bytes = decode_varint(&mut r)?;

        let sig_offset = r.position() as usize;

        let sig_len = decode_varint(&mut r)? as usize;
        let mut signature = vec![0u8; sig_len];
        r.read_exact(&mut signature)?;

        Ok((Self {
            behavior_bitfield,
            public_signing_key: signing_key,
            public_encryption_key: encryption_key,
            nonce_trials_per_byte,
            extra_bytes,
            signature,
        }, sig_offset))
    }

    pub fn encode_v2(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(132);
        buf.extend_from_slice(&self.behavior_bitfield.to_be_bytes());
        buf.extend_from_slice(&self.public_signing_key);
        buf.extend_from_slice(&self.public_encryption_key);
        buf
    }

    pub fn decode_v2(data: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(data);

        let mut bf_buf = [0u8; 4];
        r.read_exact(&mut bf_buf)?;
        let behavior_bitfield = u32::from_be_bytes(bf_buf);

        let mut signing_key = [0u8; 64];
        r.read_exact(&mut signing_key)?;

        let mut encryption_key = [0u8; 64];
        r.read_exact(&mut encryption_key)?;

        Ok(Self {
            behavior_bitfield,
            public_signing_key: signing_key,
            public_encryption_key: encryption_key,
            nonce_trials_per_byte: 1000,
            extra_bytes: 1000,
            signature: Vec::new(),
        })
    }
}

/// V4 pubkey: tag + encrypted data
#[derive(Debug, Clone)]
pub struct PubKeyV4 {
    pub tag: [u8; 32],
    pub encrypted: Vec<u8>,
}

impl PubKeyV4 {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.encrypted.len());
        buf.extend_from_slice(&self.tag);
        buf.extend_from_slice(&self.encrypted);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "v4 pubkey too short",
            )));
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&data[..32]);
        Ok(Self {
            tag,
            encrypted: data[32..].to_vec(),
        })
    }
}

// --- Unencrypted message data (inside encrypted msg/broadcast) ---

#[derive(Debug, Clone)]
pub struct UnencryptedMessage {
    pub sender_address_version: u64,
    pub sender_stream: u64,
    pub behavior_bitfield: u32,
    pub public_signing_key: [u8; 64],
    pub public_encryption_key: [u8; 64],
    pub nonce_trials_per_byte: u64,
    pub extra_bytes: u64,
    pub destination_ripe: Option<[u8; 20]>,
    pub encoding: u64,
    pub message: Vec<u8>,
    pub ack_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UnencryptedMessage {
    /// Encode for msg object (includes destination_ripe)
    pub fn encode_msg(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 + self.message.len());
        buf.extend(encode_varint(self.sender_address_version));
        buf.extend(encode_varint(self.sender_stream));
        buf.extend_from_slice(&self.behavior_bitfield.to_be_bytes());
        buf.extend_from_slice(&self.public_signing_key);
        buf.extend_from_slice(&self.public_encryption_key);
        if self.sender_address_version >= 3 {
            buf.extend(encode_varint(self.nonce_trials_per_byte));
            buf.extend(encode_varint(self.extra_bytes));
        }
        if let Some(ripe) = &self.destination_ripe {
            buf.extend_from_slice(ripe);
        }
        buf.extend(encode_varint(self.encoding));
        buf.extend(encode_varint(self.message.len() as u64));
        buf.extend_from_slice(&self.message);
        buf.extend(encode_varint(self.ack_data.len() as u64));
        buf.extend_from_slice(&self.ack_data);
        // Signature will be appended after signing
        buf
    }

    /// Encode for broadcast object (no destination_ripe)
    pub fn encode_broadcast(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 + self.message.len());
        buf.extend(encode_varint(self.sender_address_version));
        buf.extend(encode_varint(self.sender_stream));
        buf.extend_from_slice(&self.behavior_bitfield.to_be_bytes());
        buf.extend_from_slice(&self.public_signing_key);
        buf.extend_from_slice(&self.public_encryption_key);
        if self.sender_address_version >= 3 {
            buf.extend(encode_varint(self.nonce_trials_per_byte));
            buf.extend(encode_varint(self.extra_bytes));
        }
        buf.extend(encode_varint(self.encoding));
        buf.extend(encode_varint(self.message.len() as u64));
        buf.extend_from_slice(&self.message);
        // Signature will be appended after signing
        buf
    }

    /// Decode msg content. Returns (message, signature_offset) where signature_offset
    /// is the byte position in `data` where the signature length varint begins.
    /// Use `data[..signature_offset]` as the raw unsigned data for signature verification.
    pub fn decode_msg(data: &[u8]) -> Result<(Self, usize)> {
        let mut r = Cursor::new(data);

        let sender_address_version = decode_varint(&mut r)?;
        let sender_stream = decode_varint(&mut r)?;

        let mut bf = [0u8; 4];
        r.read_exact(&mut bf)?;
        let behavior_bitfield = u32::from_be_bytes(bf);

        let mut signing_key = [0u8; 64];
        r.read_exact(&mut signing_key)?;
        let mut encryption_key = [0u8; 64];
        r.read_exact(&mut encryption_key)?;

        let mut nonce_trials = 1000u64;
        let mut extra_bytes = 1000u64;
        if sender_address_version >= 3 {
            nonce_trials = decode_varint(&mut r)?;
            extra_bytes = decode_varint(&mut r)?;
        }

        let mut ripe = [0u8; 20];
        r.read_exact(&mut ripe)?;

        let encoding = decode_varint(&mut r)?;
        let remaining = data.len() - r.position() as usize;
        let msg_len = decode_varint(&mut r)? as usize;
        if msg_len > remaining {
            return Err(ProtocolError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("msg_len {msg_len} exceeds remaining {remaining}"))));
        }
        let mut message = vec![0u8; msg_len];
        r.read_exact(&mut message)?;

        let remaining = data.len() - r.position() as usize;
        let ack_len = decode_varint(&mut r)? as usize;
        if ack_len > remaining {
            return Err(ProtocolError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("ack_len {ack_len} exceeds remaining {remaining}"))));
        }
        let mut ack_data = vec![0u8; ack_len];
        r.read_exact(&mut ack_data)?;

        // Record position before signature — this is the boundary for signature verification
        let sig_offset = r.position() as usize;

        let remaining = data.len() - r.position() as usize;
        let sig_len = decode_varint(&mut r)? as usize;
        if sig_len > remaining {
            return Err(ProtocolError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("sig_len {sig_len} exceeds remaining {remaining}"))));
        }
        let mut signature = vec![0u8; sig_len];
        r.read_exact(&mut signature)?;

        Ok((Self {
            sender_address_version,
            sender_stream,
            behavior_bitfield,
            public_signing_key: signing_key,
            public_encryption_key: encryption_key,
            nonce_trials_per_byte: nonce_trials,
            extra_bytes,
            destination_ripe: Some(ripe),
            encoding,
            message,
            ack_data,
            signature,
        }, sig_offset))
    }

    /// Decode broadcast content (same as msg but without destination_ripe and ack_data).
    /// Returns (message, signature_offset).
    pub fn decode_broadcast(data: &[u8]) -> Result<(Self, usize)> {
        let mut r = Cursor::new(data);

        let sender_address_version = decode_varint(&mut r)?;
        let sender_stream = decode_varint(&mut r)?;

        let mut bf = [0u8; 4];
        r.read_exact(&mut bf)?;
        let behavior_bitfield = u32::from_be_bytes(bf);

        let mut signing_key = [0u8; 64];
        r.read_exact(&mut signing_key)?;
        let mut encryption_key = [0u8; 64];
        r.read_exact(&mut encryption_key)?;

        let mut nonce_trials = 1000u64;
        let mut extra_bytes = 1000u64;
        if sender_address_version >= 3 {
            nonce_trials = decode_varint(&mut r)?;
            extra_bytes = decode_varint(&mut r)?;
        }

        let encoding = decode_varint(&mut r)?;
        let remaining = data.len() - r.position() as usize;
        let msg_len = decode_varint(&mut r)? as usize;
        if msg_len > remaining {
            return Err(ProtocolError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("broadcast msg_len {msg_len} exceeds remaining {remaining}"))));
        }
        let mut message = vec![0u8; msg_len];
        r.read_exact(&mut message)?;

        let sig_offset = r.position() as usize;

        let remaining = data.len() - r.position() as usize;
        let sig_len = decode_varint(&mut r)? as usize;
        if sig_len > remaining {
            return Err(ProtocolError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("broadcast sig_len {sig_len} exceeds remaining data {remaining}"))));
        }
        let mut signature = vec![0u8; sig_len];
        r.read_exact(&mut signature)?;

        Ok((Self {
            sender_address_version,
            sender_stream,
            behavior_bitfield,
            public_signing_key: signing_key,
            public_encryption_key: encryption_key,
            nonce_trials_per_byte: nonce_trials,
            extra_bytes,
            destination_ripe: None,
            encoding,
            message,
            ack_data: vec![],
            signature,
        }, sig_offset))
    }
}

/// Parse Simple encoding (type 2): "Subject:<subject>\nBody:<body>"
pub fn parse_simple_encoding(data: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(data);
    let mut subject = String::new();
    let mut body = String::new();

    if let Some(rest) = text.strip_prefix("Subject:") {
        if let Some(idx) = rest.find("\nBody:") {
            subject = rest[..idx].to_string();
            body = rest[idx + 6..].to_string();
        } else {
            subject = rest.to_string();
        }
    } else {
        body = text.to_string();
    }

    (subject, body)
}

/// Encode Simple encoding (type 2)
pub fn encode_simple_message(subject: &str, body: &str) -> Vec<u8> {
    format!("Subject:{subject}\nBody:{body}").into_bytes()
}

// --- Bitfield constants ---

pub mod bitfield {
    // Bitmessage protocol uses reversed bit numbering: "bit 31" = LSB.
    // PyBitmessage: BITFIELD_DOESACK = 1
    pub const DOES_ACK: u32 = 1;
    pub const INCLUDE_DESTINATION: u32 = 2;
}

// ============================================================================
// Extended encoding (type 3) — structured messages with file attachments
// ============================================================================

/// Maximum usable chunk size (conservative, accounts for all protocol overhead)
pub const FILE_CHUNK_SIZE: usize = 180_000;

/// Part types in extended encoding
const PART_TEXT: u64 = 0;
const PART_FILE_MANIFEST: u64 = 1;
const PART_FILE_CHUNK: u64 = 2;

/// A part inside an extended-encoding message
#[derive(Debug, Clone)]
pub enum MessagePart {
    Text {
        subject: String,
        body: String,
    },
    FileManifest {
        transfer_id: [u8; 16],
        filename: String,
        mime_type: String,
        total_size: u64,
        sha256_hash: [u8; 32],
        total_chunks: u64,
        chunk_index: u64,
        chunk_data: Vec<u8>,
    },
    FileChunk {
        transfer_id: [u8; 16],
        chunk_index: u64,
        chunk_data: Vec<u8>,
    },
}

/// Extended encoding message — a list of parts
#[derive(Debug, Clone)]
pub struct ExtendedMessage {
    pub parts: Vec<MessagePart>,
}

impl ExtendedMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(encode_varint(self.parts.len() as u64));
        for part in &self.parts {
            match part {
                MessagePart::Text { subject, body } => {
                    buf.extend(encode_varint(PART_TEXT));
                    let mut inner = Vec::new();
                    inner.extend(encode_var_str(subject));
                    inner.extend(encode_var_str(body));
                    buf.extend(encode_varint(inner.len() as u64));
                    buf.extend(inner);
                }
                MessagePart::FileManifest {
                    transfer_id, filename, mime_type,
                    total_size, sha256_hash, total_chunks,
                    chunk_index, chunk_data,
                } => {
                    buf.extend(encode_varint(PART_FILE_MANIFEST));
                    let mut inner = Vec::new();
                    inner.extend_from_slice(transfer_id);
                    inner.extend(encode_var_str(filename));
                    inner.extend(encode_var_str(mime_type));
                    inner.extend_from_slice(&total_size.to_be_bytes());
                    inner.extend_from_slice(sha256_hash);
                    inner.extend(encode_varint(*total_chunks));
                    inner.extend(encode_varint(*chunk_index));
                    inner.extend(encode_varint(chunk_data.len() as u64));
                    inner.extend_from_slice(chunk_data);
                    buf.extend(encode_varint(inner.len() as u64));
                    buf.extend(inner);
                }
                MessagePart::FileChunk {
                    transfer_id, chunk_index, chunk_data,
                } => {
                    buf.extend(encode_varint(PART_FILE_CHUNK));
                    let mut inner = Vec::new();
                    inner.extend_from_slice(transfer_id);
                    inner.extend(encode_varint(*chunk_index));
                    inner.extend(encode_varint(chunk_data.len() as u64));
                    inner.extend_from_slice(chunk_data);
                    buf.extend(encode_varint(inner.len() as u64));
                    buf.extend(inner);
                }
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(data);
        let num_parts = decode_varint(&mut r)? as usize;
        if num_parts > 64 {
            return Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::InvalidData, "too many parts in extended message",
            )));
        }
        let mut parts = Vec::with_capacity(num_parts);
        for _ in 0..num_parts {
            let part_type = decode_varint(&mut r)?;
            let part_len = decode_varint(&mut r)? as usize;
            let pos = r.position() as usize;
            if pos + part_len > data.len() {
                return Err(ProtocolError::Io(io::Error::new(
                    io::ErrorKind::InvalidData, "part exceeds message data",
                )));
            }
            let part_data = &data[pos..pos + part_len];
            let mut pr = Cursor::new(part_data);

            let part = match part_type {
                PART_TEXT => {
                    let subject = decode_var_str(&mut pr)?;
                    let body = decode_var_str(&mut pr)?;
                    MessagePart::Text { subject, body }
                }
                PART_FILE_MANIFEST => {
                    let mut transfer_id = [0u8; 16];
                    pr.read_exact(&mut transfer_id)?;
                    let filename = decode_var_str(&mut pr)?;
                    let mime_type = decode_var_str(&mut pr)?;
                    let mut size_buf = [0u8; 8];
                    pr.read_exact(&mut size_buf)?;
                    let total_size = u64::from_be_bytes(size_buf);
                    let mut sha256_hash = [0u8; 32];
                    pr.read_exact(&mut sha256_hash)?;
                    let total_chunks = decode_varint(&mut pr)?;
                    let chunk_index = decode_varint(&mut pr)?;
                    let chunk_len = decode_varint(&mut pr)? as usize;
                    let mut chunk_data = vec![0u8; chunk_len];
                    pr.read_exact(&mut chunk_data)?;
                    MessagePart::FileManifest {
                        transfer_id, filename, mime_type,
                        total_size, sha256_hash, total_chunks,
                        chunk_index, chunk_data,
                    }
                }
                PART_FILE_CHUNK => {
                    let mut transfer_id = [0u8; 16];
                    pr.read_exact(&mut transfer_id)?;
                    let chunk_index = decode_varint(&mut pr)?;
                    let chunk_len = decode_varint(&mut pr)? as usize;
                    let mut chunk_data = vec![0u8; chunk_len];
                    pr.read_exact(&mut chunk_data)?;
                    MessagePart::FileChunk { transfer_id, chunk_index, chunk_data }
                }
                _ => {
                    // Unknown part type — skip
                    r.set_position((pos + part_len) as u64);
                    continue;
                }
            };
            parts.push(part);
            r.set_position((pos + part_len) as u64);
        }
        Ok(ExtendedMessage { parts })
    }
}

/// Parse extended encoding — extracts text (subject/body) and file parts
pub fn parse_extended_encoding(data: &[u8]) -> Result<ExtendedMessage> {
    ExtendedMessage::decode(data)
}

/// Split file data into chunks of FILE_CHUNK_SIZE
pub fn split_file_into_chunks(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(FILE_CHUNK_SIZE)
        .map(|c| c.to_vec())
        .collect()
}
