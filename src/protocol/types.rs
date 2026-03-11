#[allow(dead_code)]

use std::io::{self, Read};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid varint")]
    InvalidVarInt,
    #[error("Payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("Invalid magic")]
    InvalidMagic,
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Invalid command: {0}")]
    InvalidCommand(String),
    #[error("Unknown object type: {0}")]
    UnknownObjectType(u32),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

// --- Constants ---

pub const MAGIC: u32 = 0xE9BEB4D9;
pub const HEADER_SIZE: usize = 24;
pub const MAX_PAYLOAD_SIZE: usize = 1_600_003;
pub const MAX_OBJECT_PAYLOAD_SIZE: usize = 1 << 18; // 262144
pub const PROTOCOL_VERSION: u32 = 3;
pub const MAX_ADDR_COUNT: usize = 1_000;
pub const MAX_INV_COUNT: usize = 50_000;
pub const MAX_TIME_OFFSET: i64 = 3_600;
pub const ADDRESS_ALIVE_SECONDS: u64 = 10_800; // 3 hours
pub const MAX_TTL: u64 = 28 * 24 * 3600 + 3 * 3600; // 28 days + 3 hours
pub const USER_AGENT: &str = "/bitmessage-rs:0.5.0/";

pub mod services {
    pub const NODE_NETWORK: u64 = 1;
    pub const NODE_SSL: u64 = 2;
    pub const NODE_POW: u64 = 4;
    pub const NODE_DANDELION: u64 = 8;
}

pub mod object_type {
    pub const GETPUBKEY: u32 = 0;
    pub const PUBKEY: u32 = 1;
    pub const MSG: u32 = 2;
    pub const BROADCAST: u32 = 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Ignore = 0,
    Trivial = 1,
    Simple = 2,
    Extended = 3,
}

impl From<u64> for Encoding {
    fn from(v: u64) -> Self {
        match v {
            1 => Encoding::Trivial,
            2 => Encoding::Simple,
            3 => Encoding::Extended,
            _ => Encoding::Ignore,
        }
    }
}

// --- Variable-length integer encoding (big-endian) ---

pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&(value as u16).to_be_bytes());
        buf
    } else if value <= 0xffff_ffff {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&(value as u32).to_be_bytes());
        buf
    } else {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&value.to_be_bytes());
        buf
    }
}

pub fn decode_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    match first[0] {
        0xff => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_be_bytes(buf))
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_be_bytes(buf) as u64)
        }
        0xfd => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u16::from_be_bytes(buf) as u64)
        }
        v => Ok(v as u64),
    }
}

pub fn encode_var_str(s: &str) -> Vec<u8> {
    let mut buf = encode_varint(s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
    buf
}

pub fn decode_var_str<R: Read>(reader: &mut R) -> Result<String> {
    let len = decode_varint(reader)? as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|_| ProtocolError::InvalidCommand("invalid UTF-8".into()))
}

pub fn encode_var_int_list(values: &[u64]) -> Vec<u8> {
    let mut buf = encode_varint(values.len() as u64);
    for &v in values {
        buf.extend(encode_varint(v));
    }
    buf
}

pub fn decode_var_int_list<R: Read>(reader: &mut R) -> Result<Vec<u64>> {
    let count = decode_varint(reader)? as usize;
    let mut values = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        values.push(decode_varint(reader)?);
    }
    Ok(values)
}

// --- Network address ---

#[derive(Debug, Clone)]
pub struct NetworkAddress {
    pub time: u64,
    pub stream: u32,
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16,
}

impl NetworkAddress {
    pub fn new(addr: std::net::SocketAddr, stream: u32, services: u64) -> Self {
        let ip = match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[10] = 0xff;
                bytes[11] = 0xff;
                bytes[12..].copy_from_slice(&v4.octets());
                bytes
            }
            std::net::IpAddr::V6(v6) => v6.octets(),
        };

        Self {
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            stream,
            services,
            ip,
            port: addr.port(),
        }
    }

    pub fn localhost(port: u16) -> Self {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12] = 127;
        ip[15] = 1;
        Self {
            time: 0,
            stream: 1,
            services: services::NODE_NETWORK,
            ip,
            port,
        }
    }

    /// Encode with timestamp and stream (for addr messages)
    pub fn encode_full(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(38);
        buf.extend_from_slice(&self.time.to_be_bytes());
        buf.extend_from_slice(&self.stream.to_be_bytes());
        buf.extend_from_slice(&self.services.to_be_bytes());
        buf.extend_from_slice(&self.ip);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    /// Encode without timestamp and stream (for version messages)
    pub fn encode_short(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26);
        buf.extend_from_slice(&self.services.to_be_bytes());
        buf.extend_from_slice(&self.ip);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    pub fn decode_full<R: Read>(reader: &mut R) -> Result<Self> {
        let mut time_buf = [0u8; 8];
        reader.read_exact(&mut time_buf)?;
        let mut stream_buf = [0u8; 4];
        reader.read_exact(&mut stream_buf)?;
        let mut services_buf = [0u8; 8];
        reader.read_exact(&mut services_buf)?;
        let mut ip = [0u8; 16];
        reader.read_exact(&mut ip)?;
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf)?;

        Ok(Self {
            time: u64::from_be_bytes(time_buf),
            stream: u32::from_be_bytes(stream_buf),
            services: u64::from_be_bytes(services_buf),
            ip,
            port: u16::from_be_bytes(port_buf),
        })
    }

    pub fn decode_short<R: Read>(reader: &mut R) -> Result<Self> {
        let mut services_buf = [0u8; 8];
        reader.read_exact(&mut services_buf)?;
        let mut ip = [0u8; 16];
        reader.read_exact(&mut ip)?;
        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf)?;

        Ok(Self {
            time: 0,
            stream: 0,
            services: u64::from_be_bytes(services_buf),
            ip,
            port: u16::from_be_bytes(port_buf),
        })
    }
}

// --- Inventory vector ---

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InventoryVector {
    pub hash: [u8; 32],
}

impl InventoryVector {
    pub fn new(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    /// Compute from object data: first 32 bytes of double-SHA-512
    pub fn from_object_data(data: &[u8]) -> Self {
        use sha2::{Sha512, Digest};
        let h1 = Sha512::digest(data);
        let h2 = Sha512::digest(h1);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&h2[..32]);
        Self { hash }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    pub fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        Ok(Self { hash })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// Compute first 4 bytes of SHA-512 as checksum
pub fn compute_checksum(data: &[u8]) -> [u8; 4] {
    use sha2::{Sha512, Digest};
    let hash = Sha512::digest(data);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash[..4]);
    checksum
}

/// Current unix timestamp
pub fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
