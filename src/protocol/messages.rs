use std::io::{Cursor, Read};
use super::types::*;

// --- Message Header ---

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub command: String,
    pub payload_len: u32,
    pub checksum: [u8; 4],
}

impl MessageHeader {
    pub fn new(command: &str, payload: &[u8]) -> Self {
        let checksum = compute_checksum(payload);
        Self {
            command: command.to_string(),
            payload_len: payload.len() as u32,
            checksum,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let mut cmd = [0u8; 12];
        let cmd_bytes = self.command.as_bytes();
        let len = cmd_bytes.len().min(12);
        cmd[..len].copy_from_slice(&cmd_bytes[..len]);
        buf.extend_from_slice(&cmd);
        buf.extend_from_slice(&self.payload_len.to_be_bytes());
        buf.extend_from_slice(&self.checksum);
        buf
    }

    pub fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf)?;
        let magic = u32::from_be_bytes(magic_buf);
        if magic != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        let mut cmd_buf = [0u8; 12];
        reader.read_exact(&mut cmd_buf)?;
        let command = std::str::from_utf8(&cmd_buf)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let payload_len = u32::from_be_bytes(len_buf);

        if payload_len as usize > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge(payload_len as usize));
        }

        let mut checksum = [0u8; 4];
        reader.read_exact(&mut checksum)?;

        Ok(Self {
            command,
            payload_len,
            checksum,
        })
    }

    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        compute_checksum(payload) == self.checksum
    }
}

/// Encode a full message: header + payload
pub fn encode_message(command: &str, payload: &[u8]) -> Vec<u8> {
    let header = MessageHeader::new(command, payload);
    let mut msg = header.encode();
    msg.extend_from_slice(payload);
    msg
}

// --- Version Message ---

#[derive(Debug, Clone)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub streams: Vec<u64>,
}

impl VersionMessage {
    pub fn new(addr_recv: NetworkAddress) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            services: services::NODE_NETWORK,
            timestamp: chrono::Utc::now().timestamp(),
            addr_recv,
            addr_from: NetworkAddress::localhost(8444),
            nonce: rand::random(),
            user_agent: USER_AGENT.to_string(),
            streams: vec![1],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(&self.version.to_be_bytes());
        payload.extend_from_slice(&self.services.to_be_bytes());
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(&self.addr_recv.encode_short());
        payload.extend_from_slice(&self.addr_from.encode_short());
        payload.extend_from_slice(&self.nonce.to_be_bytes());
        payload.extend(encode_var_str(&self.user_agent));
        payload.extend(encode_var_int_list(&self.streams));
        encode_message("version", &payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(payload);

        let mut ver_buf = [0u8; 4];
        r.read_exact(&mut ver_buf)?;
        let version = u32::from_be_bytes(ver_buf);

        let mut svc_buf = [0u8; 8];
        r.read_exact(&mut svc_buf)?;
        let services = u64::from_be_bytes(svc_buf);

        let mut ts_buf = [0u8; 8];
        r.read_exact(&mut ts_buf)?;
        let timestamp = i64::from_be_bytes(ts_buf);

        let addr_recv = NetworkAddress::decode_short(&mut r)?;
        let addr_from = NetworkAddress::decode_short(&mut r)?;

        let mut nonce_buf = [0u8; 8];
        r.read_exact(&mut nonce_buf)?;
        let nonce = u64::from_be_bytes(nonce_buf);

        let user_agent = decode_var_str(&mut r)?;
        let streams = decode_var_int_list(&mut r)?;

        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            streams,
        })
    }
}

// --- Verack ---

pub fn encode_verack() -> Vec<u8> {
    encode_message("verack", &[])
}

// --- Addr ---

#[derive(Debug, Clone)]
pub struct AddrMessage {
    pub addresses: Vec<NetworkAddress>,
}

impl AddrMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = encode_varint(self.addresses.len() as u64);
        for addr in &self.addresses {
            payload.extend(addr.encode_full());
        }
        encode_message("addr", &payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(payload);
        let count = decode_varint(&mut r)? as usize;
        if count > MAX_ADDR_COUNT {
            return Err(ProtocolError::PayloadTooLarge(count));
        }
        let mut addresses = Vec::with_capacity(count);
        for _ in 0..count {
            addresses.push(NetworkAddress::decode_full(&mut r)?);
        }
        Ok(Self { addresses })
    }
}

// --- Inv ---

#[derive(Debug, Clone)]
pub struct InvMessage {
    pub inventory: Vec<InventoryVector>,
}

impl InvMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = encode_varint(self.inventory.len() as u64);
        for iv in &self.inventory {
            payload.extend(iv.encode());
        }
        encode_message("inv", &payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(payload);
        let count = decode_varint(&mut r)? as usize;
        if count > MAX_INV_COUNT {
            return Err(ProtocolError::PayloadTooLarge(count));
        }
        let mut inventory = Vec::with_capacity(count);
        for _ in 0..count {
            inventory.push(InventoryVector::decode(&mut r)?);
        }
        Ok(Self { inventory })
    }
}

// --- GetData ---

#[derive(Debug, Clone)]
pub struct GetDataMessage {
    pub inventory: Vec<InventoryVector>,
}

impl GetDataMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = encode_varint(self.inventory.len() as u64);
        for iv in &self.inventory {
            payload.extend(iv.encode());
        }
        encode_message("getdata", &payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(payload);
        let count = decode_varint(&mut r)? as usize;
        if count > MAX_INV_COUNT {
            return Err(ProtocolError::PayloadTooLarge(count));
        }
        let mut inventory = Vec::with_capacity(count);
        for _ in 0..count {
            inventory.push(InventoryVector::decode(&mut r)?);
        }
        Ok(Self { inventory })
    }
}

// --- Error ---

#[derive(Debug, Clone)]
pub struct ErrorMessage {
    pub fatal: u64,    // 0=warning, 1=error, 2=fatal
    pub ban_time: u64,
    pub inv_vector: String,
    pub error_text: String,
}

impl ErrorMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = encode_varint(self.fatal);
        payload.extend(encode_varint(self.ban_time));
        payload.extend(encode_var_str(&self.inv_vector));
        payload.extend(encode_var_str(&self.error_text));
        encode_message("error", &payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(payload);
        let fatal = decode_varint(&mut r)?;
        let ban_time = decode_varint(&mut r)?;
        let inv_vector = decode_var_str(&mut r)?;
        let error_text = decode_var_str(&mut r)?;
        Ok(Self {
            fatal,
            ban_time,
            inv_vector,
            error_text,
        })
    }
}

// --- Ping / Pong ---

pub fn encode_ping() -> Vec<u8> {
    encode_message("ping", &[])
}

pub fn encode_pong() -> Vec<u8> {
    encode_message("pong", &[])
}
