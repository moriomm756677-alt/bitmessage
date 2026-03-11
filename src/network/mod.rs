pub mod peer;

use std::sync::{mpsc, Arc, Mutex};
use crate::storage::Database;

/// Bootstrap seed nodes from the PyBitmessage network
pub const BOOTSTRAP_NODES: &[(&str, u16)] = &[
    // Verified active nodes (2026-03)
    ("185.19.31.46", 8444),
    ("85.114.135.102", 8444),
    ("185.158.248.216", 8444),
    ("194.164.163.84", 8444),
    ("5.135.166.102", 8444),
    ("158.69.63.42", 8080),
    ("95.49.223.149", 8444),
    // Legacy bootstrap
    ("5.45.99.75", 8444),
    ("75.167.159.54", 8444),
    ("95.165.168.168", 8444),
    ("85.180.139.241", 8444),
    ("178.62.12.187", 8448),
    ("178.11.46.221", 8444),
];

pub const DNS_SEEDS: &[&str] = &[
    "bootstrap8080.bitmessage.org",
    "bootstrap8444.bitmessage.org",
];

/// File attachment data for sending
#[derive(Debug)]
pub struct AttachmentData {
    pub filename: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum NetworkCommand {
    SendMessage {
        msgid: String,
        from_address: String,
        to_address: String,
        subject: String,
        body: String,
        attachment: Option<AttachmentData>,
    },
    SendBroadcast {
        msgid: String,
        from_address: String,
        subject: String,
        body: String,
    },
    RequestPubkey(String),
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerConnected(String),
    PeerDisconnected(String),
    PeerCountChanged(usize),
    MessageReceived {
        from: String,
        to: String,
        subject: String,
        body: String,
    },
    BroadcastReceived {
        from: String,
        subject: String,
        body: String,
    },
    PubkeyReceived {
        address: String,
    },
    FileProgress {
        transfer_id: Vec<u8>,
        chunks_done: u64,
        total_chunks: u64,
        filename: String,
    },
    TorStatus {
        connected: bool,
        bootstrap_pct: u8,
        message: String,
    },
    StatusUpdate(String),
    Error(String),
    StatsUpdate {
        objects_received: u64,
        objects_processed: u64,
        bytes_sent: u64,
        bytes_received: u64,
        inventory_count: i64,
    },
}

pub async fn run(
    cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    db: Arc<Mutex<Database>>,
) {
    let mut manager = peer::PeerManager::new(cmd_rx, event_tx, db);
    manager.run().await;
}
