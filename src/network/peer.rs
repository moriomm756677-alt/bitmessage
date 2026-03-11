use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

use crate::crypto::address::{self, BitmessageAddress};
use crate::crypto::ecies;
use crate::crypto::keys::KeyPair;
use crate::crypto::pow;
use crate::protocol::messages::*;
use crate::protocol::objects::*;
use crate::protocol::types::*;
use crate::storage::Database;
use super::{NetworkCommand, NetworkEvent, BOOTSTRAP_NODES, DNS_SEEDS};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);  // Tor circuits take longer
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);
const DEFAULT_TTL: u64 = 4 * 24 * 3600; // 4 days
const RECONNECT_INTERVAL: Duration = Duration::from_secs(90); // 90 sec
const CLEANUP_INTERVAL: Duration = Duration::from_secs(600); // 10 min
const MAX_PEERS: usize = 8;
const RETRY_QUEUED_INTERVAL: Duration = Duration::from_secs(60);
const STATS_INTERVAL: Duration = Duration::from_secs(5);
const DOWNLOAD_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const REPROCESS_RELOAD_INTERVAL: Duration = Duration::from_secs(120); // 2 min
const REQUEST_TIMEOUT_SECS: u64 = 60;
const MAX_SEEN_INV: usize = 500_000;
const MAX_MISSING_OBJECTS: usize = 50_000;
const MAX_SENT_ACKS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: String,
    pub port: u16,
    pub services: u64,
    pub user_agent: String,
    pub streams: Vec<u64>,
    pub connected: bool,
}

/// Writer half of a Tor DataStream (Box<dyn> to avoid leaking arti types everywhere)
type PeerWriter = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

struct ConnectedPeer {
    info: PeerInfo,
    writer: PeerWriter,
}

pub struct PeerManager {
    cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    db: Arc<Mutex<Database>>,
    peers: Vec<ConnectedPeer>,
    our_nonce: u64,
    // Tor client — all connections routed through Tor
    tor_client: Option<TorClient<PreferredRuntime>>,
    // Incoming data from peer read tasks
    peer_data_tx: tokio::sync::mpsc::Sender<PeerIncoming>,
    peer_data_rx: tokio::sync::mpsc::Receiver<PeerIncoming>,
    // Track seen inventory hashes to avoid re-requesting
    seen_inv: HashSet<[u8; 32]>,
    // Track missing objects for download retry
    missing_objects: HashMap<[u8; 32], MissingObject>,
    // Number of connection attempts in progress
    pending_connections: usize,
    // Timers
    last_reconnect: tokio::time::Instant,
    last_cleanup: tokio::time::Instant,
    last_retry_queued: tokio::time::Instant,
    last_stats: tokio::time::Instant,
    last_download_retry: tokio::time::Instant,
    // Stats
    pub objects_received: u64,
    pub objects_processed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    // Pending reprocess queue (periodically reloaded for unprocessed objects)
    reprocess_queue: Vec<(Vec<u8>, Vec<u8>)>, // (hash, payload)
    reprocess_decrypted: u32,
    last_reprocess_reload: tokio::time::Instant,
    // Track sent ACK hashes to prevent broadcasting duplicate ACKs
    sent_acks: HashSet<[u8; 32]>,
    // Consecutive connection failures for exponential backoff
    consecutive_failures: u32,
    // Peer reputation scores
    peer_scores: HashMap<String, PeerScore>,
}

struct MissingObject {
    requested_at: u64,
    from_peer: String,
}

struct PeerScore {
    successful_objects: u64,
    failed_requests: u64,
    last_seen: u64,
}

enum PeerIncoming {
    Message { from_addr: String, command: String, payload: Vec<u8> },
    Disconnected(String),
    NewConnection {
        info: PeerInfo,
        writer: PeerWriter,
    },
    ConnectionFailed(String),
}

impl PeerManager {
    pub fn new(
        cmd_rx: mpsc::Receiver<NetworkCommand>,
        event_tx: mpsc::Sender<NetworkEvent>,
        db: Arc<Mutex<Database>>,
    ) -> Self {
        let (peer_data_tx, peer_data_rx) = tokio::sync::mpsc::channel(4096);
        let now = tokio::time::Instant::now();
        Self {
            cmd_rx,
            event_tx,
            db,
            peers: Vec::new(),
            our_nonce: rand::random(),
            tor_client: None,
            peer_data_tx,
            peer_data_rx,
            seen_inv: HashSet::new(),
            missing_objects: HashMap::new(),
            pending_connections: 0,
            last_reconnect: now,
            last_cleanup: now,
            last_retry_queued: now,
            last_stats: now,
            last_download_retry: now,
            objects_received: 0,
            objects_processed: 0,
            bytes_sent: 0,
            bytes_received: 0,
            reprocess_queue: Vec::new(),
            reprocess_decrypted: 0,
            last_reprocess_reload: now,
            sent_acks: HashSet::new(),
            consecutive_failures: 0,
            peer_scores: HashMap::new(),
        }
    }

    fn update_peer_score(&mut self, addr: &str, success: bool) {
        let score = self.peer_scores.entry(addr.to_string()).or_insert(PeerScore {
            successful_objects: 0,
            failed_requests: 0,
            last_seen: unix_time(),
        });
        if success {
            score.successful_objects += 1;
        } else {
            score.failed_requests += 1;
        }
        score.last_seen = unix_time();
    }

    fn peer_score_value(&self, addr: &str) -> i64 {
        self.peer_scores.get(addr).map(|s| {
            s.successful_objects as i64 - s.failed_requests as i64 * 3
        }).unwrap_or(0)
    }

    /// Bootstrap the Tor client
    async fn bootstrap_tor() -> anyhow::Result<TorClient<PreferredRuntime>> {
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config).await?;
        Ok(client)
    }

    pub async fn run(&mut self) {
        self.send_event(NetworkEvent::StatusUpdate("Bootstrapping Tor...".into()));
        self.send_event(NetworkEvent::TorStatus {
            connected: false,
            bootstrap_pct: 0,
            message: "Initializing Tor...".into(),
        });

        match Self::bootstrap_tor().await {
            Ok(client) => {
                log::info!("Tor bootstrapped successfully");
                self.tor_client = Some(client);
                self.send_event(NetworkEvent::TorStatus {
                    connected: true,
                    bootstrap_pct: 100,
                    message: "Connected to Tor network".into(),
                });
            }
            Err(e) => {
                log::error!("Tor bootstrap failed: {e}");
                self.send_event(NetworkEvent::TorStatus {
                    connected: false,
                    bootstrap_pct: 0,
                    message: format!("Tor failed: {e}"),
                });
                self.send_event(NetworkEvent::Error(format!("Tor bootstrap failed: {e}")));
                // Cannot operate without Tor — keep trying
                loop {
                    self.send_event(NetworkEvent::StatusUpdate("Retrying Tor bootstrap in 30s...".into()));
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    match Self::bootstrap_tor().await {
                        Ok(client) => {
                            log::info!("Tor bootstrapped on retry");
                            self.tor_client = Some(client);
                            self.send_event(NetworkEvent::TorStatus {
                                connected: true,
                                bootstrap_pct: 100,
                                message: "Connected to Tor network".into(),
                            });
                            break;
                        }
                        Err(e) => {
                            log::error!("Tor retry failed: {e}");
                            self.send_event(NetworkEvent::TorStatus {
                                connected: false,
                                bootstrap_pct: 0,
                                message: format!("Tor retry failed: {e}"),
                            });
                        }
                    }
                }
            }
        }

        self.send_event(NetworkEvent::StatusUpdate("Starting network...".into()));
        self.bootstrap().await;

        // Load reprocess queue (non-blocking — actual processing happens in main loop batches)
        self.load_reprocess_queue();

        // Main loop — uses tokio::select! for responsive event handling
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Check for UI commands (non-blocking)
            match self.cmd_rx.try_recv() {
                Ok(NetworkCommand::Shutdown) => {
                    self.send_event(NetworkEvent::StatusUpdate("Shutting down...".into()));
                    break;
                }
                Ok(cmd) => self.handle_command(cmd).await,
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }

            tokio::select! {
                // Peer data has priority — handle immediately
                Some(incoming) = self.peer_data_rx.recv() => {
                    self.handle_incoming(incoming).await;
                    // Drain any additional queued messages without waiting
                    while let Ok(more) = self.peer_data_rx.try_recv() {
                        self.handle_incoming(more).await;
                    }
                }
                // Periodic tasks
                _ = tick.tick() => {
                    let now = tokio::time::Instant::now();

                    // Process reprocess queue in small batches (non-blocking)
                    self.process_reprocess_batch().await;

                    // Send stats to UI
                    if now.duration_since(self.last_stats) > STATS_INTERVAL {
                        self.last_stats = now;
                        let inv_count = if let Ok(db) = self.db.lock() {
                            db.inventory_count().unwrap_or(0)
                        } else {
                            0
                        };
                        self.send_event(NetworkEvent::StatsUpdate {
                            objects_received: self.objects_received,
                            objects_processed: self.objects_processed,
                            bytes_sent: self.bytes_sent,
                            bytes_received: self.bytes_received,
                            inventory_count: inv_count,
                        });
                    }

                    // Reconnection: actively maintain peer count
                    let base_interval = if self.peers.is_empty() && self.pending_connections == 0 {
                        Duration::from_secs(15)
                    } else if self.peers.len() < 3 {
                        Duration::from_secs(30)
                    } else {
                        RECONNECT_INTERVAL
                    };
                    // Exponential backoff: up to 5 min max
                    let backoff_factor = 2u64.pow(self.consecutive_failures.min(5));
                    let reconnect_interval = base_interval.mul_f64(backoff_factor as f64).min(Duration::from_secs(300));
                    if now.duration_since(self.last_reconnect) > reconnect_interval {
                        self.last_reconnect = now;
                        if self.peers.len() + self.pending_connections < MAX_PEERS {
                            self.try_reconnect().await;
                        }
                    }

                    // Cleanup: expire old inventory and pubkeys
                    if now.duration_since(self.last_cleanup) > CLEANUP_INTERVAL {
                        self.last_cleanup = now;
                        self.cleanup_expired();
                    }

                    // Retry queued messages
                    if now.duration_since(self.last_retry_queued) > RETRY_QUEUED_INTERVAL {
                        self.last_retry_queued = now;
                        self.retry_queued_messages().await;
                    }

                    // Retry timed-out downloads
                    if now.duration_since(self.last_download_retry) > DOWNLOAD_RETRY_INTERVAL {
                        self.last_download_retry = now;
                        self.retry_downloads().await;
                    }

                    // Periodically reload reprocess queue for any unprocessed objects
                    if self.reprocess_queue.is_empty()
                        && now.duration_since(self.last_reprocess_reload) > REPROCESS_RELOAD_INTERVAL
                    {
                        self.last_reprocess_reload = now;
                        self.load_reprocess_queue();
                    }
                }
            }
        }
    }

    async fn handle_incoming(&mut self, incoming: PeerIncoming) {
        match incoming {
            PeerIncoming::Message { from_addr, command, payload } => {
                self.bytes_received += payload.len() as u64;
                self.handle_peer_message(&from_addr, &command, &payload).await;
            }
            PeerIncoming::Disconnected(addr) => {
                self.peers.retain(|p| {
                    format!("{}:{}", p.info.address, p.info.port) != addr
                });
                let count = self.peers.len();
                self.send_event(NetworkEvent::PeerCountChanged(count));
                self.send_event(NetworkEvent::PeerDisconnected(addr));
            }
            PeerIncoming::NewConnection { info, writer } => {
                self.pending_connections = self.pending_connections.saturating_sub(1);
                self.consecutive_failures = 0;
                if self.peers.len() >= MAX_PEERS {
                    drop(writer);
                    return;
                }
                let addr = format!("{}:{}", info.address, info.port);
                if let Ok(db) = self.db.lock() {
                    let _ = db.upsert_known_node(
                        &info.address, info.port as i64, 1, info.services as i64,
                    );
                }
                self.peers.push(ConnectedPeer { info, writer });
                let count = self.peers.len();
                self.send_event(NetworkEvent::PeerConnected(addr.clone()));
                self.send_event(NetworkEvent::PeerCountChanged(count));
                self.send_event(NetworkEvent::StatusUpdate(
                    format!("Connected — {} peers via Tor", count),
                ));
                self.send_inv_to_peer(&addr).await;
            }
            PeerIncoming::ConnectionFailed(addr) => {
                self.pending_connections = self.pending_connections.saturating_sub(1);
                self.consecutive_failures += 1;
                self.update_peer_score(&addr, false);
                log::debug!("Connection attempt failed: {addr}");
            }
        }
    }

    /// Load unprocessed objects into reprocess queue (fast — just a DB read)
    fn load_reprocess_queue(&mut self) {
        let mut queue = Vec::new();
        if let Ok(db) = self.db.lock() {
            queue.extend(db.get_unprocessed_objects_by_type(object_type::MSG).unwrap_or_default());
            queue.extend(db.get_unprocessed_objects_by_type(object_type::BROADCAST).unwrap_or_default());
        }
        if !queue.is_empty() {
            log::info!("Loaded {} unprocessed objects for background reprocessing", queue.len());
            self.send_event(NetworkEvent::StatusUpdate(format!(
                "Processing {} stored objects...", queue.len()
            )));
        }
        self.reprocess_queue = queue;
        self.reprocess_decrypted = 0;
    }

    /// Process a small batch from the reprocess queue (non-blocking, interleaved with peer I/O)
    async fn process_reprocess_batch(&mut self) {
        const BATCH_SIZE: usize = 50;

        if self.reprocess_queue.is_empty() {
            return;
        }

        let batch: Vec<(Vec<u8>, Vec<u8>)> = self.reprocess_queue
            .drain(..BATCH_SIZE.min(self.reprocess_queue.len()))
            .collect();

        for (hash, data) in &batch {
            let mut cursor = std::io::Cursor::new(data.as_slice());
            let Ok(header) = ObjectHeader::decode(&mut cursor) else {
                if let Ok(db) = self.db.lock() { let _ = db.mark_object_processed(hash); }
                continue;
            };
            let pos = cursor.position() as usize;
            let object_payload = &data[pos..];
            let raw_header_for_signing = &data[8..pos];

            match header.object_type {
                object_type::MSG => {
                    if let Some(ack_data) = self.try_decrypt_message(&header, object_payload, raw_header_for_signing) {
                        self.reprocess_decrypted += 1;
                        let ack_inv = InventoryVector::from_object_data(&ack_data);
                        if !self.sent_acks.contains(&ack_inv.hash) {
                            if self.sent_acks.len() >= MAX_SENT_ACKS {
                                let to_keep: HashSet<[u8; 32]> = self.sent_acks.iter().skip(self.sent_acks.len() / 2).copied().collect();
                                self.sent_acks = to_keep;
                            }
                            self.sent_acks.insert(ack_inv.hash);
                            let ack_msg = encode_message("object", &ack_data);
                            self.broadcast_to_peers(&ack_msg).await;
                        }
                    }
                }
                object_type::BROADCAST => {
                    self.try_decrypt_broadcast(&header, object_payload, raw_header_for_signing);
                }
                _ => {}
            }
            if let Ok(db) = self.db.lock() { let _ = db.mark_object_processed(hash); }
        }

        if self.reprocess_queue.is_empty() {
            if self.reprocess_decrypted > 0 {
                log::info!("Reprocessing complete: decrypted {} messages", self.reprocess_decrypted);
                self.send_event(NetworkEvent::StatusUpdate(
                    format!("Found {} new messages", self.reprocess_decrypted)
                ));
            } else {
                log::info!("Reprocessing complete: no new messages found");
                self.send_event(NetworkEvent::StatusUpdate("Connected".into()));
            }
            self.reprocess_decrypted = 0;
        }
    }

    async fn bootstrap(&mut self) {
        self.send_event(NetworkEvent::StatusUpdate(
            "Connecting to bootstrap nodes...".into(),
        ));

        // Priority candidates: DNS seeds and hardcoded bootstrap nodes FIRST
        let mut priority: Vec<(String, u16)> = Vec::new();

        // DNS seeds — connect through Tor (hostname resolved by Tor, no clearnet DNS leak)
        for dns_seed in DNS_SEEDS {
            log::info!("Adding DNS seed (resolved via Tor): {dns_seed}");
            priority.push((dns_seed.to_string(), 8444));
        }

        // Hardcoded bootstrap nodes
        for &(host, port) in BOOTSTRAP_NODES {
            priority.push((host.to_string(), port));
        }

        // Then known nodes from DB (recently seen first, skip very old ones)
        let mut db_candidates: Vec<(String, u16)> = Vec::new();
        let cutoff = chrono::Utc::now().timestamp() - 3 * 24 * 3600; // only nodes seen in last 3 days
        if let Ok(db) = self.db.lock() {
            if let Ok(nodes) = db.get_known_nodes(1) {
                for node in nodes.iter().take(32) {
                    if node.last_seen > cutoff {
                        db_candidates.push((node.ip.clone(), node.port as u16));
                    }
                }
            }
        }

        // Merge: priority first, then DB candidates
        let mut candidates = priority;
        candidates.extend(db_candidates);

        // Dedup
        let mut seen = HashSet::new();
        candidates.retain(|(h, p)| seen.insert(format!("{h}:{p}")));

        log::info!("Bootstrap: {} candidate nodes", candidates.len());

        // Try more aggressively — up to 32 parallel connections
        let max_attempts = 32.min(candidates.len());
        for (host, port) in candidates.into_iter().take(max_attempts) {
            self.spawn_connection(host, port);
        }

        self.send_event(NetworkEvent::StatusUpdate(format!(
            "Connecting to {} nodes...", self.pending_connections
        )));
    }

    /// Try to reconnect to more peers when count drops (non-blocking)
    async fn try_reconnect(&mut self) {
        let connected_addrs: HashSet<String> = self.peers.iter()
            .map(|p| format!("{}:{}", p.info.address, p.info.port))
            .collect();

        let target = MAX_PEERS
            .saturating_sub(self.peers.len())
            .saturating_sub(self.pending_connections);
        if target == 0 {
            return;
        }
        let mut spawned = 0;

        // Always try DNS seeds and bootstrap nodes first
        for &(host, port) in BOOTSTRAP_NODES {
            if spawned >= target { break; }
            let addr = format!("{host}:{port}");
            if connected_addrs.contains(&addr) { continue; }
            self.spawn_connection(host.to_string(), port);
            spawned += 1;
        }

        // Then try recently-seen known nodes from DB, preferring higher-scored peers
        let cutoff = chrono::Utc::now().timestamp() - 3 * 24 * 3600;
        let mut nodes = if let Ok(db) = self.db.lock() {
            db.get_known_nodes(1).unwrap_or_default()
        } else {
            vec![]
        };

        // Sort by peer reputation score (highest first)
        nodes.sort_by(|a, b| {
            let addr_a = format!("{}:{}", a.ip, a.port);
            let addr_b = format!("{}:{}", b.ip, b.port);
            self.peer_score_value(&addr_b).cmp(&self.peer_score_value(&addr_a))
        });

        for node in nodes.iter().take(32) {
            if spawned >= target { break; }
            if node.last_seen < cutoff { continue; }
            let addr = format!("{}:{}", node.ip, node.port);
            if connected_addrs.contains(&addr) { continue; }
            self.spawn_connection(node.ip.clone(), node.port as u16);
            spawned += 1;
        }

        // If still nothing, try DNS seeds (resolved via Tor)
        if spawned == 0 {
            for dns_seed in DNS_SEEDS {
                if spawned >= target { break; }
                let addr = format!("{dns_seed}:8444");
                if connected_addrs.contains(&addr) { continue; }
                self.spawn_connection(dns_seed.to_string(), 8444);
                spawned += 1;
            }
        }
    }

    /// Cleanup expired inventory and pubkeys
    fn cleanup_expired(&self) {
        if let Ok(db) = self.db.lock() {
            let inv_deleted = db.cleanup_expired_inventory().unwrap_or(0);
            let pk_deleted = db.delete_expired_pubkeys().unwrap_or(0);
            let node_deleted = db.cleanup_old_nodes(3 * 24 * 3600).unwrap_or(0);
            if inv_deleted + pk_deleted + node_deleted > 0 {
                log::info!("Cleanup: {inv_deleted} inv, {pk_deleted} pubkeys, {node_deleted} nodes expired");
            }
        }
    }

    /// Retry sending queued messages (e.g., after pubkey arrives)
    async fn retry_queued_messages(&mut self) {
        let queued = if let Ok(db) = self.db.lock() {
            db.get_queued_messages().unwrap_or_default()
        } else {
            return;
        };

        for msg in queued {
            match msg.status.as_str() {
                "msgqueued" | "awaitingpubkey" => {
                    // Check if we now have the pubkey
                    if self.find_recipient_pubkey(&msg.to_address).is_some() {
                        self.prepare_and_send_message(
                            &msg.from_address,
                            &msg.to_address,
                            &msg.subject,
                            &msg.body,
                            Some(&msg.msgid),
                            None,
                        ).await;
                    } else {
                        log::debug!("Still awaiting pubkey for {}", msg.to_address);
                        self.send_event(NetworkEvent::StatusUpdate(format!(
                            "Awaiting pubkey for {}. Message queued.", msg.to_address
                        )));
                    }
                }
                "broadcastqueued" => {
                    self.prepare_and_send_broadcast(
                        &msg.from_address,
                        &msg.subject,
                        &msg.body,
                        Some(&msg.msgid),
                    ).await;
                }
                _ => {}
            }
        }
    }

    /// Send our inventory to a specific peer
    async fn send_inv_to_peer(&mut self, peer_addr: &str) {
        let hashes = if let Ok(db) = self.db.lock() {
            db.get_inventory_hashes(1).unwrap_or_default()
        } else {
            return;
        };

        if hashes.is_empty() {
            return;
        }

        let inventory: Vec<InventoryVector> = hashes
            .into_iter()
            .filter_map(|h| {
                if h.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&h);
                    Some(InventoryVector::new(arr))
                } else {
                    None
                }
            })
            .collect();

        // Send in batches of 50000
        for chunk in inventory.chunks(50000) {
            let inv = InvMessage {
                inventory: chunk.to_vec(),
            };
            let msg = inv.encode();
            self.send_to_peer(peer_addr, &msg).await;
        }
    }

    /// Spawn a non-blocking connection attempt
    fn spawn_connection(&mut self, host: String, port: u16) {
        let tor_client = match &self.tor_client {
            Some(c) => c.clone(),
            None => {
                log::warn!("Cannot connect without Tor client");
                return;
            }
        };
        self.pending_connections += 1;
        let tx = self.peer_data_tx.clone();
        let addr = format!("{host}:{port}");
        tokio::spawn(async move {
            log::info!("Connecting via Tor to {addr}...");
            let stream = match timeout(
                CONNECT_TIMEOUT,
                tor_client.connect((&*host, port)),
            ).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    log::info!("Tor connection refused by {addr}: {e}");
                    let _ = tx.send(PeerIncoming::ConnectionFailed(addr)).await;
                    return;
                }
                Err(_) => {
                    log::info!("Tor connection timed out to {addr}");
                    let _ = tx.send(PeerIncoming::ConnectionFailed(addr)).await;
                    return;
                }
            };

            match PeerManager::perform_handshake_tor(stream, &host, port).await {
                Ok((info, reader, writer, leftover)) => {
                    log::info!("Connected via Tor to {addr}: {}", info.user_agent);
                    let read_tx = tx.clone();
                    let peer_addr = addr.clone();
                    tokio::spawn(async move {
                        PeerManager::peer_read_loop_tor(reader, read_tx, peer_addr, leftover).await;
                    });
                    let _ = tx.send(PeerIncoming::NewConnection { info, writer: Box::new(writer) }).await;
                }
                Err(e) => {
                    log::info!("Handshake failed with {addr}: {e}");
                    let _ = tx.send(PeerIncoming::ConnectionFailed(addr)).await;
                }
            }
        });
    }

    /// Retry downloading objects that timed out
    async fn retry_downloads(&mut self) {
        let now = unix_time();
        let to_retry: Vec<([u8; 32], String)> = self.missing_objects.iter()
            .filter(|(_, obj)| now.saturating_sub(obj.requested_at) > REQUEST_TIMEOUT_SECS)
            .map(|(hash, obj)| (*hash, obj.from_peer.clone()))
            .collect();

        if to_retry.is_empty() || self.peers.is_empty() {
            return;
        }

        // Record failed score for the peers that timed out
        let failed_peers: HashSet<String> = to_retry.iter().map(|(_, p)| p.clone()).collect();
        for peer in &failed_peers {
            self.update_peer_score(peer, false);
        }

        // Sort peers by reputation score (highest first) for retry
        let mut peer_addrs: Vec<String> = self.peers.iter()
            .map(|p| format!("{}:{}", p.info.address, p.info.port))
            .collect();
        peer_addrs.sort_by(|a, b| self.peer_score_value(b).cmp(&self.peer_score_value(a)));

        let now_ts = unix_time();
        let mut requests_per_peer: HashMap<String, Vec<InventoryVector>> = HashMap::new();

        for (i, (hash, _)) in to_retry.iter().enumerate() {
            let peer = &peer_addrs[i % peer_addrs.len()];
            if let Some(obj) = self.missing_objects.get_mut(hash) {
                obj.requested_at = now_ts;
                obj.from_peer = peer.clone();
            }
            requests_per_peer.entry(peer.clone())
                .or_default()
                .push(InventoryVector::new(*hash));
        }

        for (peer_addr, inventory) in requests_per_peer {
            for chunk in inventory.chunks(1000) {
                let getdata = GetDataMessage { inventory: chunk.to_vec() };
                let msg = getdata.encode();
                self.send_to_peer(&peer_addr, &msg).await;
            }
        }

        log::debug!("Retried {} download requests", to_retry.len());
    }

    /// Perform handshake over a Tor DataStream
    async fn perform_handshake_tor(
        mut stream: arti_client::DataStream,
        host: &str,
        port: u16,
    ) -> anyhow::Result<(PeerInfo, Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box<dyn tokio::io::AsyncWrite + Unpin + Send>, Vec<u8>)> {
        let sock_addr = format!("{host}:{port}")
            .parse::<std::net::SocketAddr>()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], port)));
        let addr_recv = NetworkAddress::new(sock_addr, 1, services::NODE_NETWORK);

        let version_msg = VersionMessage::new(addr_recv);
        let encoded = version_msg.encode();
        stream.write_all(&encoded).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 65536];
        let mut total_read = 0;
        let mut _got_version = false;
        let mut got_verack = false;
        let mut peer_info = PeerInfo {
            address: host.to_string(),
            port,
            services: 0,
            user_agent: String::new(),
            streams: vec![],
            connected: false,
        };

        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

        while !got_verack {
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!("Handshake timeout");
            }

            let n = timeout(
                Duration::from_secs(15),
                stream.read(&mut buf[total_read..]),
            )
            .await??;

            if n == 0 {
                anyhow::bail!("Connection closed during handshake");
            }
            total_read += n;

            let mut pos = 0;
            while pos + HEADER_SIZE <= total_read {
                let header_data = &buf[pos..pos + HEADER_SIZE];
                let header = match MessageHeader::decode(&mut std::io::Cursor::new(header_data)) {
                    Ok(h) => h,
                    Err(_) => break,
                };

                let msg_end = pos + HEADER_SIZE + header.payload_len as usize;
                if msg_end > total_read {
                    break;
                }

                let payload = &buf[pos + HEADER_SIZE..msg_end];

                match header.command.as_str() {
                    "version" => {
                        if let Ok(ver) = VersionMessage::decode(payload) {
                            peer_info.services = ver.services;
                            peer_info.user_agent = ver.user_agent;
                            peer_info.streams = ver.streams;
                            _got_version = true;
                            stream.write_all(&encode_verack()).await?;
                            stream.flush().await?;
                        }
                    }
                    "verack" => {
                        got_verack = true;
                    }
                    _ => {}
                }

                pos = msg_end;
            }

            if pos > 0 {
                buf.copy_within(pos..total_read, 0);
                total_read -= pos;
            }
        }

        peer_info.connected = true;
        let leftover = buf[..total_read].to_vec();
        let (reader, writer) = stream.split();
        Ok((peer_info, Box::new(reader), Box::new(writer), leftover))
    }

    /// Read loop for Tor DataStream (reader half)
    async fn peer_read_loop_tor(
        mut reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        tx: tokio::sync::mpsc::Sender<PeerIncoming>,
        addr: String,
        leftover: Vec<u8>,
    ) {
        let mut buf = vec![0u8; 512 * 1024];
        let mut total_read = leftover.len();
        buf[..total_read].copy_from_slice(&leftover);

        loop {
            match timeout(Duration::from_secs(600), reader.read(&mut buf[total_read..])).await {
                Ok(Ok(0)) | Err(_) => {
                    let _ = tx.send(PeerIncoming::Disconnected(addr)).await;
                    return;
                }
                Ok(Ok(n)) => {
                    total_read += n;
                }
                Ok(Err(_)) => {
                    let _ = tx.send(PeerIncoming::Disconnected(addr)).await;
                    return;
                }
            }

            if total_read > buf.len() - 4096 {
                buf.resize(buf.len() + 256 * 1024, 0);
            }

            let mut pos = 0;
            while pos + HEADER_SIZE <= total_read {
                let header_data = &buf[pos..pos + HEADER_SIZE];
                let header = match MessageHeader::decode(&mut std::io::Cursor::new(header_data)) {
                    Ok(h) => h,
                    Err(_) => {
                        pos += 1;
                        continue;
                    }
                };

                let msg_end = pos + HEADER_SIZE + header.payload_len as usize;
                if msg_end > total_read {
                    break;
                }

                let payload = buf[pos + HEADER_SIZE..msg_end].to_vec();

                if header.verify_checksum(&payload) {
                    let _ = tx
                        .send(PeerIncoming::Message {
                            from_addr: addr.clone(),
                            command: header.command,
                            payload,
                        })
                        .await;
                }

                pos = msg_end;
            }

            if pos > 0 {
                buf.copy_within(pos..total_read, 0);
                total_read -= pos;
            }
        }
    }

    async fn handle_command(&mut self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::SendMessage {
                msgid,
                from_address,
                to_address,
                subject,
                body,
                attachment,
            } => {
                // Self-delivery: sender == recipient
                if from_address == to_address {
                    self.deliver_locally(&from_address, &to_address, &subject, &body);
                    if let Ok(db) = self.db.lock() {
                        let _ = db.update_message_status(&msgid, "msgsent");
                    }
                    return;
                }

                // Prepare and send message (pass msgid so status gets updated)
                self.prepare_and_send_message(&from_address, &to_address, &subject, &body, Some(&msgid), attachment)
                    .await;
            }
            NetworkCommand::SendBroadcast {
                msgid,
                from_address,
                subject,
                body,
            } => {
                self.prepare_and_send_broadcast(&from_address, &subject, &body, Some(&msgid))
                    .await;
            }
            NetworkCommand::RequestPubkey(ref addr_str) => {
                self.send_getpubkey_request(addr_str).await;
            }
            NetworkCommand::Shutdown => {}
        }
    }

    /// Deliver a message locally (sender == recipient)
    fn deliver_locally(&self, from: &str, to: &str, subject: &str, body: &str) {
        if let Ok(db) = self.db.lock() {
            let msgid = hex::encode(rand::random::<[u8; 16]>());
            let _ = db.insert_message(&msgid, from, to, subject, body, 2, "received", "inbox");
        }

        self.send_event(NetworkEvent::MessageReceived {
            from: from.to_string(),
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        });
        self.send_event(NetworkEvent::StatusUpdate(
            "Message delivered locally".into(),
        ));
    }

    /// Send a getpubkey request for an address
    async fn send_getpubkey_request(&mut self, addr_str: &str) {
        self.send_event(NetworkEvent::StatusUpdate(format!(
            "Requesting pubkey for {addr_str}..."
        )));

        let Ok(addr) = BitmessageAddress::decode(addr_str) else {
            self.send_event(NetworkEvent::Error("Invalid address for pubkey request".into()));
            return;
        };

        let getpubkey_payload = if addr.version >= 4 {
            let tag = addr.tag.unwrap_or_else(|| address::compute_tag(addr.version, addr.stream, &addr.ripe));
            GetPubKey::V4 { tag }.encode()
        } else {
            let mut ripe = [0u8; 20];
            if addr.ripe.len() == 20 {
                ripe.copy_from_slice(&addr.ripe);
            }
            GetPubKey::V3 { ripe }.encode()
        };

        let expires = unix_time() + DEFAULT_TTL;
        let obj_header = ObjectHeader {
            nonce: 0,
            expires_time: expires,
            object_type: object_type::GETPUBKEY,
            version: addr.version,
            stream_number: addr.stream,
        };

        let mut pow_payload = obj_header.encode_for_signing();
        pow_payload.extend_from_slice(&getpubkey_payload);

        // PoW
        let event_tx = self.event_tx.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let pow_result = tokio::task::spawn_blocking({
            let cancelled = cancelled.clone();
            move || {
                let target = pow::calculate_target(
                    (pow_payload.len() + 8) as u64,
                    DEFAULT_TTL,
                    pow::DEFAULT_NONCE_TRIALS_PER_BYTE,
                    pow::DEFAULT_EXTRA_BYTES,
                );
                let nonce = pow::do_pow_with_progress(&pow_payload, target, |n| {
                    let _ = event_tx.send(NetworkEvent::StatusUpdate(format!(
                        "Computing getpubkey PoW... ({n})"
                    )));
                }, cancelled);
                (nonce, pow_payload)
            }
        })
        .await;

        let Ok((nonce_opt, pow_payload)) = pow_result else {
            self.send_event(NetworkEvent::Error("Getpubkey PoW failed".into()));
            return;
        };
        let Some(nonce) = nonce_opt else {
            self.send_event(NetworkEvent::StatusUpdate("Getpubkey PoW cancelled".into()));
            return;
        };

        let mut full_object = nonce.to_be_bytes().to_vec();
        full_object.extend_from_slice(&pow_payload);

        // Store in inventory
        let inv_hash = InventoryVector::from_object_data(&full_object);
        if let Ok(db) = self.db.lock() {
            let _ = db.store_inventory(
                &inv_hash.hash,
                object_type::GETPUBKEY,
                addr.stream,
                &full_object,
                expires,
            );
        }

        let object_msg = encode_message("object", &full_object);
        self.broadcast_to_peers(&object_msg).await;

        self.send_event(NetworkEvent::StatusUpdate(format!(
            "Pubkey request sent for {addr_str}"
        )));
    }

    /// Reset message status to queued on failure
    fn reset_msg_status(&self, msgid: Option<&str>, status: &str) {
        if let Some(id) = msgid {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_status(id, status);
            }
        }
    }

    /// Prepare, encrypt, PoW, and send a message to the network
    async fn prepare_and_send_message(
        &mut self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
        existing_msgid: Option<&str>,
        attachment: Option<super::AttachmentData>,
    ) {
        self.send_event(NetworkEvent::StatusUpdate(format!(
            "Preparing message to {to}..."
        )));

        // Update status if existing message
        if let Some(msgid) = existing_msgid {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_status(msgid, "doingmsgpow");
            }
        }

        // Get sender identity
        let sender_identity = if let Ok(db) = self.db.lock() {
            db.get_identity_by_address(from).ok().flatten()
        } else {
            None
        };

        let Some(sender) = sender_identity else {
            self.send_event(NetworkEvent::Error("Sender identity not found".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        log::info!("Sender signing_key len={}, encryption_key len={} for {}",
            sender.signing_key.len(), sender.encryption_key.len(), from);
        let Ok(sender_keypair) =
            KeyPair::from_secrets(sender.signing_key.clone(), sender.encryption_key.clone())
        else {
            self.send_event(NetworkEvent::Error(format!(
                "Invalid sender keys (sign={} bytes, enc={} bytes) — keys may be encrypted, unlock in Settings",
                sender.signing_key.len(), sender.encryption_key.len()
            )));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        // Get recipient's pubkey and PoW requirements
        let recipient_info = self.find_recipient_pubkey(to);

        let Some((enc_key_bytes, rcpt_nonce_trials, rcpt_extra_bytes)) = recipient_info else {
            // No pubkey - request it and set status to awaitingpubkey
            if let Some(msgid) = existing_msgid {
                if let Ok(db) = self.db.lock() {
                    let _ = db.update_message_status(msgid, "awaitingpubkey");
                }
            }
            self.send_getpubkey_request(to).await;
            self.send_event(NetworkEvent::StatusUpdate(format!(
                "Awaiting pubkey for {to}. Message queued."
            )));
            return;
        };

        // Decode recipient address to get ripe
        let Ok(recipient_addr) = BitmessageAddress::decode(to) else {
            self.send_event(NetworkEvent::Error("Invalid recipient address".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        // Generate ACK object (complete object with PoW that recipient will broadcast)
        self.send_event(NetworkEvent::StatusUpdate("Generating ACK proof of work...".into()));
        let ack_stream = sender.stream_number as u64;
        let ack_expires = unix_time() + DEFAULT_TTL;
        let ack_random: [u8; 32] = rand::random();
        let ack_obj_header = ObjectHeader {
            nonce: 0,
            expires_time: ack_expires,
            object_type: object_type::MSG,
            version: 1,
            stream_number: ack_stream,
        };
        let mut ack_pow_payload = ack_obj_header.encode_for_signing();
        ack_pow_payload.extend_from_slice(&ack_random);

        let ack_event_tx = self.event_tx.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let ack_pow_result = tokio::task::spawn_blocking({
            let cancelled = cancelled.clone();
            move || {
                let target = pow::calculate_target(
                    (ack_pow_payload.len() + 8) as u64, DEFAULT_TTL,
                    pow::DEFAULT_NONCE_TRIALS_PER_BYTE, pow::DEFAULT_EXTRA_BYTES,
                );
                let nonce = pow::do_pow_with_progress(&ack_pow_payload, target, |n| {
                    let _ = ack_event_tx.send(NetworkEvent::StatusUpdate(
                        format!("ACK PoW... ({n})")
                    ));
                }, cancelled);
                (nonce, ack_pow_payload)
            }
        }).await;

        let Ok((ack_nonce_opt, ack_pow_payload)) = ack_pow_result else {
            self.send_event(NetworkEvent::Error("ACK PoW failed".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };
        let Some(ack_nonce) = ack_nonce_opt else {
            self.send_event(NetworkEvent::StatusUpdate("ACK PoW cancelled".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        let mut ack_full_object = ack_nonce.to_be_bytes().to_vec();
        ack_full_object.extend_from_slice(&ack_pow_payload);
        let ack_inv_hash = InventoryVector::from_object_data(&ack_full_object);

        // Build the unencrypted message — use extended encoding if attachment present
        let (message_data, encoding, file_chunks) = if let Some(ref att) = attachment {
            use crate::protocol::objects::{ExtendedMessage, MessagePart, split_file_into_chunks};
            use sha2::{Sha256, Digest as _};

            let file_hash: [u8; 32] = Sha256::digest(&att.data).into();
            let transfer_id: [u8; 16] = rand::random();
            let chunks = split_file_into_chunks(&att.data);
            let total_chunks = chunks.len() as u64;

            // Store attachment metadata in DB
            if let Ok(db) = self.db.lock() {
                let msg_db_id = if let Some(msgid) = existing_msgid {
                    db.get_message_by_msgid(msgid).map(|m| m.id).unwrap_or(0)
                } else { 0 };
                let _ = db.insert_attachment(
                    msg_db_id, &transfer_id, &att.filename, &att.mime_type,
                    att.data.len() as i64, &file_hash, total_chunks as i64,
                );
                // Store all chunks as sent
                for (i, chunk) in chunks.iter().enumerate() {
                    let _ = db.insert_attachment_chunk(&transfer_id, i as i64, chunk);
                }
                let _ = db.update_attachment_status(&transfer_id, "verified");
            }

            // First message: TextPart + FileManifest (with first chunk)
            let parts = vec![
                MessagePart::Text { subject: subject.to_string(), body: body.to_string() },
                MessagePart::FileManifest {
                    transfer_id,
                    filename: att.filename.clone(),
                    mime_type: att.mime_type.clone(),
                    total_size: att.data.len() as u64,
                    sha256_hash: file_hash,
                    total_chunks,
                    chunk_index: 0,
                    chunk_data: chunks.first().cloned().unwrap_or_default(),
                },
            ];
            let ext_msg = ExtendedMessage { parts };
            let data = ext_msg.encode();

            // Remaining chunks (will be sent as separate MSG objects)
            let remaining: Vec<(u64, Vec<u8>)> = chunks.into_iter()
                .enumerate()
                .skip(1)
                .map(|(i, c)| {
                    let chunk_msg = ExtendedMessage {
                        parts: vec![MessagePart::FileChunk {
                            transfer_id,
                            chunk_index: i as u64,
                            chunk_data: c,
                        }],
                    };
                    (i as u64, chunk_msg.encode())
                })
                .collect();

            log::info!("File attachment: {} ({} bytes, {} chunks)", att.filename, att.data.len(), total_chunks);
            (data, 3u64, remaining)
        } else {
            (encode_simple_message(subject, body), 2u64, vec![])
        };

        let mut dest_ripe = [0u8; 20];
        dest_ripe.copy_from_slice(&recipient_addr.ripe);

        let unenc = UnencryptedMessage {
            sender_address_version: sender.address_version as u64,
            sender_stream: sender.stream_number as u64,
            behavior_bitfield: bitfield::DOES_ACK | bitfield::INCLUDE_DESTINATION,
            public_signing_key: {
                let mut k = [0u8; 64];
                k.copy_from_slice(&sender.pub_signing_key);
                k
            },
            public_encryption_key: {
                let mut k = [0u8; 64];
                k.copy_from_slice(&sender.pub_encryption_key);
                k
            },
            nonce_trials_per_byte: sender.nonce_trials as u64,
            extra_bytes: sender.extra_bytes as u64,
            destination_ripe: Some(dest_ripe),
            encoding,
            message: message_data,
            ack_data: ack_full_object,
            signature: vec![],
        };

        // Encode message (without signature first, for signing)
        let unsigned_data = unenc.encode_msg();

        // Build data to sign: object header fields + unsigned message
        let expires = unix_time() + DEFAULT_TTL;
        let obj_header = ObjectHeader {
            nonce: 0,
            expires_time: expires,
            object_type: object_type::MSG,
            version: 1,
            stream_number: sender.stream_number as u64,
        };
        let header_for_signing = obj_header.encode_for_signing();

        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&header_for_signing);
        sign_data.extend_from_slice(&unsigned_data);

        // Sign
        let Ok(signature) = sender_keypair.sign(&sign_data) else {
            self.send_event(NetworkEvent::Error("Signing failed".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        // Build final payload: unsigned_data + sig_len + signature
        let mut msg_payload = unsigned_data;
        msg_payload.extend(encode_varint(signature.len() as u64));
        msg_payload.extend_from_slice(&signature);

        // Encrypt with recipient's public key
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..65].copy_from_slice(&enc_key_bytes);
        let Ok(recipient_pk) = k256::PublicKey::from_sec1_bytes(&uncompressed) else {
            self.send_event(NetworkEvent::Error(
                "Invalid recipient public key".into(),
            ));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        let Ok(encrypted) = ecies::encrypt(&recipient_pk, &msg_payload) else {
            self.send_event(NetworkEvent::Error("Encryption failed".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        // Now do PoW (CPU-bound, use spawn_blocking)
        self.send_event(NetworkEvent::StatusUpdate(
            "Computing proof of work...".into(),
        ));

        // Build the object payload (without nonce) for PoW
        let mut pow_payload = obj_header.encode_for_signing();
        pow_payload.extend_from_slice(&encrypted);

        let event_tx = self.event_tx.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let pow_result = tokio::task::spawn_blocking({
            let cancelled = cancelled.clone();
            move || {
                // Use recipient's advertised PoW difficulty (at least the default)
                let target = pow::calculate_target(
                    (pow_payload.len() + 8) as u64,
                    DEFAULT_TTL,
                    rcpt_nonce_trials,
                    rcpt_extra_bytes,
                );
                let nonce = pow::do_pow_with_progress(&pow_payload, target, |n| {
                    let _ = event_tx.send(NetworkEvent::StatusUpdate(format!(
                        "Computing PoW... ({n} attempts)"
                    )));
                }, cancelled);
                (nonce, pow_payload)
            }
        })
        .await;

        let Ok((nonce_opt, pow_payload)) = pow_result else {
            self.send_event(NetworkEvent::Error("PoW computation failed".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };
        let Some(nonce) = nonce_opt else {
            self.send_event(NetworkEvent::StatusUpdate("PoW cancelled".into()));
            self.reset_msg_status(existing_msgid, "msgqueued");
            return;
        };

        // Build the complete object
        let mut full_object = nonce.to_be_bytes().to_vec();
        full_object.extend_from_slice(&pow_payload);

        // Store in inventory
        let inv_hash = InventoryVector::from_object_data(&full_object);
        if let Ok(db) = self.db.lock() {
            let _ = db.store_inventory(
                &inv_hash.hash,
                object_type::MSG,
                sender.stream_number as u64,
                &full_object,
                expires,
            );
        }

        // Send to all connected peers as "object" message
        let object_msg = encode_message("object", &full_object);
        self.broadcast_to_peers(&object_msg).await;

        // Update message status and store ACK hash for tracking
        if let Some(msgid) = existing_msgid {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_status(msgid, "msgsent");
                let _ = db.update_message_ack(msgid, &[], &ack_inv_hash.to_hex());
            }
        }
        self.send_event(NetworkEvent::StatusUpdate("Message sent!".into()));

        // Send remaining file chunks as separate MSG objects (sequential PoW)
        if !file_chunks.is_empty() {
            let total = file_chunks.len() + 1; // +1 for manifest already sent
            for (chunk_idx, chunk_message_data) in &file_chunks {
                let att_filename = attachment.as_ref().map(|a| a.filename.clone()).unwrap_or_default();
                self.send_event(NetworkEvent::StatusUpdate(
                    format!("Sending file chunk {}/{total}: {att_filename}...", chunk_idx + 1)
                ));

                // Build a new MSG object for this chunk
                let chunk_unenc = UnencryptedMessage {
                    sender_address_version: sender.address_version as u64,
                    sender_stream: sender.stream_number as u64,
                    behavior_bitfield: bitfield::DOES_ACK | bitfield::INCLUDE_DESTINATION,
                    public_signing_key: {
                        let mut k = [0u8; 64];
                        k.copy_from_slice(&sender.pub_signing_key);
                        k
                    },
                    public_encryption_key: {
                        let mut k = [0u8; 64];
                        k.copy_from_slice(&sender.pub_encryption_key);
                        k
                    },
                    nonce_trials_per_byte: sender.nonce_trials as u64,
                    extra_bytes: sender.extra_bytes as u64,
                    destination_ripe: Some(dest_ripe),
                    encoding: 3,
                    message: chunk_message_data.clone(),
                    ack_data: vec![], // No ACK for chunk objects
                    signature: vec![],
                };

                let chunk_unsigned = chunk_unenc.encode_msg();
                let chunk_expires = unix_time() + DEFAULT_TTL;
                let chunk_obj_header = ObjectHeader {
                    nonce: 0,
                    expires_time: chunk_expires,
                    object_type: object_type::MSG,
                    version: 1,
                    stream_number: sender.stream_number as u64,
                };
                let chunk_header_for_signing = chunk_obj_header.encode_for_signing();

                let mut chunk_sign_data = Vec::new();
                chunk_sign_data.extend_from_slice(&chunk_header_for_signing);
                chunk_sign_data.extend_from_slice(&chunk_unsigned);

                let Ok(chunk_sig) = sender_keypair.sign(&chunk_sign_data) else {
                    log::warn!("Failed to sign file chunk {chunk_idx}");
                    continue;
                };

                let mut chunk_payload = chunk_unsigned;
                chunk_payload.extend(encode_varint(chunk_sig.len() as u64));
                chunk_payload.extend_from_slice(&chunk_sig);

                let Ok(chunk_encrypted) = ecies::encrypt(&recipient_pk, &chunk_payload) else {
                    log::warn!("Failed to encrypt file chunk {chunk_idx}");
                    continue;
                };

                let mut chunk_pow_payload = chunk_obj_header.encode_for_signing();
                chunk_pow_payload.extend_from_slice(&chunk_encrypted);

                let chunk_event_tx = self.event_tx.clone();
                let cancelled = Arc::new(AtomicBool::new(false));
                let chunk_pow = tokio::task::spawn_blocking({
                    let cancelled = cancelled.clone();
                    move || {
                        let target = pow::calculate_target(
                            (chunk_pow_payload.len() + 8) as u64, DEFAULT_TTL,
                            rcpt_nonce_trials, rcpt_extra_bytes,
                        );
                        let nonce = pow::do_pow_with_progress(&chunk_pow_payload, target, |n| {
                            let _ = chunk_event_tx.send(NetworkEvent::StatusUpdate(
                                format!("File chunk PoW... ({n})")
                            ));
                        }, cancelled);
                        (nonce, chunk_pow_payload)
                    }
                }).await;

                let Ok((chunk_nonce_opt, chunk_pow_payload)) = chunk_pow else {
                    log::warn!("PoW failed for file chunk {chunk_idx}");
                    continue;
                };
                let Some(chunk_nonce) = chunk_nonce_opt else {
                    log::warn!("PoW cancelled for file chunk {chunk_idx}");
                    continue;
                };

                let mut chunk_full = chunk_nonce.to_be_bytes().to_vec();
                chunk_full.extend_from_slice(&chunk_pow_payload);

                let chunk_inv = InventoryVector::from_object_data(&chunk_full);
                if let Ok(db) = self.db.lock() {
                    let _ = db.store_inventory(
                        &chunk_inv.hash, object_type::MSG,
                        sender.stream_number as u64, &chunk_full, chunk_expires,
                    );
                    let _ = db.mark_object_processed(&chunk_inv.hash);
                }

                let chunk_obj_msg = encode_message("object", &chunk_full);
                self.broadcast_to_peers(&chunk_obj_msg).await;
            }

            self.send_event(NetworkEvent::StatusUpdate(
                format!("File sent ({total} chunks)!")
            ));
        }

        // Try to decrypt our own message in case recipient is also our identity
        {
            let mut cursor = std::io::Cursor::new(full_object.as_slice());
            if let Ok(header) = ObjectHeader::decode(&mut cursor) {
                let pos = cursor.position() as usize;
                let object_payload = &full_object[pos..];
                let raw_header_for_signing = &full_object[8..pos];
                if let Some(ack_data) = self.try_decrypt_message(&header, object_payload, raw_header_for_signing) {
                    let ack_inv = InventoryVector::from_object_data(&ack_data);
                    if !self.sent_acks.contains(&ack_inv.hash) {
                        if self.sent_acks.len() >= MAX_SENT_ACKS {
                            let to_keep: HashSet<[u8; 32]> = self.sent_acks.iter().skip(self.sent_acks.len() / 2).copied().collect();
                            self.sent_acks = to_keep;
                        }
                        self.sent_acks.insert(ack_inv.hash);
                        let ack_msg = encode_message("object", &ack_data);
                        self.broadcast_to_peers(&ack_msg).await;
                    }
                }
            }
        }
        // Mark as processed
        if let Ok(db) = self.db.lock() {
            let _ = db.mark_object_processed(&inv_hash.hash);
        }
    }

    /// Prepare and send a broadcast
    async fn prepare_and_send_broadcast(
        &mut self,
        from: &str,
        subject: &str,
        body: &str,
        existing_msgid: Option<&str>,
    ) {
        self.send_event(NetworkEvent::StatusUpdate(
            "Preparing broadcast...".into(),
        ));

        if let Some(msgid) = existing_msgid {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_status(msgid, "doingbroadcastpow");
            }
        }

        let sender_identity = if let Ok(db) = self.db.lock() {
            db.get_identity_by_address(from).ok().flatten()
        } else {
            None
        };

        let Some(sender) = sender_identity else {
            self.send_event(NetworkEvent::Error("Sender identity not found".into()));
            self.reset_msg_status(existing_msgid, "broadcastqueued");
            return;
        };

        let Ok(sender_keypair) =
            KeyPair::from_secrets(sender.signing_key.clone(), sender.encryption_key.clone())
        else {
            self.send_event(NetworkEvent::Error("Invalid sender keys".into()));
            self.reset_msg_status(existing_msgid, "broadcastqueued");
            return;
        };

        let message_data = encode_simple_message(subject, body);

        let unenc = UnencryptedMessage {
            sender_address_version: sender.address_version as u64,
            sender_stream: sender.stream_number as u64,
            behavior_bitfield: bitfield::DOES_ACK,
            public_signing_key: {
                let mut k = [0u8; 64];
                k.copy_from_slice(&sender.pub_signing_key);
                k
            },
            public_encryption_key: {
                let mut k = [0u8; 64];
                k.copy_from_slice(&sender.pub_encryption_key);
                k
            },
            nonce_trials_per_byte: sender.nonce_trials as u64,
            extra_bytes: sender.extra_bytes as u64,
            destination_ripe: None,
            encoding: 2,
            message: message_data,
            ack_data: vec![],
            signature: vec![],
        };

        let unsigned_data = unenc.encode_broadcast();

        let expires = unix_time() + DEFAULT_TTL;
        let obj_header = ObjectHeader {
            nonce: 0,
            expires_time: expires,
            object_type: object_type::BROADCAST,
            version: if sender.address_version >= 4 { 5 } else { 4 },
            stream_number: sender.stream_number as u64,
        };

        // Compute address encryption key and tag (needed for signing v5 and encryption)
        let Ok(sender_addr) = BitmessageAddress::decode(from) else {
            self.send_event(NetworkEvent::Error("Invalid sender address".into()));
            self.reset_msg_status(existing_msgid, "broadcastqueued");
            return;
        };

        let (enc_key_bytes, tag) = address::compute_address_encryption_key(
            sender.address_version as u64,
            sender.stream_number as u64,
            &sender_addr.ripe,
        );

        // Sign: for v5 broadcast, tag is part of sign_data (between header and payload)
        let header_for_signing = obj_header.encode_for_signing();
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&header_for_signing);
        if sender.address_version >= 4 {
            sign_data.extend_from_slice(&tag);
        }
        sign_data.extend_from_slice(&unsigned_data);

        let Ok(signature) = sender_keypair.sign(&sign_data) else {
            self.send_event(NetworkEvent::Error("Signing failed".into()));
            self.reset_msg_status(existing_msgid, "broadcastqueued");
            return;
        };

        let mut broadcast_payload = unsigned_data;
        broadcast_payload.extend(encode_varint(signature.len() as u64));
        broadcast_payload.extend_from_slice(&signature);

        // Encrypt broadcast with address-derived key (both v4 and v5 are encrypted)
        let final_payload = {
            if let Ok(enc_sk) = k256::SecretKey::from_slice(&enc_key_bytes) {
                let enc_pk = enc_sk.public_key();
                match ecies::encrypt(&enc_pk, &broadcast_payload) {
                    Ok(encrypted) => {
                        if sender.address_version >= 4 {
                            // V5 broadcast: tag + encrypted
                            let mut payload = tag.to_vec();
                            payload.extend_from_slice(&encrypted);
                            payload
                        } else {
                            // V4 broadcast: just encrypted (no tag prefix)
                            encrypted
                        }
                    }
                    Err(e) => {
                        self.send_event(NetworkEvent::Error(format!("Broadcast encryption failed: {e}")));
                        self.reset_msg_status(existing_msgid, "broadcastqueued");
                        return;
                    }
                }
            } else {
                self.send_event(NetworkEvent::Error("Invalid broadcast encryption key".into()));
                self.reset_msg_status(existing_msgid, "broadcastqueued");
                return;
            }
        };

        // PoW
        self.send_event(NetworkEvent::StatusUpdate(
            "Computing broadcast PoW...".into(),
        ));

        let mut pow_payload = obj_header.encode_for_signing();
        pow_payload.extend_from_slice(&final_payload);

        let event_tx = self.event_tx.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let pow_result = tokio::task::spawn_blocking({
            let cancelled = cancelled.clone();
            move || {
                let target = pow::calculate_target(
                    (pow_payload.len() + 8) as u64,
                    DEFAULT_TTL,
                    pow::DEFAULT_NONCE_TRIALS_PER_BYTE,
                    pow::DEFAULT_EXTRA_BYTES,
                );
                let nonce = pow::do_pow_with_progress(&pow_payload, target, |n| {
                    let _ = event_tx.send(NetworkEvent::StatusUpdate(format!(
                        "Computing broadcast PoW... ({n} attempts)"
                    )));
                }, cancelled);
                (nonce, pow_payload)
            }
        })
        .await;

        let Ok((nonce_opt, pow_payload)) = pow_result else {
            self.send_event(NetworkEvent::Error("Broadcast PoW failed".into()));
            self.reset_msg_status(existing_msgid, "broadcastqueued");
            return;
        };
        let Some(nonce) = nonce_opt else {
            self.send_event(NetworkEvent::StatusUpdate("Broadcast PoW cancelled".into()));
            self.reset_msg_status(existing_msgid, "broadcastqueued");
            return;
        };

        let mut full_object = nonce.to_be_bytes().to_vec();
        full_object.extend_from_slice(&pow_payload);

        // Store in inventory
        let inv_hash = InventoryVector::from_object_data(&full_object);
        if let Ok(db) = self.db.lock() {
            let _ = db.store_inventory(
                &inv_hash.hash,
                object_type::BROADCAST,
                sender.stream_number as u64,
                &full_object,
                expires,
            );
        }

        let object_msg = encode_message("object", &full_object);
        self.broadcast_to_peers(&object_msg).await;

        if let Some(msgid) = existing_msgid {
            if let Ok(db) = self.db.lock() {
                let _ = db.update_message_status(msgid, "broadcastsent");
            }
        }
        self.send_event(NetworkEvent::StatusUpdate("Broadcast sent!".into()));
    }

    /// Find a recipient's public encryption key (64 bytes, no prefix)
    /// Find encryption key and PoW requirements for a recipient.
    /// Returns (encryption_key, nonce_trials_per_byte, extra_bytes).
    fn find_recipient_pubkey(&self, addr_str: &str) -> Option<(Vec<u8>, u64, u64)> {
        let db = self.db.lock().ok()?;

        // Check identities (local addresses)
        if let Ok(Some(identity)) = db.get_identity_by_address(addr_str) {
            return Some((
                identity.pub_encryption_key,
                identity.nonce_trials as u64,
                identity.extra_bytes as u64,
            ));
        }

        // Check pubkeys table (includes PoW difficulty)
        if let Ok(Some((_, encryption, nonce_trials, extra_bytes))) = db.get_pubkey_full(addr_str) {
            return Some((
                encryption,
                (nonce_trials as u64).max(pow::DEFAULT_NONCE_TRIALS_PER_BYTE),
                (extra_bytes as u64).max(pow::DEFAULT_EXTRA_BYTES),
            ));
        }

        // Check contacts
        if let Ok(contacts) = db.get_contacts() {
            if let Some(c) = contacts.iter().find(|c| c.address == addr_str) {
                if let Some(ref enc_key) = c.pub_encryption_key {
                    return Some((enc_key.clone(), pow::DEFAULT_NONCE_TRIALS_PER_BYTE, pow::DEFAULT_EXTRA_BYTES));
                }
            }
        }

        None
    }

    /// Handle incoming protocol messages from peers
    async fn handle_peer_message(&mut self, from_addr: &str, command: &str, payload: &[u8]) {
        match command {
            "inv" => {
                if let Ok(inv) = InvMessage::decode(payload) {
                    log::info!("Received inv with {} items from {}", inv.inventory.len(), from_addr);

                    // Pre-filter with in-memory sets
                    let mut to_check: Vec<[u8; 32]> = Vec::new();
                    for iv in &inv.inventory {
                        if !self.seen_inv.contains(&iv.hash) && !self.missing_objects.contains_key(&iv.hash) {
                            to_check.push(iv.hash);
                        }
                    }

                    // Batch DB lookup — single lock, single query per 500 hashes
                    let existing = if !to_check.is_empty() {
                        if let Ok(db) = self.db.lock() {
                            db.has_inventory_batch(&to_check)
                        } else {
                            std::collections::HashSet::new()
                        }
                    } else {
                        std::collections::HashSet::new()
                    };

                    let now_ts = unix_time();
                    let mut needed = Vec::new();

                    // Evict half of seen_inv if at capacity to avoid frequent evictions
                    if self.seen_inv.len() >= MAX_SEEN_INV {
                        let to_keep: HashSet<[u8; 32]> = self.seen_inv.iter().skip(self.seen_inv.len() / 2).copied().collect();
                        self.seen_inv = to_keep;
                    }

                    for hash in &to_check {
                        if existing.contains(hash) {
                            self.seen_inv.insert(*hash);
                            continue;
                        }
                        needed.push(InventoryVector::new(*hash));
                        self.seen_inv.insert(*hash);

                        // Evict oldest missing_objects entries if at capacity
                        if self.missing_objects.len() >= MAX_MISSING_OBJECTS {
                            let cutoff = self.missing_objects.values().map(|v| v.requested_at).min().unwrap_or(0) + 60;
                            self.missing_objects.retain(|_, v| v.requested_at > cutoff);
                        }
                        self.missing_objects.insert(*hash, MissingObject {
                            requested_at: now_ts,
                            from_peer: from_addr.to_string(),
                        });
                    }

                    if !needed.is_empty() {
                        log::info!("Requesting {} objects from {}", needed.len(), from_addr);
                    }
                    // Send getdata in batches of 1000
                    for chunk in needed.chunks(1000) {
                        let getdata = GetDataMessage { inventory: chunk.to_vec() };
                        let msg = getdata.encode();
                        self.send_to_peer(from_addr, &msg).await;
                    }
                }
            }
            "getdata" => {
                // Respond with objects from our inventory
                if let Ok(getdata) = GetDataMessage::decode(payload) {
                    // Collect all objects first, then send
                    let mut objects_to_send = Vec::new();
                    for iv in &getdata.inventory {
                        if let Ok(db) = self.db.lock() {
                            if let Ok(Some(obj_data)) = db.get_inventory_object(&iv.hash) {
                                objects_to_send.push(encode_message("object", &obj_data));
                            }
                        }
                    }
                    for msg in objects_to_send {
                        self.send_to_peer(from_addr, &msg).await;
                    }
                }
            }
            "object" => {
                self.objects_received += 1;
                log::info!("Received object ({} bytes) from {}", payload.len(), from_addr);
                let inv_hash = InventoryVector::from_object_data(payload);
                self.missing_objects.remove(&inv_hash.hash);
                self.update_peer_score(from_addr, true);
                self.handle_object(payload).await;
            }
            "addr" => {
                // Store received addresses as known nodes
                if let Ok(addr_msg) = AddrMessage::decode(payload) {
                    if let Ok(db) = self.db.lock() {
                        for na in &addr_msg.addresses {
                            // Extract IPv4 from IPv6-mapped address
                            let ip = if na.ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                                format!("{}.{}.{}.{}", na.ip[12], na.ip[13], na.ip[14], na.ip[15])
                            } else {
                                // Skip non-IPv4 for now
                                continue;
                            };
                            let _ = db.upsert_known_node(&ip, na.port as i64, na.stream as i64, na.services as i64);
                        }
                    }
                }
            }
            "ping" => {
                let pong = encode_pong();
                self.send_to_peer(from_addr, &pong).await;
            }
            "error" => {
                if let Ok(err) = ErrorMessage::decode(payload) {
                    log::warn!("Peer {from_addr} error: {}", err.error_text);
                    self.send_event(NetworkEvent::Error(format!(
                        "Peer error: {}", err.error_text
                    )));
                }
            }
            _ => {
                log::debug!("Unknown command from {from_addr}: {command}");
            }
        }
    }

    /// Handle a received object - try to decrypt if it's a message for us
    async fn handle_object(&mut self, data: &[u8]) {
        let mut cursor = std::io::Cursor::new(data);
        let Ok(header) = ObjectHeader::decode(&mut cursor) else {
            return;
        };

        // Validate expiration
        let now = unix_time();
        if header.expires_time < now {
            return; // Expired object
        }
        if header.expires_time > now + MAX_TTL {
            return; // Too far in future
        }

        // PoW validation
        let target = pow::calculate_target(
            data.len() as u64,
            header.expires_time.saturating_sub(now).max(300),
            pow::DEFAULT_NONCE_TRIALS_PER_BYTE,
            pow::DEFAULT_EXTRA_BYTES,
        );
        if !pow::check_pow(data, target) {
            log::debug!("Object failed PoW check");
            // Don't reject - some objects may have different PoW requirements
        }

        // Store in inventory and check state (dedup + processed check)
        let inv_hash = InventoryVector::from_object_data(data);
        let (is_new, already_processed) = if let Ok(db) = self.db.lock() {
            if db.has_inventory(&inv_hash.hash) {
                // Already in inventory — check if it was processed
                (false, db.is_inventory_processed(&inv_hash.hash))
            } else {
                let _ = db.store_inventory(
                    &inv_hash.hash,
                    header.object_type,
                    header.stream_number,
                    data,
                    header.expires_time,
                );
                // Check if this object is an ACK for one of our sent messages
                if db.check_ack_received(&inv_hash.to_hex()) {
                    log::info!("ACK received for sent message (hash: {})", inv_hash.to_hex());
                    self.send_event(NetworkEvent::StatusUpdate(
                        "Message delivery confirmed (ACK received)".into(),
                    ));
                }
                (true, false)
            }
        } else {
            // DB lock failed — still try to process (don't skip)
            (false, false)
        };

        // Relay to peers only if new
        if is_new {
            let object_msg = encode_message("object", data);
            self.broadcast_to_peers(&object_msg).await;
        }

        // Skip only if already successfully processed
        if already_processed {
            return;
        }

        self.objects_processed += 1;

        let pos = cursor.position() as usize;
        let object_payload = &data[pos..];
        // Raw header bytes for signing: skip 8-byte nonce, keep everything up to payload
        let raw_header_for_signing = &data[8..pos];

        log::debug!("Processing object type={} version={} stream={} ({} bytes payload)",
            header.object_type, header.version, header.stream_number, object_payload.len());

        match header.object_type {
            object_type::MSG => {
                if let Some(ack_data) = self.try_decrypt_message(&header, object_payload, raw_header_for_signing) {
                    // Broadcast the ACK object to confirm delivery (with deduplication)
                    let ack_hash = InventoryVector::from_object_data(&ack_data);
                    if !self.sent_acks.contains(&ack_hash.hash) {
                        if self.sent_acks.len() >= MAX_SENT_ACKS {
                            let to_keep: HashSet<[u8; 32]> = self.sent_acks.iter().skip(self.sent_acks.len() / 2).copied().collect();
                            self.sent_acks = to_keep;
                        }
                        self.sent_acks.insert(ack_hash.hash);
                        let ack_msg = encode_message("object", &ack_data);
                        self.broadcast_to_peers(&ack_msg).await;
                    }
                    // Also store ACK in our inventory
                    if let Ok(db) = self.db.lock() {
                        let _ = db.store_inventory(
                            &ack_hash.hash, object_type::MSG, header.stream_number,
                            &ack_data, unix_time() + DEFAULT_TTL,
                        );
                    }
                }
            }
            object_type::PUBKEY => {
                self.handle_pubkey_object(&header, object_payload, raw_header_for_signing);
            }
            object_type::BROADCAST => {
                log::info!("Processing broadcast object (version={}, {} bytes)", header.version, object_payload.len());
                self.try_decrypt_broadcast(&header, object_payload, raw_header_for_signing);
            }
            object_type::GETPUBKEY => {
                if let Some(identity) = self.match_getpubkey(&header, object_payload) {
                    self.send_pubkey_response(&identity).await;
                }
            }
            _ => {
                log::debug!("Unknown object type: {}", header.object_type);
            }
        }

        // Mark as processed so reprocess won't retry it
        if let Ok(db) = self.db.lock() {
            let _ = db.mark_object_processed(&inv_hash.hash);
        }
    }

    /// Handle incoming pubkey object - decode and store
    fn handle_pubkey_object(&self, header: &ObjectHeader, data: &[u8], raw_header_for_signing: &[u8]) {
        log::info!("Received pubkey object (version {})", header.version);

        match header.version {
            2 => {
                if let Ok(pk) = PubKeyData::decode_v2(data) {
                    let ripe = address::compute_ripe(&pk.public_signing_key, &pk.public_encryption_key);
                    let addr = address::encode_address(2, header.stream_number, &ripe);
                    self.store_received_pubkey(&addr, &pk, header.expires_time as i64);
                }
            }
            3 => {
                if let Ok((pk, sig_offset)) = PubKeyData::decode_v3(data) {
                    // Verify signature using raw wire bytes
                    let mut sign_data = Vec::new();
                    sign_data.extend_from_slice(raw_header_for_signing);
                    sign_data.extend_from_slice(&data[..sig_offset]);

                    match crate::crypto::keys::verify_signature(
                        &pk.public_signing_key, &sign_data, &pk.signature,
                    ) {
                        Ok(true) => {
                            log::info!("V3 pubkey signature verified OK");
                        }
                        Ok(false) => {
                            log::warn!("V3 pubkey signature FAILED (sign_data len={}, sig len={})", sign_data.len(), pk.signature.len());
                            return;
                        }
                        Err(e) => {
                            log::warn!("V3 pubkey signature error: {e}");
                            return;
                        }
                    }

                    let ripe = address::compute_ripe(&pk.public_signing_key, &pk.public_encryption_key);
                    let addr = address::encode_address(3, header.stream_number, &ripe);
                    log::info!("Storing v3 pubkey for {addr}");
                    self.store_received_pubkey(&addr, &pk, header.expires_time as i64);
                }
            }
            4 => {
                // V4 pubkey: tag (32 bytes) + encrypted data
                if let Ok(v4pk) = PubKeyV4::decode(data) {
                    // Try to decrypt with addresses we're interested in
                    self.try_decrypt_v4_pubkey(&v4pk, header, raw_header_for_signing);
                }
            }
            _ => {
                log::debug!("Unsupported pubkey version: {}", header.version);
            }
        }
    }

    /// Try to decrypt a v4 pubkey using tags of addresses we need
    fn try_decrypt_v4_pubkey(&self, v4pk: &PubKeyV4, header: &ObjectHeader, raw_header_for_signing: &[u8]) {
        // Check all contacts, queued messages, etc. for matching tag
        let contacts = if let Ok(db) = self.db.lock() {
            db.get_contacts().unwrap_or_default()
        } else {
            return;
        };

        // Also check queued messages for their to_address
        let queued = if let Ok(db) = self.db.lock() {
            db.get_queued_messages().unwrap_or_default()
        } else {
            vec![]
        };

        let mut addresses_to_check: Vec<String> = contacts.iter().map(|c| c.address.clone()).collect();
        for msg in &queued {
            if !addresses_to_check.contains(&msg.to_address) {
                addresses_to_check.push(msg.to_address.clone());
            }
        }

        for addr_str in &addresses_to_check {
            let Ok(addr) = BitmessageAddress::decode(addr_str) else {
                continue;
            };
            if addr.version < 4 {
                continue;
            }

            let (enc_key_bytes, expected_tag) = address::compute_address_encryption_key(
                addr.version,
                addr.stream,
                &addr.ripe,
            );

            if v4pk.tag != expected_tag {
                continue;
            }

            // Tag matches! Try to decrypt
            let Ok(secret_key) = k256::SecretKey::from_slice(&enc_key_bytes) else {
                continue;
            };

            let Ok(decrypted) = ecies::decrypt(&secret_key, &v4pk.encrypted) else {
                continue;
            };

            // Parse the decrypted pubkey data (same as v3 format)
            if let Ok((pk, sig_offset)) = PubKeyData::decode_v3(&decrypted) {
                // Verify signature using raw wire bytes
                let mut sign_data = Vec::new();
                sign_data.extend_from_slice(raw_header_for_signing);
                sign_data.extend_from_slice(&v4pk.tag);
                sign_data.extend_from_slice(&decrypted[..sig_offset]);

                log::info!("V4 pubkey decrypted for {addr_str}, verifying signature (sign_data len={}, sig len={})", sign_data.len(), pk.signature.len());
                match crate::crypto::keys::verify_signature(
                    &pk.public_signing_key, &sign_data, &pk.signature,
                ) {
                    Ok(true) => {
                        log::info!("V4 pubkey signature verified OK for {addr_str}");
                    }
                    Ok(false) => {
                        log::warn!("V4 pubkey signature FAILED for {addr_str}");
                        break;
                    }
                    Err(e) => {
                        log::warn!("V4 pubkey signature error for {addr_str}: {e}");
                        break;
                    }
                }

                // Verify the pubkey matches the address
                let ripe = address::compute_ripe(&pk.public_signing_key, &pk.public_encryption_key);
                let computed_addr = address::encode_address(addr.version, addr.stream, &ripe);
                if computed_addr == *addr_str {
                    self.store_received_pubkey(addr_str, &pk, header.expires_time as i64);
                    log::info!("Decrypted and stored v4 pubkey for {addr_str}");
                } else {
                    log::warn!("V4 pubkey address mismatch: expected {addr_str}, got {computed_addr}");
                }
            }
            break;
        }
    }

    /// Store a received pubkey in the database
    fn store_received_pubkey(&self, addr: &str, pk: &PubKeyData, expires: i64) {
        if let Ok(db) = self.db.lock() {
            let _ = db.store_pubkey(
                addr,
                &pk.public_signing_key,
                &pk.public_encryption_key,
                pk.nonce_trials_per_byte as i64,
                pk.extra_bytes as i64,
                expires,
            );

            // Also update contact if exists
            let _ = db.update_contact_pubkeys(
                addr,
                &pk.public_signing_key,
                &pk.public_encryption_key,
            );
        }

        self.send_event(NetworkEvent::PubkeyReceived {
            address: addr.to_string(),
        });
        self.send_event(NetworkEvent::StatusUpdate(format!(
            "Received pubkey for {addr}"
        )));
    }

    /// Match an incoming getpubkey request against our identities
    fn match_getpubkey(&self, header: &ObjectHeader, data: &[u8]) -> Option<crate::storage::StoredIdentity> {
        let identities = if let Ok(db) = self.db.lock() {
            db.get_identities().unwrap_or_default()
        } else {
            return None;
        };

        match header.version {
            v if v <= 3 => {
                let gpk = GetPubKey::decode(data, v).ok()?;
                if let GetPubKey::V3 { ripe } = gpk {
                    for identity in &identities {
                        if !identity.enabled { continue; }
                        let our_ripe = address::compute_ripe(
                            identity.pub_signing_key.as_slice().try_into().unwrap_or(&[0u8; 64]),
                            identity.pub_encryption_key.as_slice().try_into().unwrap_or(&[0u8; 64]),
                        );
                        if our_ripe == ripe {
                            log::info!("Getpubkey request matches identity {}", identity.address);
                            return Some(identity.clone());
                        }
                    }
                }
            }
            4 => {
                let gpk = GetPubKey::decode(data, 4).ok()?;
                if let GetPubKey::V4 { tag } = gpk {
                    for identity in &identities {
                        if !identity.enabled { continue; }
                        let Ok(addr) = BitmessageAddress::decode(&identity.address) else { continue };
                        if let Some(our_tag) = addr.tag {
                            if our_tag == tag {
                                log::info!("Getpubkey request matches v4 identity {}", identity.address);
                                return Some(identity.clone());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// Send our pubkey in response to a getpubkey request
    async fn send_pubkey_response(&mut self, identity: &crate::storage::StoredIdentity) {
        self.send_event(NetworkEvent::StatusUpdate(format!(
            "Publishing pubkey for {}...", identity.address
        )));

        let Ok(keypair) = KeyPair::from_secrets(
            identity.signing_key.clone(), identity.encryption_key.clone(),
        ) else {
            return;
        };

        let Ok(addr) = BitmessageAddress::decode(&identity.address) else { return; };

        let pk_data = PubKeyData {
            behavior_bitfield: bitfield::DOES_ACK,
            public_signing_key: keypair.public_signing_key,
            public_encryption_key: keypair.public_encryption_key,
            nonce_trials_per_byte: identity.nonce_trials as u64,
            extra_bytes: identity.extra_bytes as u64,
            signature: vec![], // will be computed below
        };

        let expires = unix_time() + DEFAULT_TTL;
        let obj_header = ObjectHeader {
            nonce: 0,
            expires_time: expires,
            object_type: object_type::PUBKEY,
            version: identity.address_version as u64,
            stream_number: identity.stream_number as u64,
        };

        if identity.address_version <= 3 {
            // V3 pubkey: sign and send directly
            let mut sign_data = obj_header.encode_for_signing();
            sign_data.extend_from_slice(&pk_data.behavior_bitfield.to_be_bytes());
            sign_data.extend_from_slice(&pk_data.public_signing_key);
            sign_data.extend_from_slice(&pk_data.public_encryption_key);
            sign_data.extend(encode_varint(pk_data.nonce_trials_per_byte));
            sign_data.extend(encode_varint(pk_data.extra_bytes));

            let Ok(signature) = keypair.sign(&sign_data) else { return; };

            let mut pubkey_payload = pk_data.behavior_bitfield.to_be_bytes().to_vec();
            pubkey_payload.extend_from_slice(&pk_data.public_signing_key);
            pubkey_payload.extend_from_slice(&pk_data.public_encryption_key);
            pubkey_payload.extend(encode_varint(pk_data.nonce_trials_per_byte));
            pubkey_payload.extend(encode_varint(pk_data.extra_bytes));
            pubkey_payload.extend(encode_varint(signature.len() as u64));
            pubkey_payload.extend_from_slice(&signature);

            let mut pow_payload = obj_header.encode_for_signing();
            pow_payload.extend_from_slice(&pubkey_payload);

            let event_tx = self.event_tx.clone();
            let cancelled = Arc::new(AtomicBool::new(false));
            let pow_result = tokio::task::spawn_blocking({
                let cancelled = cancelled.clone();
                move || {
                    let target = pow::calculate_target(
                        (pow_payload.len() + 8) as u64, DEFAULT_TTL,
                        pow::DEFAULT_NONCE_TRIALS_PER_BYTE, pow::DEFAULT_EXTRA_BYTES,
                    );
                    let nonce = pow::do_pow_with_progress(&pow_payload, target, |n| {
                        let _ = event_tx.send(NetworkEvent::StatusUpdate(
                            format!("Computing pubkey PoW... ({n})")
                        ));
                    }, cancelled);
                    (nonce, pow_payload)
                }
            }).await;

            let Ok((nonce_opt, pow_payload)) = pow_result else { return; };
            let Some(nonce) = nonce_opt else { return; };
            let mut full_object = nonce.to_be_bytes().to_vec();
            full_object.extend_from_slice(&pow_payload);

            let inv_hash = InventoryVector::from_object_data(&full_object);
            if let Ok(db) = self.db.lock() {
                let _ = db.store_inventory(&inv_hash.hash, object_type::PUBKEY,
                    identity.stream_number as u64, &full_object, expires);
            }

            let object_msg = encode_message("object", &full_object);
            self.broadcast_to_peers(&object_msg).await;
            self.send_event(NetworkEvent::StatusUpdate(format!(
                "Published v3 pubkey for {}", identity.address
            )));
        } else {
            // V4 pubkey: sign, encrypt with address-derived key, prepend tag
            let tag = addr.tag.unwrap_or_else(|| address::compute_tag(
                addr.version, addr.stream, &addr.ripe,
            ));

            let mut sign_data = obj_header.encode_for_signing();
            sign_data.extend_from_slice(&tag);
            sign_data.extend_from_slice(&pk_data.behavior_bitfield.to_be_bytes());
            sign_data.extend_from_slice(&pk_data.public_signing_key);
            sign_data.extend_from_slice(&pk_data.public_encryption_key);
            sign_data.extend(encode_varint(pk_data.nonce_trials_per_byte));
            sign_data.extend(encode_varint(pk_data.extra_bytes));

            let Ok(signature) = keypair.sign(&sign_data) else { return; };

            // Build inner pubkey data (same as v3 format)
            let mut inner = pk_data.behavior_bitfield.to_be_bytes().to_vec();
            inner.extend_from_slice(&pk_data.public_signing_key);
            inner.extend_from_slice(&pk_data.public_encryption_key);
            inner.extend(encode_varint(pk_data.nonce_trials_per_byte));
            inner.extend(encode_varint(pk_data.extra_bytes));
            inner.extend(encode_varint(signature.len() as u64));
            inner.extend_from_slice(&signature);

            // Encrypt with address-derived key
            let (enc_key_bytes, _) = address::compute_address_encryption_key(
                addr.version, addr.stream, &addr.ripe,
            );
            let Ok(enc_sk) = k256::SecretKey::from_slice(&enc_key_bytes) else { return; };
            let enc_pk = enc_sk.public_key();
            let Ok(encrypted) = ecies::encrypt(&enc_pk, &inner) else { return; };

            // Pubkey payload: tag + encrypted
            let mut pubkey_payload = tag.to_vec();
            pubkey_payload.extend_from_slice(&encrypted);

            let mut pow_payload = obj_header.encode_for_signing();
            pow_payload.extend_from_slice(&pubkey_payload);

            let event_tx = self.event_tx.clone();
            let cancelled = Arc::new(AtomicBool::new(false));
            let pow_result = tokio::task::spawn_blocking({
                let cancelled = cancelled.clone();
                move || {
                    let target = pow::calculate_target(
                        (pow_payload.len() + 8) as u64, DEFAULT_TTL,
                        pow::DEFAULT_NONCE_TRIALS_PER_BYTE, pow::DEFAULT_EXTRA_BYTES,
                    );
                    let nonce = pow::do_pow_with_progress(&pow_payload, target, |n| {
                        let _ = event_tx.send(NetworkEvent::StatusUpdate(
                            format!("Computing v4 pubkey PoW... ({n})")
                        ));
                    }, cancelled);
                    (nonce, pow_payload)
                }
            }).await;

            let Ok((nonce_opt, pow_payload)) = pow_result else { return; };
            let Some(nonce) = nonce_opt else { return; };
            let mut full_object = nonce.to_be_bytes().to_vec();
            full_object.extend_from_slice(&pow_payload);

            let inv_hash = InventoryVector::from_object_data(&full_object);
            if let Ok(db) = self.db.lock() {
                let _ = db.store_inventory(&inv_hash.hash, object_type::PUBKEY,
                    identity.stream_number as u64, &full_object, expires);
            }

            let object_msg = encode_message("object", &full_object);
            self.broadcast_to_peers(&object_msg).await;
            self.send_event(NetworkEvent::StatusUpdate(format!(
                "Published v4 pubkey for {}", identity.address
            )));
        }
    }

    /// Try to decrypt an incoming msg object with all our private keys.
    /// Returns ack_data to broadcast if message was successfully decrypted.
    fn try_decrypt_message(&self, _header: &ObjectHeader, encrypted_data: &[u8], raw_header_for_signing: &[u8]) -> Option<Vec<u8>> {
        let identities = if let Ok(db) = self.db.lock() {
            db.get_identities().unwrap_or_default()
        } else {
            return None;
        };

        for identity in &identities {
            if !identity.enabled {
                continue;
            }

            let Ok(secret_key) = k256::SecretKey::from_slice(&identity.encryption_key) else {
                continue;
            };

            // Try to decrypt
            let Ok(decrypted) = ecies::decrypt(&secret_key, encrypted_data) else {
                continue;
            };

            log::info!("ECIES decryption succeeded for identity {} — message is for us!", identity.address);

            // Parse the decrypted message
            let Ok((msg, sig_offset)) = UnencryptedMessage::decode_msg(&decrypted) else {
                log::warn!("Failed to decode decrypted message payload for {}", identity.address);
                continue;
            };

            // Validate destination RIPE matches our identity
            if let Some(dest_ripe) = &msg.destination_ripe {
                let our_ripe = address::compute_ripe(
                    identity.pub_signing_key.as_slice().try_into().unwrap_or(&[0u8; 64]),
                    identity.pub_encryption_key.as_slice().try_into().unwrap_or(&[0u8; 64]),
                );
                if *dest_ripe != our_ripe {
                    log::warn!(
                        "Message destination RIPE mismatch for {}: expected {}, got {}",
                        identity.address,
                        hex::encode(our_ripe),
                        hex::encode(dest_ripe)
                    );
                    continue;
                }
                log::info!("Destination RIPE verified OK for {}", identity.address);
            }

            // Verify ECDSA signature using original raw wire bytes (not re-encoded)
            let mut sign_data = Vec::new();
            sign_data.extend_from_slice(raw_header_for_signing);
            sign_data.extend_from_slice(&decrypted[..sig_offset]);

            log::info!(
                "Verifying msg signature: sign_data len={}, raw_header len={}, decrypted_unsigned len={}, sig len={}, sign_data_hex={}",
                sign_data.len(),
                raw_header_for_signing.len(),
                sig_offset,
                msg.signature.len(),
                hex::encode(&sign_data[..sign_data.len().min(64)])
            );

            match crate::crypto::keys::verify_signature(
                &msg.public_signing_key,
                &sign_data,
                &msg.signature,
            ) {
                Ok(true) => {
                    log::info!("Message signature verified OK");
                }
                Ok(false) => {
                    log::warn!(
                        "Message signature verification FAILED — sign_data SHA256={}",
                        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&sign_data))
                    );
                    continue;
                }
                Err(e) => {
                    log::warn!("Message signature check error: {e}");
                    continue;
                }
            }

            // Parse the message content — handle both Simple (2) and Extended (3)
            let (subject, body) = if msg.encoding == 3 {
                // Extended encoding with possible file attachments
                match parse_extended_encoding(&msg.message) {
                    Ok(ext) => {
                        let mut subj = String::new();
                        let mut bod = String::new();
                        for part in &ext.parts {
                            match part {
                                crate::protocol::objects::MessagePart::Text { subject: s, body: b } => {
                                    subj = s.clone();
                                    bod = b.clone();
                                }
                                _ => {} // File parts handled below
                            }
                        }
                        (subj, bod)
                    }
                    Err(e) => {
                        log::warn!("Failed to decode extended message: {e:?}");
                        parse_simple_encoding(&msg.message)
                    }
                }
            } else {
                parse_simple_encoding(&msg.message)
            };

            // Compute sender address from their public keys
            let sender_ripe =
                address::compute_ripe(&msg.public_signing_key, &msg.public_encryption_key);
            let sender_address = address::encode_address(
                msg.sender_address_version,
                msg.sender_stream,
                &sender_ripe,
            );

            // Check blacklist
            if let Ok(db) = self.db.lock() {
                if db.is_blacklisted(&sender_address) {
                    log::info!("Ignoring message from blacklisted address: {sender_address}");
                    return None;
                }
            }

            // Store in inbox (msgid derived from encrypted data hash for dedup)
            let msg_hash = <sha2::Sha256 as sha2::Digest>::digest(encrypted_data);
            let msgid = hex::encode(&msg_hash[..16]);
            let mut msg_already_inserted = false;
            let mut is_chunk_only = false;

            if let Ok(db) = self.db.lock() {
                // Handle extended encoding file parts
                if msg.encoding == 3 {
                    if let Ok(ext) = parse_extended_encoding(&msg.message) {
                        for part in &ext.parts {
                            match part {
                                crate::protocol::objects::MessagePart::FileManifest {
                                    transfer_id, filename, mime_type,
                                    total_size, sha256_hash, total_chunks,
                                    chunk_index, chunk_data,
                                } => {
                                    log::info!("Received file manifest: {} ({} bytes, {} chunks)",
                                        filename, total_size, total_chunks);

                                    // Insert message first to get message_id
                                    let msg_db_id = db.insert_message(
                                        &msgid, &sender_address, &identity.address,
                                        &subject, &body, 3, "received", "inbox",
                                    ).unwrap_or(0);
                                    msg_already_inserted = true;

                                    // Create attachment record
                                    let _ = db.insert_attachment(
                                        msg_db_id, transfer_id, filename, mime_type,
                                        *total_size as i64, sha256_hash, *total_chunks as i64,
                                    );

                                    // Store first chunk
                                    let _ = db.insert_attachment_chunk(
                                        transfer_id, *chunk_index as i64, chunk_data,
                                    );

                                    // If single-chunk file, reassemble immediately
                                    if *total_chunks == 1 {
                                        let _ = db.reassemble_attachment(transfer_id);
                                    }
                                }
                                crate::protocol::objects::MessagePart::FileChunk {
                                    transfer_id, chunk_index, chunk_data,
                                } => {
                                    log::info!("Received file chunk {chunk_index} for transfer {}",
                                        hex::encode(transfer_id));

                                    let _ = db.insert_attachment_chunk(
                                        transfer_id, *chunk_index as i64, chunk_data,
                                    );

                                    // Check if all chunks received
                                    if let Some(att) = db.get_attachment_by_transfer_id(transfer_id) {
                                        if att.received_chunks >= att.total_chunks {
                                            log::info!("All chunks received for {}, reassembling...", att.filename);
                                            let _ = db.reassemble_attachment(transfer_id);
                                        }
                                        self.send_event(NetworkEvent::FileProgress {
                                            transfer_id: transfer_id.to_vec(),
                                            chunks_done: att.received_chunks as u64,
                                            total_chunks: att.total_chunks as u64,
                                            filename: att.filename.clone(),
                                        });
                                    }

                                    is_chunk_only = true; // Don't create another inbox message
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Store message in inbox (skip if already inserted or chunk-only)
                if !is_chunk_only && !msg_already_inserted {
                    let _ = db.insert_message(
                        &msgid,
                        &sender_address,
                        &identity.address,
                        &subject,
                        &body,
                        msg.encoding as i64,
                        "received",
                        "inbox",
                    );
                }

                // Store sender's pubkey for future replies
                let _ = db.store_pubkey(
                    &sender_address,
                    &msg.public_signing_key,
                    &msg.public_encryption_key,
                    msg.nonce_trials_per_byte as i64,
                    msg.extra_bytes as i64,
                    (unix_time() + 28 * 24 * 3600) as i64,
                );

                // Update contact pubkey if exists
                let _ = db.update_contact_pubkeys(
                    &sender_address,
                    &msg.public_signing_key,
                    &msg.public_encryption_key,
                );
            }

            if !is_chunk_only {
                self.send_event(NetworkEvent::MessageReceived {
                    from: sender_address,
                    to: identity.address.clone(),
                    subject,
                    body,
                });
            }

            // Return ack_data for broadcasting (if non-empty)
            if !msg.ack_data.is_empty() {
                return Some(msg.ack_data);
            }
            return None;
        }
        None
    }

    /// Try to decrypt a broadcast using subscriptions and channels
    fn try_decrypt_broadcast(&self, header: &ObjectHeader, data: &[u8], raw_header_for_signing: &[u8]) {
        log::info!("try_decrypt_broadcast: version={}, data_len={}", header.version, data.len());

        if header.version == 5 {
            // V5 broadcast: tag (32 bytes) + encrypted data
            if data.len() < 32 {
                log::warn!("Broadcast v5 too short: {} bytes", data.len());
                return;
            }
            let tag = &data[..32];
            let encrypted = &data[32..];
            log::debug!("Broadcast v5: tag={}, encrypted_len={}", hex::encode(&tag[..8]), encrypted.len());

            // Check subscriptions
            let subscriptions = if let Ok(db) = self.db.lock() {
                db.get_subscriptions().unwrap_or_default()
            } else {
                log::warn!("try_decrypt_broadcast: failed to lock DB for subscriptions");
                return;
            };
            log::debug!("Checking {} subscriptions for broadcast", subscriptions.len());

            for sub in &subscriptions {
                if !sub.enabled {
                    continue;
                }
                let Ok(addr) = BitmessageAddress::decode(&sub.address) else {
                    continue;
                };

                let (enc_key_bytes, expected_tag) = address::compute_address_encryption_key(
                    addr.version,
                    addr.stream,
                    &addr.ripe,
                );

                if tag != expected_tag.as_slice() {
                    continue;
                }

                let Ok(secret_key) = k256::SecretKey::from_slice(&enc_key_bytes) else {
                    continue;
                };

                let Ok(decrypted) = ecies::decrypt(&secret_key, encrypted) else {
                    continue;
                };

                self.process_decrypted_broadcast(header, &decrypted, &sub.address, raw_header_for_signing, Some(tag));
                return;
            }

            // Also check channels
            let channels = if let Ok(db) = self.db.lock() {
                db.get_channels().unwrap_or_default()
            } else {
                log::warn!("try_decrypt_broadcast: failed to lock DB for channels");
                return;
            };
            log::debug!("Checking {} channels for broadcast", channels.len());

            for channel in &channels {
                if !channel.enabled {
                    continue;
                }
                let Ok(addr) = BitmessageAddress::decode(&channel.address) else {
                    log::debug!("Channel address decode failed: {}", channel.address);
                    continue;
                };

                let (enc_key_bytes, expected_tag) = address::compute_address_encryption_key(
                    addr.version,
                    addr.stream,
                    &addr.ripe,
                );

                if tag != expected_tag.as_slice() {
                    continue;
                }
                log::info!("Broadcast tag matches channel: {}", channel.address);

                let Ok(secret_key) = k256::SecretKey::from_slice(&enc_key_bytes) else {
                    log::warn!("Failed to create secret key for channel: {}", channel.address);
                    continue;
                };

                let Ok(decrypted) = ecies::decrypt(&secret_key, encrypted) else {
                    continue;
                };

                self.process_decrypted_broadcast(header, &decrypted, &channel.address, raw_header_for_signing, Some(tag));
                return;
            }
            log::debug!("No subscription/channel matched broadcast v5 tag");
        } else if header.version == 4 {
            // V4 broadcast: encrypted (v3 address), no tag — try all subscriptions + channels
            let subscriptions = if let Ok(db) = self.db.lock() {
                db.get_subscriptions().unwrap_or_default()
            } else {
                return;
            };
            for sub in &subscriptions {
                if !sub.enabled { continue; }
                let Ok(addr) = BitmessageAddress::decode(&sub.address) else { continue };
                let (enc_key_bytes, _) = address::compute_address_encryption_key(
                    addr.version, addr.stream, &addr.ripe,
                );
                let Ok(secret_key) = k256::SecretKey::from_slice(&enc_key_bytes) else { continue };
                if let Ok(decrypted) = ecies::decrypt(&secret_key, data) {
                    self.process_decrypted_broadcast(header, &decrypted, &sub.address, raw_header_for_signing, None);
                    return;
                }
            }
            let channels = if let Ok(db) = self.db.lock() {
                db.get_channels().unwrap_or_default()
            } else {
                return;
            };
            for channel in &channels {
                if !channel.enabled { continue; }
                let Ok(addr) = BitmessageAddress::decode(&channel.address) else { continue };
                let (enc_key_bytes, _) = address::compute_address_encryption_key(
                    addr.version, addr.stream, &addr.ripe,
                );
                let Ok(secret_key) = k256::SecretKey::from_slice(&enc_key_bytes) else { continue };
                if let Ok(decrypted) = ecies::decrypt(&secret_key, data) {
                    self.process_decrypted_broadcast(header, &decrypted, &channel.address, raw_header_for_signing, None);
                    return;
                }
            }
            log::debug!("No subscription/channel matched broadcast v4");
        } else {
            log::warn!("Unknown broadcast version: {}", header.version);
        }
    }

    /// Process decrypted broadcast content
    fn process_decrypted_broadcast(
        &self,
        _header: &ObjectHeader,
        decrypted: &[u8],
        subscription_address: &str,
        raw_header_for_signing: &[u8],
        raw_tag: Option<&[u8]>,
    ) {
        let Ok((msg, sig_offset)) = UnencryptedMessage::decode_broadcast(decrypted) else {
            log::debug!("Failed to decode broadcast content");
            return;
        };

        // Verify ECDSA signature using original raw wire bytes
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(raw_header_for_signing);
        // For v5 broadcast, tag is part of sign_data
        if let Some(tag) = raw_tag {
            sign_data.extend_from_slice(tag);
        }
        sign_data.extend_from_slice(&decrypted[..sig_offset]);

        match crate::crypto::keys::verify_signature(
            &msg.public_signing_key, &sign_data, &msg.signature,
        ) {
            Ok(true) => {}
            Ok(false) => {
                log::warn!("Broadcast signature verification failed");
                return;
            }
            Err(e) => {
                log::warn!("Broadcast signature check error: {e}");
                return;
            }
        }

        let (subject, body) = parse_simple_encoding(&msg.message);

        // Compute sender address
        let sender_ripe = address::compute_ripe(&msg.public_signing_key, &msg.public_encryption_key);
        let sender_address = address::encode_address(
            msg.sender_address_version, msg.sender_stream, &sender_ripe,
        );

        // Check blacklist
        if let Ok(db) = self.db.lock() {
            if db.is_blacklisted(&sender_address) {
                log::info!("Ignoring broadcast from blacklisted address: {sender_address}");
                return;
            }
        }

        let to_addr = if subscription_address.is_empty() {
            "[Broadcast]".to_string()
        } else {
            subscription_address.to_string()
        };

        log::info!("Broadcast decrypted from {sender_address}: {subject}");

        if let Ok(db) = self.db.lock() {
            let bc_hash = <sha2::Sha256 as sha2::Digest>::digest(decrypted);
            let msgid = hex::encode(&bc_hash[..16]);
            let _ = db.insert_message(
                &msgid, &sender_address, &to_addr, &subject, &body,
                msg.encoding as i64, "received", "inbox",
            );

            let _ = db.store_pubkey(
                &sender_address, &msg.public_signing_key, &msg.public_encryption_key,
                msg.nonce_trials_per_byte as i64, msg.extra_bytes as i64,
                (unix_time() + 28 * 24 * 3600) as i64,
            );
        }

        self.send_event(NetworkEvent::BroadcastReceived {
            from: sender_address.clone(),
            subject: subject.clone(),
            body: body.clone(),
        });
        self.send_event(NetworkEvent::MessageReceived {
            from: sender_address,
            to: to_addr,
            subject,
            body,
        });
    }

    /// Send data to a specific peer
    async fn send_to_peer(&mut self, addr: &str, data: &[u8]) {
        self.bytes_sent += data.len() as u64;
        for peer in &mut self.peers {
            if format!("{}:{}", peer.info.address, peer.info.port) == addr
                || peer.info.address == addr
            {
                let _ = peer.writer.write_all(data).await;
                let _ = peer.writer.flush().await;
                return;
            }
        }
    }

    /// Send data to all connected peers
    async fn broadcast_to_peers(&mut self, data: &[u8]) {
        self.bytes_sent += (data.len() * self.peers.len()) as u64;
        let mut failed = vec![];
        for (i, peer) in self.peers.iter_mut().enumerate() {
            if peer.writer.write_all(data).await.is_err()
                || peer.writer.flush().await.is_err()
            {
                failed.push(i);
            }
        }
        // Remove failed peers in reverse order
        for i in failed.into_iter().rev() {
            self.peers.remove(i);
        }
    }

    fn send_event(&self, event: NetworkEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Get current peer list info (for UI)
    pub fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|p| p.info.clone()).collect()
    }
}
