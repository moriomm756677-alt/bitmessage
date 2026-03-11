use rusqlite::{Connection, params};
use std::collections::HashSet;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// --- Data types ---

#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub id: i64,
    pub label: String,
    pub address: String,
    pub signing_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub pub_signing_key: Vec<u8>,
    pub pub_encryption_key: Vec<u8>,
    pub address_version: i64,
    pub stream_number: i64,
    pub enabled: bool,
    pub nonce_trials: i64,
    pub extra_bytes: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredContact {
    pub id: i64,
    pub label: String,
    pub address: String,
    pub pub_signing_key: Option<Vec<u8>>,
    pub pub_encryption_key: Option<Vec<u8>>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: i64,
    pub msgid: String,
    pub from_address: String,
    pub to_address: String,
    pub subject: String,
    pub body: String,
    pub encoding: i64,
    pub status: String,
    pub folder: String,
    pub read: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredChannel {
    pub id: i64,
    pub label: String,
    pub address: String,
    pub passphrase: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredSubscription {
    pub id: i64,
    pub label: String,
    pub address: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct KnownNode {
    pub ip: String,
    pub port: i64,
    pub stream: i64,
    pub services: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone)]
pub struct BlacklistEntry {
    pub id: i64,
    pub label: String,
    pub address: String,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredSettings {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct StoredAttachment {
    pub id: i64,
    pub message_id: i64,
    pub transfer_id: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
    pub total_size: i64,
    pub sha256_hash: Vec<u8>,
    pub total_chunks: i64,
    pub received_chunks: i64,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportedIdentity {
    pub label: String,
    pub address: String,
    pub signing_key: String,
    pub encryption_key: String,
    pub pub_signing_key: String,
    pub pub_encryption_key: String,
    pub address_version: i64,
    pub stream_number: i64,
    pub nonce_trials: i64,
    pub extra_bytes: i64,
}

// --- Database ---

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self, DbError> {
        let path = Self::db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA busy_timeout=5000;
        ")?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    fn db_path() -> PathBuf {
        let mut path = dirs_or_default();
        path.push("bitmessage-rs");
        path.push("messages.db");
        path
    }

    fn init_tables(&self) -> Result<(), DbError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                signing_key BLOB NOT NULL,
                encryption_key BLOB NOT NULL,
                pub_signing_key BLOB NOT NULL,
                pub_encryption_key BLOB NOT NULL,
                address_version INTEGER NOT NULL DEFAULT 4,
                stream_number INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                nonce_trials INTEGER NOT NULL DEFAULT 1000,
                extra_bytes INTEGER NOT NULL DEFAULT 1000,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                pub_signing_key BLOB,
                pub_encryption_key BLOB,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msgid TEXT NOT NULL,
                from_address TEXT NOT NULL,
                to_address TEXT NOT NULL,
                subject TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                encoding INTEGER NOT NULL DEFAULT 2,
                status TEXT NOT NULL DEFAULT 'received',
                folder TEXT NOT NULL DEFAULT 'inbox',
                read INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                passphrase TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS known_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                stream INTEGER NOT NULL DEFAULT 1,
                services INTEGER NOT NULL DEFAULT 1,
                last_seen INTEGER NOT NULL,
                UNIQUE(ip, port)
            );

            CREATE TABLE IF NOT EXISTS inventory (
                hash BLOB PRIMARY KEY,
                object_type INTEGER NOT NULL,
                stream_number INTEGER NOT NULL,
                payload BLOB NOT NULL,
                expires_time INTEGER NOT NULL,
                received_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pubkeys (
                address TEXT PRIMARY KEY,
                pub_signing_key BLOB NOT NULL,
                pub_encryption_key BLOB NOT NULL,
                nonce_trials INTEGER NOT NULL DEFAULT 1000,
                extra_bytes INTEGER NOT NULL DEFAULT 1000,
                expires_time INTEGER NOT NULL,
                received_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                address TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL DEFAULT 0,
                transfer_id BLOB NOT NULL,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                total_size INTEGER NOT NULL,
                sha256_hash BLOB NOT NULL,
                total_chunks INTEGER NOT NULL,
                received_chunks INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'incomplete',
                file_data BLOB,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_attachments_transfer_id
                ON attachments(transfer_id);
            CREATE INDEX IF NOT EXISTS idx_attachments_message_id
                ON attachments(message_id);

            CREATE TABLE IF NOT EXISTS attachment_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_id BLOB NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_data BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                UNIQUE(transfer_id, chunk_index)
            );
            CREATE INDEX IF NOT EXISTS idx_chunks_transfer_id
                ON attachment_chunks(transfer_id);
            CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_address);
            CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_address);
            CREATE INDEX IF NOT EXISTS idx_messages_folder ON messages(folder);
            CREATE INDEX IF NOT EXISTS idx_inventory_expires ON inventory(expires_time);
            CREATE INDEX IF NOT EXISTS idx_pubkeys_expires ON pubkeys(expires_time);
            ",
        )?;

        // Migrations: add columns to existing tables (safe to call multiple times)
        let _ = self.conn.execute("ALTER TABLE messages ADD COLUMN ack_data BLOB", []);
        let _ = self.conn.execute("ALTER TABLE messages ADD COLUMN ack_hash TEXT", []);
        let _ = self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_msgid ON messages(msgid)", [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE inventory ADD COLUMN processed INTEGER NOT NULL DEFAULT 0", [],
        );

        let version: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap_or(0);

        // Migration v1: reset processed flag so fixed decryption code retries all objects
        if version < 1 {
            log::info!("Migration v1: resetting processed flag on MSG/BROADCAST inventory for re-decryption");
            let _ = self.conn.execute(
                "UPDATE inventory SET processed = 0 WHERE object_type IN (2, 3)", [],
            );
        }

        // Migration v2: fix identity addresses (compute_ripe now includes 0x04 prefix)
        if version < 2 {
            log::info!("Migration v2: fixing identity addresses");
            self.migrate_identity_addresses()?;
        }

        // Update to latest version
        if version < 2 {
            let _ = self.conn.execute("PRAGMA user_version = 2", []);
        }

        Ok(())
    }

    /// Check if an inventory hash matches any pending ACK and update status
    pub fn check_ack_received(&self, inv_hash_hex: &str) -> bool {
        let updated = self.conn.execute(
            "UPDATE messages SET status = 'ackreceived'
             WHERE ack_hash = ?1 AND status IN ('msgsent', 'msgsentnoack')",
            params![inv_hash_hex],
        ).unwrap_or(0);
        updated > 0
    }

    /// Store ack_data and ack_hash for a sent message
    pub fn update_message_ack(&self, msgid: &str, ack_data: &[u8], ack_hash: &str) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE messages SET ack_data = ?1, ack_hash = ?2 WHERE msgid = ?3",
            params![ack_data, ack_hash, msgid],
        )?;
        Ok(())
    }

    /// Recalculate identity addresses using corrected compute_ripe (with 0x04 prefix).
    /// Also fixes message from/to addresses referencing old (incorrect) identity addresses.
    fn migrate_identity_addresses(&self) -> Result<(), DbError> {
        use crate::crypto::address;
        use sha2::{Sha512, Digest};
        use ripemd::Ripemd160;

        let mut stmt = self.conn.prepare(
            "SELECT id, pub_signing_key, pub_encryption_key, address_version, stream_number, address FROM identities"
        )?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>, i64, i64, String)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))
        })?.filter_map(|r| r.ok()).collect();

        for (id, pub_sign, pub_enc, addr_ver, stream, current_address) in rows {
            if pub_sign.len() != 64 || pub_enc.len() != 64 {
                continue;
            }
            let sign_arr: &[u8; 64] = pub_sign.as_slice().try_into().unwrap();
            let enc_arr: &[u8; 64] = pub_enc.as_slice().try_into().unwrap();

            // Correct address (with 0x04 prefix)
            let correct_ripe = address::compute_ripe(sign_arr, enc_arr);
            let correct_address = address::encode_address(addr_ver as u64, stream as u64, &correct_ripe);

            // Compute old (wrong) address without 0x04 prefix, to fix orphaned messages
            let mut old_combined = Vec::with_capacity(128);
            old_combined.extend_from_slice(sign_arr);
            old_combined.extend_from_slice(enc_arr);
            let old_sha = Sha512::digest(&old_combined);
            let old_ripe_hash = Ripemd160::digest(&old_sha);
            let mut old_ripe = [0u8; 20];
            old_ripe.copy_from_slice(&old_ripe_hash);
            let old_address = address::encode_address(addr_ver as u64, stream as u64, &old_ripe);

            // Fix identity address if still wrong
            if current_address != correct_address {
                log::info!("Migrating identity address: {} -> {}", current_address, correct_address);
                let _ = self.conn.execute(
                    "UPDATE identities SET address = ?1 WHERE id = ?2",
                    params![correct_address, id],
                );
            }

            // Fix messages referencing old (wrong) address
            if old_address != correct_address {
                let updated_from = self.conn.execute(
                    "UPDATE messages SET from_address = ?1 WHERE from_address = ?2",
                    params![correct_address, old_address],
                ).unwrap_or(0);
                let updated_to = self.conn.execute(
                    "UPDATE messages SET to_address = ?1 WHERE to_address = ?2",
                    params![correct_address, old_address],
                ).unwrap_or(0);
                if updated_from > 0 || updated_to > 0 {
                    log::info!("Fixed {} message from_address and {} to_address references: {} -> {}",
                        updated_from, updated_to, old_address, correct_address);
                }
            }
        }
        Ok(())
    }

    // --- Identity CRUD ---

    pub fn insert_identity(&self, identity: &StoredIdentity) -> Result<i64, DbError> {
        self.conn.execute(
            "INSERT INTO identities (label, address, signing_key, encryption_key,
             pub_signing_key, pub_encryption_key, address_version, stream_number,
             enabled, nonce_trials, extra_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                identity.label,
                identity.address,
                identity.signing_key,
                identity.encryption_key,
                identity.pub_signing_key,
                identity.pub_encryption_key,
                identity.address_version,
                identity.stream_number,
                identity.enabled as i64,
                identity.nonce_trials,
                identity.extra_bytes,
                identity.created_at,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_identities(&self) -> Result<Vec<StoredIdentity>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, address, signing_key, encryption_key,
             pub_signing_key, pub_encryption_key, address_version, stream_number,
             enabled, nonce_trials, extra_bytes, created_at FROM identities ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredIdentity {
                id: row.get(0)?,
                label: row.get(1)?,
                address: row.get(2)?,
                signing_key: row.get(3)?,
                encryption_key: row.get(4)?,
                pub_signing_key: row.get(5)?,
                pub_encryption_key: row.get(6)?,
                address_version: row.get(7)?,
                stream_number: row.get(8)?,
                enabled: row.get::<_, i64>(9)? != 0,
                nonce_trials: row.get(10)?,
                extra_bytes: row.get(11)?,
                created_at: row.get(12)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_identity(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .execute("DELETE FROM identities WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn toggle_identity(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE identities SET enabled = ?1 WHERE id = ?2",
            params![enabled as i64, id],
        )?;
        Ok(())
    }

    // --- Contact CRUD ---

    pub fn insert_contact(&self, label: &str, address: &str) -> Result<i64, DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (label, address, created_at) VALUES (?1, ?2, ?3)",
            params![label, address, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_contacts(&self) -> Result<Vec<StoredContact>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, address, pub_signing_key, pub_encryption_key, created_at
             FROM contacts ORDER BY label",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredContact {
                id: row.get(0)?,
                label: row.get(1)?,
                address: row.get(2)?,
                pub_signing_key: row.get(3)?,
                pub_encryption_key: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_contact(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .execute("DELETE FROM contacts WHERE id = ?1", params![id])?;
        Ok(())
    }

    // --- Message CRUD ---

    #[allow(clippy::too_many_arguments)]
    pub fn insert_message(
        &self,
        msgid: &str,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
        encoding: i64,
        status: &str,
        folder: &str,
    ) -> Result<i64, DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (msgid, from_address, to_address, subject, body,
             encoding, status, folder, read, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![msgid, from, to, subject, body, encoding, status, folder, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_messages_by_folder(&self, folder: &str) -> Result<Vec<StoredMessage>, DbError> {
        self.get_messages_by_folder_paged(folder, 200, 0)
    }

    pub fn get_messages_by_folder_paged(&self, folder: &str, limit: i64, offset: i64) -> Result<Vec<StoredMessage>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, msgid, from_address, to_address, subject, body,
             encoding, status, folder, read, created_at
             FROM messages WHERE folder = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![folder, limit, offset], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                msgid: row.get(1)?,
                from_address: row.get(2)?,
                to_address: row.get(3)?,
                subject: row.get(4)?,
                body: row.get(5)?,
                encoding: row.get(6)?,
                status: row.get(7)?,
                folder: row.get(8)?,
                read: row.get::<_, i64>(9)? != 0,
                created_at: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn count_messages_by_folder(&self, folder: &str) -> Result<i64, DbError> {
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder = ?1",
            params![folder],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn get_message_by_id(&self, id: i64) -> Result<Option<StoredMessage>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, msgid, from_address, to_address, subject, body,
             encoding, status, folder, read, created_at
             FROM messages WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                msgid: row.get(1)?,
                from_address: row.get(2)?,
                to_address: row.get(3)?,
                subject: row.get(4)?,
                body: row.get(5)?,
                encoding: row.get(6)?,
                status: row.get(7)?,
                folder: row.get(8)?,
                read: row.get::<_, i64>(9)? != 0,
                created_at: row.get(10)?,
            })
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    pub fn get_message_by_msgid(&self, msgid: &str) -> Option<StoredMessage> {
        self.conn.query_row(
            "SELECT id, msgid, from_address, to_address, subject, body,
             encoding, status, folder, read, created_at
             FROM messages WHERE msgid = ?1",
            params![msgid],
            |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    msgid: row.get(1)?,
                    from_address: row.get(2)?,
                    to_address: row.get(3)?,
                    subject: row.get(4)?,
                    body: row.get(5)?,
                    encoding: row.get(6)?,
                    status: row.get(7)?,
                    folder: row.get(8)?,
                    read: row.get::<_, i64>(9)? != 0,
                    created_at: row.get(10)?,
                })
            },
        ).ok()
    }

    pub fn mark_message_read(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .execute("UPDATE messages SET read = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn trash_message(&self, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE messages SET folder = 'trash' WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn delete_message(&self, id: i64) -> Result<(), DbError> {
        // Mark as permanently deleted instead of removing the row,
        // so the msgid stays in the table and prevents re-insertion on reprocess.
        self.conn.execute(
            "UPDATE messages SET folder = 'deleted', subject = '', body = '' WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn update_message_status(&self, msgid: &str, status: &str) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE messages SET status = ?1 WHERE msgid = ?2",
            params![status, msgid],
        )?;
        Ok(())
    }

    pub fn get_identity_by_address(&self, address: &str) -> Result<Option<StoredIdentity>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, address, signing_key, encryption_key,
             pub_signing_key, pub_encryption_key, address_version, stream_number,
             enabled, nonce_trials, extra_bytes, created_at
             FROM identities WHERE address = ?1",
        )?;
        let mut rows = stmt.query_map(params![address], |row| {
            Ok(StoredIdentity {
                id: row.get(0)?,
                label: row.get(1)?,
                address: row.get(2)?,
                signing_key: row.get(3)?,
                encryption_key: row.get(4)?,
                pub_signing_key: row.get(5)?,
                pub_encryption_key: row.get(6)?,
                address_version: row.get(7)?,
                stream_number: row.get(8)?,
                enabled: row.get::<_, i64>(9)? != 0,
                nonce_trials: row.get(10)?,
                extra_bytes: row.get(11)?,
                created_at: row.get(12)?,
            })
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    pub fn get_pubkey_for_address(&self, address: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>, DbError> {
        let now = chrono::Utc::now().timestamp();
        let mut stmt = self.conn.prepare(
            "SELECT pub_signing_key, pub_encryption_key FROM pubkeys
             WHERE address = ?1 AND expires_time > ?2",
        )?;
        let mut rows = stmt.query_map(params![address, now], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    /// Get full pubkey info including PoW difficulty requirements
    pub fn get_pubkey_full(&self, address: &str) -> Result<Option<(Vec<u8>, Vec<u8>, i64, i64)>, DbError> {
        let now = chrono::Utc::now().timestamp();
        let mut stmt = self.conn.prepare(
            "SELECT pub_signing_key, pub_encryption_key, nonce_trials, extra_bytes FROM pubkeys
             WHERE address = ?1 AND expires_time > ?2",
        )?;
        let mut rows = stmt.query_map(params![address, now], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?))
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    pub fn store_pubkey(
        &self,
        address: &str,
        signing_key: &[u8],
        encryption_key: &[u8],
        nonce_trials: i64,
        extra_bytes: i64,
        expires_time: i64,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO pubkeys
             (address, pub_signing_key, pub_encryption_key, nonce_trials, extra_bytes, expires_time, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![address, signing_key, encryption_key, nonce_trials, extra_bytes, expires_time, now],
        )?;
        Ok(())
    }

    pub fn unread_count(&self, folder: &str) -> Result<i64, DbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder = ?1 AND read = 0",
            params![folder],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // --- Channel CRUD ---

    pub fn insert_channel(&self, label: &str, address: &str, passphrase: &str) -> Result<i64, DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO channels (label, address, passphrase, enabled, created_at)
             VALUES (?1, ?2, ?3, 1, ?4)",
            params![label, address, passphrase, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_channels(&self) -> Result<Vec<StoredChannel>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, address, passphrase, enabled, created_at
             FROM channels ORDER BY label",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredChannel {
                id: row.get(0)?,
                label: row.get(1)?,
                address: row.get(2)?,
                passphrase: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_channel(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .execute("DELETE FROM channels WHERE id = ?1", params![id])?;
        Ok(())
    }

    // --- Subscription CRUD ---

    pub fn insert_subscription(&self, label: &str, address: &str) -> Result<i64, DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO subscriptions (label, address, enabled, created_at)
             VALUES (?1, ?2, 1, ?3)",
            params![label, address, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_subscriptions(&self) -> Result<Vec<StoredSubscription>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, address, enabled, created_at FROM subscriptions ORDER BY label",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredSubscription {
                id: row.get(0)?,
                label: row.get(1)?,
                address: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: row.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_subscription(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        Ok(())
    }

    // --- Inventory ---

    pub fn has_inventory(&self, hash: &[u8]) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM inventory WHERE hash = ?1",
                params![hash],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0
    }

    /// Batch check: returns a set of hashes that already exist in inventory.
    pub fn has_inventory_batch(&self, hashes: &[[u8; 32]]) -> HashSet<[u8; 32]> {
        let mut existing = HashSet::new();
        // Use a temporary table approach for efficiency
        let _ = self.conn.execute("CREATE TEMP TABLE IF NOT EXISTS _check_hashes (h BLOB)", []);
        let _ = self.conn.execute("DELETE FROM _check_hashes", []);
        {
            let mut stmt = match self.conn.prepare("INSERT INTO _check_hashes VALUES (?1)") {
                Ok(s) => s,
                Err(_) => return existing,
            };
            for h in hashes {
                let _ = stmt.execute(params![&h[..]]);
            }
        }
        let mut stmt = match self.conn.prepare(
            "SELECT i.hash FROM inventory i INNER JOIN _check_hashes c ON i.hash = c.h"
        ) {
            Ok(s) => s,
            Err(_) => return existing,
        };
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)) {
            for row in rows.flatten() {
                if row.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&row);
                    existing.insert(arr);
                }
            }
        }
        existing
    }

    pub fn store_inventory(
        &self,
        hash: &[u8],
        object_type: u32,
        stream_number: u64,
        payload: &[u8],
        expires_time: u64,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR IGNORE INTO inventory (hash, object_type, stream_number, payload, expires_time, received_at, processed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![hash, object_type as i64, stream_number as i64, payload, expires_time as i64, now],
        )?;
        Ok(())
    }

    pub fn get_inventory_hashes(&self, stream: u64) -> Result<Vec<Vec<u8>>, DbError> {
        let now = chrono::Utc::now().timestamp();
        let mut stmt = self.conn.prepare(
            "SELECT hash FROM inventory WHERE stream_number = ?1 AND expires_time > ?2",
        )?;
        let rows = stmt.query_map(params![stream as i64, now], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_inventory_object(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT payload FROM inventory WHERE hash = ?1",
        )?;
        let mut rows = stmt.query_map(params![hash], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    /// Get unprocessed inventory objects of a given type (for reprocessing)
    pub fn get_unprocessed_objects_by_type(&self, obj_type: u32) -> Result<Vec<(Vec<u8>, Vec<u8>)>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, payload FROM inventory WHERE object_type = ?1 AND expires_time > ?2 AND processed = 0",
        )?;
        let now = chrono::Utc::now().timestamp();
        let rows = stmt.query_map(params![obj_type, now], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Mark a single inventory object as processed by hash
    pub fn mark_object_processed(&self, hash: &[u8]) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE inventory SET processed = 1 WHERE hash = ?1",
            params![hash],
        )?;
        Ok(())
    }

    /// Mark all inventory objects of a given type as processed
    pub fn mark_inventory_processed(&self, obj_type: u32) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE inventory SET processed = 1 WHERE object_type = ?1",
            params![obj_type],
        )?;
        Ok(())
    }

    pub fn cleanup_expired_inventory(&self) -> Result<usize, DbError> {
        let now = chrono::Utc::now().timestamp();
        let deleted = self.conn.execute(
            "DELETE FROM inventory WHERE expires_time < ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    pub fn inventory_count(&self) -> Result<i64, DbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM inventory",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // --- Known Nodes ---

    pub fn upsert_known_node(&self, ip: &str, port: i64, stream: i64, services: i64) -> Result<(), DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO known_nodes (ip, port, stream, services, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip, port, stream, services, now],
        )?;
        Ok(())
    }

    pub fn get_known_nodes(&self, stream: i64) -> Result<Vec<KnownNode>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, port, stream, services, last_seen FROM known_nodes
             WHERE stream = ?1 ORDER BY last_seen DESC LIMIT 1000",
        )?;
        let rows = stmt.query_map(params![stream], |row| {
            Ok(KnownNode {
                ip: row.get(0)?,
                port: row.get(1)?,
                stream: row.get(2)?,
                services: row.get(3)?,
                last_seen: row.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn cleanup_old_nodes(&self, max_age_secs: i64) -> Result<usize, DbError> {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        let deleted = self.conn.execute(
            "DELETE FROM known_nodes WHERE last_seen < ?1",
            params![cutoff],
        )?;
        Ok(deleted)
    }

    // --- Blacklist ---

    pub fn insert_blacklist(&self, label: &str, address: &str) -> Result<i64, DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO blacklist (label, address, enabled, created_at)
             VALUES (?1, ?2, 1, ?3)",
            params![label, address, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_blacklist(&self) -> Result<Vec<BlacklistEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, address, enabled, created_at FROM blacklist ORDER BY label",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BlacklistEntry {
                id: row.get(0)?,
                label: row.get(1)?,
                address: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: row.get(4)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn delete_blacklist(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .execute("DELETE FROM blacklist WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn toggle_blacklist(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE blacklist SET enabled = ?1 WHERE id = ?2",
            params![enabled as i64, id],
        )?;
        Ok(())
    }

    pub fn is_blacklisted(&self, address: &str) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM blacklist WHERE address = ?1 AND enabled = 1",
                params![address],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0
    }

    // --- Message extensions ---

    pub fn untrash_message(&self, id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE messages SET folder = 'inbox' WHERE id = ?1 AND folder = 'trash'",
            params![id],
        )?;
        Ok(())
    }

    pub fn empty_trash(&self) -> Result<usize, DbError> {
        // Mark as permanently deleted instead of removing,
        // so msgids stay and prevent re-insertion on reprocess.
        let deleted = self.conn.execute(
            "UPDATE messages SET folder = 'deleted', subject = '', body = '' WHERE folder = 'trash'",
            [],
        )?;
        Ok(deleted)
    }

    pub fn message_count_by_folder(&self, folder: &str) -> Result<i64, DbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE folder = ?1",
            params![folder],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn get_queued_messages(&self) -> Result<Vec<StoredMessage>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, msgid, from_address, to_address, subject, body,
             encoding, status, folder, read, created_at
             FROM messages WHERE status IN ('msgqueued', 'broadcastqueued', 'awaitingpubkey')
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                msgid: row.get(1)?,
                from_address: row.get(2)?,
                to_address: row.get(3)?,
                subject: row.get(4)?,
                body: row.get(5)?,
                encoding: row.get(6)?,
                status: row.get(7)?,
                folder: row.get(8)?,
                read: row.get::<_, i64>(9)? != 0,
                created_at: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // --- Settings ---

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // --- Identity extensions ---

    pub fn update_identity_label(&self, id: i64, label: &str) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE identities SET label = ?1 WHERE id = ?2",
            params![label, id],
        )?;
        Ok(())
    }

    // --- Pubkey extensions ---

    pub fn delete_expired_pubkeys(&self) -> Result<usize, DbError> {
        let now = chrono::Utc::now().timestamp();
        let deleted = self.conn.execute(
            "DELETE FROM pubkeys WHERE expires_time < ?1",
            params![now],
        )?;
        Ok(deleted)
    }

    pub fn pubkey_count(&self) -> Result<i64, DbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pubkeys",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // --- Contact extensions ---

    pub fn update_contact_pubkeys(
        &self,
        address: &str,
        signing_key: &[u8],
        encryption_key: &[u8],
    ) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE contacts SET pub_signing_key = ?1, pub_encryption_key = ?2 WHERE address = ?3",
            params![signing_key, encryption_key, address],
        )?;
        Ok(())
    }

    // === Attachments ===

    pub fn insert_attachment(
        &self,
        message_id: i64,
        transfer_id: &[u8],
        filename: &str,
        mime_type: &str,
        total_size: i64,
        sha256_hash: &[u8],
        total_chunks: i64,
    ) -> Result<i64, DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO attachments (message_id, transfer_id, filename, mime_type,
             total_size, sha256_hash, total_chunks, received_chunks, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'incomplete', ?8)",
            params![message_id, transfer_id, filename, mime_type, total_size, sha256_hash, total_chunks, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn insert_attachment_chunk(
        &self,
        transfer_id: &[u8],
        chunk_index: i64,
        chunk_data: &[u8],
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR IGNORE INTO attachment_chunks (transfer_id, chunk_index, chunk_data, received_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![transfer_id, chunk_index, chunk_data, now],
        )?;
        // Update received_chunks count
        self.conn.execute(
            "UPDATE attachments SET received_chunks = (
                SELECT COUNT(*) FROM attachment_chunks WHERE transfer_id = ?1
             ) WHERE transfer_id = ?1",
            params![transfer_id],
        )?;
        Ok(())
    }

    pub fn get_attachments_for_message(&self, message_id: i64) -> Result<Vec<StoredAttachment>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, message_id, transfer_id, filename, mime_type, total_size,
             sha256_hash, total_chunks, received_chunks, status, created_at
             FROM attachments WHERE message_id = ?1 ORDER BY created_at",
        )?;
        let rows = stmt.query_map(params![message_id], |row| {
            Ok(StoredAttachment {
                id: row.get(0)?,
                message_id: row.get(1)?,
                transfer_id: row.get(2)?,
                filename: row.get(3)?,
                mime_type: row.get(4)?,
                total_size: row.get(5)?,
                sha256_hash: row.get(6)?,
                total_chunks: row.get(7)?,
                received_chunks: row.get(8)?,
                status: row.get(9)?,
                created_at: row.get(10)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn get_attachment_by_transfer_id(&self, transfer_id: &[u8]) -> Option<StoredAttachment> {
        self.conn.query_row(
            "SELECT id, message_id, transfer_id, filename, mime_type, total_size,
             sha256_hash, total_chunks, received_chunks, status, created_at
             FROM attachments WHERE transfer_id = ?1",
            params![transfer_id],
            |row| {
                Ok(StoredAttachment {
                    id: row.get(0)?,
                    message_id: row.get(1)?,
                    transfer_id: row.get(2)?,
                    filename: row.get(3)?,
                    mime_type: row.get(4)?,
                    total_size: row.get(5)?,
                    sha256_hash: row.get(6)?,
                    total_chunks: row.get(7)?,
                    received_chunks: row.get(8)?,
                    status: row.get(9)?,
                    created_at: row.get(10)?,
                })
            },
        ).ok()
    }

    /// Reassemble all chunks into complete file, verify SHA-256
    pub fn reassemble_attachment(&self, transfer_id: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        let att = match self.get_attachment_by_transfer_id(transfer_id) {
            Some(a) => a,
            None => return Ok(None),
        };
        if att.received_chunks < att.total_chunks {
            return Ok(None); // Not all chunks received yet
        }

        let mut stmt = self.conn.prepare(
            "SELECT chunk_data FROM attachment_chunks
             WHERE transfer_id = ?1 ORDER BY chunk_index ASC",
        )?;
        let chunks: Vec<Vec<u8>> = stmt.query_map(params![transfer_id], |row| {
            row.get::<_, Vec<u8>>(0)
        })?.filter_map(|r| r.ok()).collect();

        let mut file_data = Vec::with_capacity(att.total_size as usize);
        for chunk in &chunks {
            file_data.extend_from_slice(chunk);
        }

        // Verify SHA-256
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(&file_data);
        let status = if hash.as_slice() == att.sha256_hash.as_slice() {
            "verified"
        } else {
            "failed"
        };

        // Store assembled file and update status
        self.conn.execute(
            "UPDATE attachments SET status = ?1, file_data = ?2 WHERE transfer_id = ?3",
            params![status, file_data, transfer_id],
        )?;

        // Clean up chunks
        self.conn.execute(
            "DELETE FROM attachment_chunks WHERE transfer_id = ?1",
            params![transfer_id],
        )?;

        if status == "verified" {
            Ok(Some(file_data))
        } else {
            Ok(None)
        }
    }

    pub fn get_attachment_file_data(&self, transfer_id: &[u8]) -> Option<Vec<u8>> {
        self.conn.query_row(
            "SELECT file_data FROM attachments WHERE transfer_id = ?1 AND status = 'verified'",
            params![transfer_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ).ok().flatten()
    }

    pub fn update_attachment_status(&self, transfer_id: &[u8], status: &str) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE attachments SET status = ?1 WHERE transfer_id = ?2",
            params![status, transfer_id],
        )?;
        Ok(())
    }

    pub fn set_attachment_message_id(&self, transfer_id: &[u8], message_id: i64) -> Result<(), DbError> {
        self.conn.execute(
            "UPDATE attachments SET message_id = ?1 WHERE transfer_id = ?2",
            params![message_id, transfer_id],
        )?;
        Ok(())
    }

    pub fn has_attachment(&self, message_id: i64) -> bool {
        self.conn.query_row(
            "SELECT COUNT(*) FROM attachments WHERE message_id = ?1",
            params![message_id],
            |row| row.get::<_, i64>(0),
        ).unwrap_or(0) > 0
    }

    /// Export all identities as JSON-like string for backup
    pub fn export_identities(&self) -> Result<Vec<ExportedIdentity>, DbError> {
        let identities = self.get_identities()?;
        Ok(identities.into_iter().map(|id| ExportedIdentity {
            label: id.label,
            address: id.address,
            signing_key: hex::encode(&id.signing_key),
            encryption_key: hex::encode(&id.encryption_key),
            pub_signing_key: hex::encode(&id.pub_signing_key),
            pub_encryption_key: hex::encode(&id.pub_encryption_key),
            address_version: id.address_version,
            stream_number: id.stream_number,
            nonce_trials: id.nonce_trials,
            extra_bytes: id.extra_bytes,
        }).collect())
    }

    /// Import identities from exported data
    pub fn import_identities(&self, identities: &[ExportedIdentity]) -> Result<usize, DbError> {
        let mut imported = 0;
        let now = chrono::Utc::now().timestamp();
        for id in identities {
            let signing_key = hex::decode(&id.signing_key).map_err(|_| DbError::Sqlite(rusqlite::Error::InvalidParameterName("bad hex".into())))?;
            let encryption_key = hex::decode(&id.encryption_key).map_err(|_| DbError::Sqlite(rusqlite::Error::InvalidParameterName("bad hex".into())))?;
            let pub_signing_key = hex::decode(&id.pub_signing_key).map_err(|_| DbError::Sqlite(rusqlite::Error::InvalidParameterName("bad hex".into())))?;
            let pub_encryption_key = hex::decode(&id.pub_encryption_key).map_err(|_| DbError::Sqlite(rusqlite::Error::InvalidParameterName("bad hex".into())))?;

            let result = self.conn.execute(
                "INSERT OR IGNORE INTO identities (label, address, signing_key, encryption_key,
                 pub_signing_key, pub_encryption_key, address_version, stream_number,
                 enabled, nonce_trials, extra_bytes, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11)",
                params![
                    id.label, id.address, signing_key, encryption_key,
                    pub_signing_key, pub_encryption_key,
                    id.address_version, id.stream_number,
                    id.nonce_trials, id.extra_bytes, now,
                ],
            )?;
            if result > 0 { imported += 1; }
        }
        Ok(imported)
    }

    /// Encrypt private keys for all identities with a password hash
    pub fn encrypt_private_keys(&self, password_hash: &[u8; 32]) -> Result<(), DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, signing_key, encryption_key FROM identities"
        )?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?.filter_map(|r| r.ok()).collect();

        for (id, sign_key, enc_key) in rows {
            // Skip if already encrypted (encrypted keys will be longer due to IV + padding)
            if sign_key.len() != 32 || enc_key.len() != 32 {
                continue;
            }
            let encrypted_sign = simple_encrypt(password_hash, &sign_key);
            let encrypted_enc = simple_encrypt(password_hash, &enc_key);
            self.conn.execute(
                "UPDATE identities SET signing_key = ?1, encryption_key = ?2 WHERE id = ?3",
                params![encrypted_sign, encrypted_enc, id],
            )?;
        }
        self.set_setting("keys_encrypted", "1")?;
        Ok(())
    }

    /// Decrypt private keys with password hash
    pub fn decrypt_private_keys(&self, password_hash: &[u8; 32]) -> Result<(), DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, signing_key, encryption_key FROM identities"
        )?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?.filter_map(|r| r.ok()).collect();

        for (id, sign_key, enc_key) in rows {
            // Skip if not encrypted (raw keys are 32 bytes)
            if sign_key.len() == 32 && enc_key.len() == 32 {
                continue;
            }
            let decrypted_sign = simple_decrypt(password_hash, &sign_key)
                .map_err(|_| DbError::Sqlite(rusqlite::Error::InvalidParameterName("decryption failed".into())))?;
            let decrypted_enc = simple_decrypt(password_hash, &enc_key)
                .map_err(|_| DbError::Sqlite(rusqlite::Error::InvalidParameterName("decryption failed".into())))?;
            self.conn.execute(
                "UPDATE identities SET signing_key = ?1, encryption_key = ?2 WHERE id = ?3",
                params![decrypted_sign, decrypted_enc, id],
            )?;
        }
        Ok(())
    }

    /// Check if keys are encrypted
    pub fn are_keys_encrypted(&self) -> bool {
        self.get_setting("keys_encrypted").map(|v| v == "1").unwrap_or(false)
    }
}

/// Simple AES-256-CBC encryption with random IV
fn simple_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use cipher::block_padding::Pkcs7;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let iv: [u8; 16] = rand::random();
    let encryptor = Aes256CbcEnc::new(key.into(), &iv.into());
    let mut buffer = vec![0u8; plaintext.len() + 16]; // room for padding
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = encryptor.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len()).unwrap();
    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(ciphertext);
    result
}

/// Simple AES-256-CBC decryption
fn simple_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use cipher::block_padding::Pkcs7;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    if data.len() < 17 { // at least IV + 1 block
        return Err("data too short");
    }
    let iv = &data[..16];
    let ciphertext = &data[16..];
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let mut buffer = ciphertext.to_vec();
    let plaintext = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| "decryption failed")?;
    Ok(plaintext.to_vec())
}

/// Derive a 32-byte key from a password using SHA-256
pub fn derive_key_from_password(password: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"bitmessage-rs-key-derivation");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn dirs_or_default() -> PathBuf {
    if let Some(data_dir) = dirs_data_dir() {
        data_dir
    } else {
        PathBuf::from(".")
    }
}

fn dirs_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".local").join("share"))
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}
