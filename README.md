# Bitmessage-RS

A decentralized, encrypted messaging client implementing the [Bitmessage protocol](https://wiki.bitmessage.org/) in Rust. All connections are routed through **Tor** (via [arti](https://gitlab.torproject.org/tpo/core/arti)).

Built with **Rust** + **egui** for the GUI.

## Features

- Full Bitmessage protocol v3 implementation
- End-to-end ECIES encryption (secp256k1)
- All traffic routed through Tor (arti-client)
- Multiple identities management
- Contacts, channels, subscriptions, blacklist
- Broadcast messages
- Proof of Work (PoW) for spam prevention
- ACK delivery confirmation
- SQLite persistent storage
- System tray support
- Dark theme UI

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

On first launch, the app will bootstrap a Tor connection (may take 30-60 seconds), then connect to Bitmessage network peers.

## Architecture: Message Send & Receive

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SENDING A MESSAGE                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. ADDRESSING                                                          │
│     ┌──────────────────┐                                                │
│     │ BM-2cX7... addr  │──→ Base58 decode ──→ version, stream,          │
│     └──────────────────┘                      RIPE hash (20 bytes)      │
│                                                                         │
│  2. RECIPIENT KEY LOOKUP                                                │
│     ┌──────────┐    ┌────────┐    ┌──────────────────────┐              │
│     │ Local DB │──→ │ Found? │─N─→│ Send getpubkey       │              │
│     └──────────┘    └────────┘    │ to the network       │              │
│                          │Y       │ (wait for response)  │              │
│                          ▼        └──────────────────────┘              │
│     ┌──────────────────────────────────┐                                │
│     │ Recipient's public keys:         │                                │
│     │   • signing_key  (EC point)      │                                │
│     │   • encryption_key (EC point)    │                                │
│     └──────────────────────────────────┘                                │
│                                                                         │
│  3. MESSAGE ASSEMBLY                                                    │
│     ┌────────────────────────────────────────────┐                      │
│     │ msg_version │ sender_addr_version           │                      │
│     │ sender_stream │ bitfield (INCLUDE_DEST)     │                      │
│     │ sender_signing_key (64 bytes)               │                      │
│     │ sender_encryption_key (64 bytes)            │                      │
│     │ sender_nonce_trials │ sender_extra_bytes    │                      │
│     │ dest_ripe (20 bytes)                        │                      │
│     │ encoding_type (2 = simple)                  │                      │
│     │ "Subject: ...\nBody: ..."                   │                      │
│     │ ack_data (full msg object for ACK)          │                      │
│     │ ECDSA signature (DER, signing_key)          │                      │
│     └────────────────────────────────────────────┘                      │
│                                                                         │
│  4. ECIES ENCRYPTION (Elliptic Curve Integrated Encryption Scheme)      │
│     ┌─────────────────────────────────────────────────────┐             │
│     │ 1. Generate ephemeral key pair (k, K = k*G)         │             │
│     │ 2. ECDH: shared_secret = k * recipient_pubkey       │             │
│     │ 3. KDF: key_data = SHA-512(shared_secret)           │             │
│     │    ├── key_e = key_data[0..32]  (AES-256 key)       │             │
│     │    └── key_m = key_data[32..64] (HMAC key)          │             │
│     │ 4. AES-256-CBC encrypt(key_e, IV, plaintext)        │             │
│     │ 5. HMAC-SHA-256(key_m, ciphertext)                  │             │
│     │                                                     │             │
│     │ Output: IV │ curve_type │ X_len │ X │ Y_len │ Y     │             │
│     │         │ ciphertext │ MAC (32 bytes)                │             │
│     └─────────────────────────────────────────────────────┘             │
│                                                                         │
│  5. OBJECT WRAPPING                                                     │
│     ┌───────────────────────────────────────────────┐                   │
│     │ nonce (8 bytes) │ expires_time (8 bytes)       │                   │
│     │ object_type = 2 (msg) │ version │ stream       │                   │
│     │ encrypted_payload                              │                   │
│     └───────────────────────────────────────────────┘                   │
│                                                                         │
│  6. PROOF OF WORK                                                       │
│     ┌─────────────────────────────────────────────────────┐             │
│     │ Find nonce such that:                               │             │
│     │ SHA-512(SHA-512(nonce ∥ initial_hash)) has           │             │
│     │ enough leading zeros                                │             │
│     │                                                     │             │
│     │ target = 2^64 / (nonceTrials *                      │             │
│     │          (payload_len + 8 + extraBytes))            │             │
│     │                                                     │             │
│     │ trial_value (first 8 bytes of hash) < target        │             │
│     └─────────────────────────────────────────────────────┘             │
│                                                                         │
│  7. BROADCAST VIA TOR                                                   │
│     ┌──────────┐    ┌────────────┐    ┌──────────────────┐              │
│     │ Object   │──→ │ Tor Circuit│──→ │ Bitmessage Peers │              │
│     │ with PoW │    │ (arti)     │    │ (flood fill)     │              │
│     └──────────┘    └────────────┘    └──────────────────┘              │
│                                                                         │
│     Every peer stores the encrypted blob in their inventory.            │
│     Nobody except the recipient can decrypt it.                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                       RECEIVING A MESSAGE                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. OBJECT ARRIVAL (from Tor peer)                                      │
│     ┌──────────────────────────────────────────────┐                    │
│     │ Receive inv → getdata → object (type=2 msg)  │                    │
│     └──────────────────────────────────────────────┘                    │
│                                                                         │
│  2. PROOF OF WORK VERIFICATION                                          │
│     ┌──────────────────────────────────────────────┐                    │
│     │ Verify: trial_value < target                  │                    │
│     │ Reject if PoW is insufficient                 │                    │
│     └──────────────────────────────────────────────┘                    │
│                                                                         │
│  3. DECRYPTION ATTEMPT (try each local identity)                        │
│     ┌────────────────────────────────────────────────────┐              │
│     │ For each identity (private_key):                   │              │
│     │   1. ECDH: shared_secret = priv_key * ephemeral_K  │              │
│     │   2. KDF: SHA-512(shared_secret) → key_e, key_m    │              │
│     │   3. Verify HMAC-SHA-256(key_m, ciphertext)        │              │
│     │      ├── HMAC mismatch → not for this identity     │              │
│     │      └── HMAC match → decrypt!                     │              │
│     │   4. AES-256-CBC decrypt(key_e, IV, ciphertext)    │              │
│     └────────────────────────────────────────────────────┘              │
│                                                                         │
│  4. MESSAGE VERIFICATION                                                │
│     ┌────────────────────────────────────────────────────┐              │
│     │ 1. Parse message fields from plaintext              │              │
│     │ 2. Check dest_ripe matches our identity             │              │
│     │ 3. Verify ECDSA signature with sender_signing_key   │              │
│     │ 4. Check sender address matches their public keys   │              │
│     └────────────────────────────────────────────────────┘              │
│                                                                         │
│  5. ACK DELIVERY                                                        │
│     ┌────────────────────────────────────────────────────┐              │
│     │ 1. Extract ack_data from message                    │              │
│     │ 2. Broadcast ack object to the network              │              │
│     │ 3. Sender receives ACK → marks message delivered    │              │
│     └────────────────────────────────────────────────────┘              │
│                                                                         │
│  6. STORAGE                                                             │
│     ┌────────────────────────────────────────────────────┐              │
│     │ Save to SQLite: sender, subject, body, timestamp    │              │
│     │ Store sender's pubkey for future replies             │              │
│     └────────────────────────────────────────────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
src/
├── main.rs                 # Entry point, tray icon setup
├── crypto/
│   ├── address.rs          # Bitmessage address encoding/decoding
│   ├── ecies.rs            # ECIES encrypt/decrypt (secp256k1)
│   ├── keys.rs             # Key generation, signing, ECDH
│   └── pow.rs              # Proof of Work computation
├── protocol/
│   ├── messages.rs         # Protocol message serialization
│   ├── objects.rs          # Network objects (msg, broadcast, pubkey, getpubkey)
│   └── types.rs            # Shared types (VarInt, NetworkAddress, etc.)
├── network/
│   ├── mod.rs              # NetworkEvent enum, constants
│   └── peer.rs             # Tor connection, peer management, message handling
├── storage/
│   └── db.rs               # SQLite database (identities, messages, contacts, etc.)
└── ui/
    ├── app.rs              # Main application state and event loop
    ├── theme.rs            # Dark theme colors, icons, styling
    ├── inbox.rs            # Inbox/Sent/Trash views with multi-select
    ├── compose.rs          # Message composition
    ├── identities.rs       # Identity management
    ├── contacts.rs         # Contact management
    ├── channels.rs         # Channel management
    ├── blacklist.rs        # Blacklist management
    ├── settings.rs         # Settings and network status views
    ├── bbcode.rs           # BBCode rendering
    └── tray.rs             # System tray integration
```

## License

MIT
