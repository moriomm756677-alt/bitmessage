use sha2::{Sha512, Digest};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Default proof-of-work parameters
pub const DEFAULT_NONCE_TRIALS_PER_BYTE: u64 = 1000;
pub const DEFAULT_EXTRA_BYTES: u64 = 1000;

/// Maximum sanity-check difficulty
pub const RIDICULOUS_DIFFICULTY: u64 = 20_000_000;

/// Calculate PoW target value
///
/// target = 2^64 / (nonce_trials * (payload_len + extra_bytes + (ttl * (payload_len + extra_bytes)) / 2^16))
pub fn calculate_target(
    payload_length: u64,
    ttl: u64,
    nonce_trials_per_byte: u64,
    extra_bytes: u64,
) -> u64 {
    let trials = nonce_trials_per_byte.max(DEFAULT_NONCE_TRIALS_PER_BYTE);
    let extra = extra_bytes.max(DEFAULT_EXTRA_BYTES);
    let payload_with_extra = payload_length + extra;
    let ttl_factor = (ttl as u128 * payload_with_extra as u128) >> 16;
    let denominator = trials as u128 * (payload_with_extra as u128 + ttl_factor);

    if denominator == 0 {
        return u64::MAX;
    }

    ((1u128 << 64) / denominator).min(u64::MAX as u128) as u64
}

/// Perform proof of work: find a nonce such that the hash meets the target
///
/// Returns the 8-byte nonce. The `payload` should NOT include the nonce prefix.
pub fn do_pow(payload: &[u8], target: u64) -> u64 {
    let initial_hash = Sha512::digest(payload);
    let mut nonce: u64 = 0;

    loop {
        let mut hasher = Sha512::new();
        hasher.update(nonce.to_be_bytes());
        hasher.update(&initial_hash);
        let first_hash = hasher.finalize();
        let result_hash = Sha512::digest(&first_hash);

        let trial_value = u64::from_be_bytes([
            result_hash[0],
            result_hash[1],
            result_hash[2],
            result_hash[3],
            result_hash[4],
            result_hash[5],
            result_hash[6],
            result_hash[7],
        ]);

        if trial_value <= target {
            return nonce;
        }

        nonce = nonce.wrapping_add(1);
    }
}

/// Verify proof of work: check that the nonce in the payload satisfies the target
///
/// The `full_payload` includes the 8-byte nonce prefix.
pub fn check_pow(full_payload: &[u8], target: u64) -> bool {
    if full_payload.len() < 8 {
        return false;
    }

    let nonce = u64::from_be_bytes([
        full_payload[0],
        full_payload[1],
        full_payload[2],
        full_payload[3],
        full_payload[4],
        full_payload[5],
        full_payload[6],
        full_payload[7],
    ]);

    let payload_after_nonce = &full_payload[8..];
    let initial_hash = Sha512::digest(payload_after_nonce);

    let mut hasher = Sha512::new();
    hasher.update(nonce.to_be_bytes());
    hasher.update(&initial_hash);
    let first_hash = hasher.finalize();
    let result_hash = Sha512::digest(&first_hash);

    let trial_value = u64::from_be_bytes([
        result_hash[0],
        result_hash[1],
        result_hash[2],
        result_hash[3],
        result_hash[4],
        result_hash[5],
        result_hash[6],
        result_hash[7],
    ]);

    trial_value <= target
}

/// Try a single nonce, return trial_value
#[inline(always)]
fn try_nonce(nonce: u64, initial_hash: &[u8; 64]) -> u64 {
    let mut hasher = Sha512::new();
    hasher.update(nonce.to_be_bytes());
    hasher.update(initial_hash.as_slice());
    let first_hash = hasher.finalize();
    let result_hash = Sha512::digest(&first_hash);
    u64::from_be_bytes([
        result_hash[0], result_hash[1], result_hash[2], result_hash[3],
        result_hash[4], result_hash[5], result_hash[6], result_hash[7],
    ])
}

/// Multithreaded PoW with progress callback.
/// Splits the nonce space across all available CPU cores.
/// The callback receives the total number of attempts so far.
pub fn do_pow_with_progress<F>(payload: &[u8], target: u64, on_progress: F) -> u64
where
    F: FnMut(u64) + Send,
{
    let on_progress = std::sync::Mutex::new(on_progress);
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let initial_hash: [u8; 64] = Sha512::digest(payload).into();
    let found = Arc::new(AtomicBool::new(false));
    let result_nonce = Arc::new(AtomicU64::new(0));
    let total_attempts = Arc::new(AtomicU64::new(0));
    let on_progress = Arc::new(on_progress);

    std::thread::scope(|s| {
        for thread_id in 0..num_threads {
            let found = Arc::clone(&found);
            let result_nonce = Arc::clone(&result_nonce);
            let total_attempts = Arc::clone(&total_attempts);
            let on_progress = Arc::clone(&on_progress);
            let initial_hash = initial_hash;

            s.spawn(move || {
                let mut nonce = thread_id as u64;
                let step = num_threads as u64;
                let mut local_count: u64 = 0;

                while !found.load(Ordering::Relaxed) {
                    let trial_value = try_nonce(nonce, &initial_hash);

                    if trial_value <= target {
                        found.store(true, Ordering::Relaxed);
                        result_nonce.store(nonce, Ordering::Relaxed);
                        return;
                    }

                    nonce = nonce.wrapping_add(step);
                    local_count += 1;

                    if local_count % 100_000 == 0 {
                        let total = total_attempts.fetch_add(100_000, Ordering::Relaxed) + 100_000;
                        // Only one thread reports progress (thread 0)
                        if thread_id == 0 {
                            if let Ok(mut cb) = on_progress.lock() {
                                cb(total);
                            }
                        }
                    }
                }
            });
        }
    });

    result_nonce.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_roundtrip() {
        let payload = b"test payload for pow";
        let target = calculate_target(payload.len() as u64 + 8, 3600, 1000, 1000);
        let nonce = do_pow(payload, target);

        let mut full = nonce.to_be_bytes().to_vec();
        full.extend_from_slice(payload);
        assert!(check_pow(&full, target));
    }

    #[test]
    fn test_parallel_pow() {
        let payload = b"test parallel pow computation";
        let target = calculate_target(payload.len() as u64 + 8, 3600, 1000, 1000);
        let nonce = do_pow_with_progress(payload, target, |_| {});

        let mut full = nonce.to_be_bytes().to_vec();
        full.extend_from_slice(payload);
        assert!(check_pow(&full, target));
    }
}
