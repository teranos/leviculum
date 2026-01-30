//! Protocol constants matching the Python Reticulum implementation

// ─── Utility Functions ───────────────────────────────────────────────────────

/// Convert a slice to a fixed-size array by copying bytes from the given offset.
///
/// # Panics
/// Panics if `src.len() < offset + N`.
#[inline]
pub fn slice_to_array<const N: usize>(src: &[u8], offset: usize) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(&src[offset..offset + N]);
    arr
}

// ─── Protocol Constants ──────────────────────────────────────────────────────

/// Physical layer MTU in bytes
pub const MTU: usize = 500;

/// Truncated hash length in bits (for destination addresses)
pub const TRUNCATED_HASHLENGTH: usize = 128;

/// Truncated hash length in bytes
pub const TRUNCATED_HASHBYTES: usize = TRUNCATED_HASHLENGTH / 8; // 16 bytes

/// Identity hash length in bytes
pub const IDENTITY_HASHBYTES: usize = 16;

/// Name hash length in bytes
pub const NAME_HASHBYTES: usize = 10;

/// Random hash length in bytes (for announces)
pub const RANDOM_HASHBYTES: usize = 10;

/// Minimum header size (Header Type 1)
/// flags(1) + hops(1) + destination_hash(16) + context(1) = 19
pub const HEADER_MINSIZE: usize = 2 + 1 + TRUNCATED_HASHBYTES;

/// Maximum header size (Header Type 2 with transport ID)
/// flags(1) + hops(1) + transport_id(16) + destination_hash(16) + context(1) = 35
pub const HEADER_MAXSIZE: usize = 2 + 1 + TRUNCATED_HASHBYTES * 2;

/// Maximum data unit (payload after headers)
/// Formula: MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE = 500 - 35 - 1 = 464 bytes
/// The IFAC_MIN_SIZE accounts for the minimum Interface Access Code size that
/// may be present in packets transmitted over authenticated interfaces.
pub const MDU: usize = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE;

/// Default per-hop timeout in seconds
pub const DEFAULT_PER_HOP_TIMEOUT: u64 = 6;

/// Key sizes
pub const X25519_KEY_SIZE: usize = 32;
pub const ED25519_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const IDENTITY_KEY_SIZE: usize = X25519_KEY_SIZE + ED25519_KEY_SIZE; // 64 bytes

/// AES block size
pub const AES_BLOCK_SIZE: usize = 16;

/// AES-256 key size
pub const AES256_KEY_SIZE: usize = 32;

/// HMAC-SHA256 output size
pub const HMAC_SIZE: usize = 32;

/// Token overhead (IV + HMAC)
pub const TOKEN_OVERHEAD: usize = AES_BLOCK_SIZE + HMAC_SIZE; // 48 bytes

/// Ratchet constants
pub const RATCHET_SIZE: usize = 32;
pub const RATCHET_EXPIRY_SECS: u64 = 60 * 60 * 24 * 30; // 30 days
pub const RATCHET_INTERVAL_SECS: u64 = 60 * 30; // 30 minutes

/// Transport constants
pub const PATHFINDER_MAX_HOPS: u8 = 128;
pub const PATHFINDER_RETRIES: u8 = 1;
pub const PATHFINDER_EXPIRY_SECS: u64 = 60 * 60 * 24 * 7; // 7 days
pub const PATH_REQUEST_GRACE_SECS: f64 = 0.4;

/// Link constants
pub const LINK_KEEPALIVE_SECS: u64 = 360; // 6 minutes
pub const LINK_STALE_FACTOR: u64 = 2;
pub const LINK_STALE_TIME_SECS: u64 = LINK_STALE_FACTOR * LINK_KEEPALIVE_SECS;
pub const LINK_KEEPALIVE_TIMEOUT_FACTOR: u64 = 4;

/// Resource constants
pub const RESOURCE_WINDOW_INITIAL: usize = 4;
pub const RESOURCE_WINDOW_MIN: usize = 2;
pub const RESOURCE_WINDOW_MAX_SLOW: usize = 10;
pub const RESOURCE_WINDOW_MAX_FAST: usize = 75;
pub const RESOURCE_HASHMAP_LEN: usize = 4;
pub const RESOURCE_AUTO_COMPRESS_MAX: usize = 64 * 1024 * 1024; // 64 MB

/// Interface Access Code minimum size
pub const IFAC_MIN_SIZE: usize = 1;

/// Interface Access Code default size for serial interfaces (8 bytes)
pub const IFAC_DEFAULT_SIZE_SERIAL: usize = 8;

/// Interface Access Code default size for network interfaces (16 bytes)
pub const IFAC_DEFAULT_SIZE_NETWORK: usize = 16;

/// IFAC salt for HKDF key derivation (32 bytes)
/// This is a fixed constant from Python Reticulum
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
    0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
    0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];
