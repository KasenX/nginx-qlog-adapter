/// Bytes of QUIC Initial long header before the Length field
/// (flags + version + dcid_len + dcid + scid_len + scid + token_len=0x00 + length varint).
pub(crate) const QUIC_INITIAL_HEADER_OVERHEAD: u32 = 52;

/// Bytes of QUIC Handshake long header before the Length field
/// (same as Initial minus the 1-byte empty token length).
pub(crate) const QUIC_HANDSHAKE_HEADER_OVERHEAD: u32 = 51;

pub(crate) const REORDERING_THRESHOLD: u16 = 3;
pub(crate) const TIME_THRESHOLD: f32 = 1.125;
pub(crate) const TIMER_GRANULARITY_MS: u16 = 1;
pub(crate) const INITIAL_RTT_MS: u64 = 333;
pub(crate) const LOSS_REDUCTION_FACTOR: f32 = 0.7;
pub(crate) const PERSISTENT_CONGESTION_THRESHOLD: u16 = 3;
