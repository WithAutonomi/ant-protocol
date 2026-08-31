//! Shared WebRTC Direct transfer timing policy.
//!
//! WebRTC requests are split across ordered SCTP messages. A fixed deadline is
//! appropriate for headers and small control requests, but not for a full
//! [`crate::MAX_CHUNK_SIZE`] body competing with other replica uploads. Both
//! sides use this module so the sender never waits longer than the receiver is
//! willing to accept the same frame.

use std::time::Duration;

/// Time allowed for a header-only WebRTC Direct request.
pub const WEBRTC_TRANSFER_BASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Slowest sustained per-DataChannel frame rate accommodated by the protocol.
///
/// Uploads deliberately fan out to several peers. A conservative per-channel
/// floor keeps those parallel streams viable on ordinary residential uplinks.
pub const WEBRTC_MIN_TRANSFER_RATE_BYTES_PER_SEC: u64 = 32 * 1024;

/// Upper bound for one complete WebRTC Direct request or response transfer.
pub const WEBRTC_TRANSFER_MAX_TIMEOUT: Duration = Duration::from_secs(180);

/// Return the transfer deadline for a frame containing `frame_bytes` bytes.
///
/// The fixed base covers connection scheduling and latency. Transfer time is
/// added at [`WEBRTC_MIN_TRANSFER_RATE_BYTES_PER_SEC`] and clamped so a
/// permanently stalled channel is still discarded.
#[must_use]
pub fn transfer_timeout(frame_bytes: usize) -> Duration {
    let frame_bytes = u64::try_from(frame_bytes).unwrap_or(u64::MAX);
    let transfer_seconds = frame_bytes.div_ceil(WEBRTC_MIN_TRANSFER_RATE_BYTES_PER_SEC);
    WEBRTC_TRANSFER_BASE_TIMEOUT
        .saturating_add(Duration::from_secs(transfer_seconds))
        .min(WEBRTC_TRANSFER_MAX_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_timeout_scales_with_body_size() {
        assert_eq!(transfer_timeout(0), Duration::from_secs(10));
        assert_eq!(transfer_timeout(32 * 1024), Duration::from_secs(11));
        assert_eq!(
            transfer_timeout(crate::MAX_CHUNK_SIZE),
            Duration::from_secs(138)
        );
        assert_eq!(
            transfer_timeout(crate::MAX_CHUNK_SIZE + 1),
            Duration::from_secs(139)
        );
    }

    #[test]
    fn transfer_timeout_is_capped() {
        assert_eq!(transfer_timeout(usize::MAX), WEBRTC_TRANSFER_MAX_TIMEOUT);
    }
}
