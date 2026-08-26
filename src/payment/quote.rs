//! Portable construction of payment-quote signing bytes and EVM hashes.

use tiny_keccak::{Hasher as _, Keccak};

/// Construct the canonical bytes covered by a storage quote signature.
///
/// This is byte-for-byte equivalent to `evmlib::PaymentQuote::bytes_for_signing`
/// while accepting only portable fixed-width primitives.
#[must_use]
pub fn payment_quote_bytes_for_signing(
    content: &[u8; 32],
    timestamp_secs: u64,
    price_wei: u128,
    rewards_address: &[u8; 20],
    committed_key_count: u32,
    commitment_pin: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 8 + 32 + 20 + 4 + 33);
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(&timestamp_secs.to_le_bytes());
    bytes.extend_from_slice(&price_wei.to_le_bytes());
    // EVM Amount is U256; browser quote prices are currently bounded to u128.
    bytes.extend_from_slice(&[0u8; 16]);
    bytes.extend_from_slice(rewards_address);
    bytes.extend_from_slice(&committed_key_count.to_le_bytes());
    if let Some(pin) = commitment_pin {
        bytes.push(1);
        bytes.extend_from_slice(pin);
    } else {
        bytes.push(0);
    }
    bytes
}

/// Compute the Keccak-256 hash used as the EVM payment quote identifier.
#[must_use]
pub fn payment_quote_hash(signed_bytes: &[u8], public_key: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(signed_bytes);
    hasher.update(public_key);
    hasher.update(signature);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_hash_matches_evmlib_vector() {
        assert_eq!(
            hex::encode(payment_quote_hash(&[0, 1], &[2], &[3])),
            "d98f2e8134922f73748703c8e7084d42f13d2fa1439936ef5a3abcf5646fe83f"
        );
    }

    #[cfg(feature = "native")]
    #[test]
    fn portable_quote_encoding_matches_evmlib() {
        use evmlib::common::Amount;
        use evmlib::{PaymentQuote, RewardsAddress};
        use std::time::{Duration, SystemTime};

        let content = [0x31; 32];
        let timestamp_secs = 1_775_000_001;
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp_secs);
        let price_wei = 7_654_321_u128;
        let price = Amount::from(price_wei);
        let rewards = [0x42; 20];
        let rewards_address = RewardsAddress::from(rewards);
        let commitment_pin = Some([0x53; 32]);
        let public_key = vec![0x64; 17];
        let signature = vec![0x75; 23];
        let native = PaymentQuote {
            content: xor_name::XorName(content),
            timestamp,
            price,
            rewards_address,
            pub_key: public_key.clone(),
            signature: signature.clone(),
            committed_key_count: 23,
            commitment_pin,
        };
        let portable = payment_quote_bytes_for_signing(
            &content,
            timestamp_secs,
            price_wei,
            &rewards,
            23,
            commitment_pin.as_ref(),
        );

        assert_eq!(portable, native.bytes_for_sig());
        assert_eq!(
            payment_quote_hash(&portable, &public_key, &signature).as_slice(),
            native.hash().as_slice()
        );
    }
}
