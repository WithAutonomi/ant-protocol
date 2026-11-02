//! Golden wire-format vectors.
//!
//! Every other serialization test in this crate round-trips in-process: encode
//! a value, decode it, compare. That proves nothing about compatibility. A
//! reordered field, an inserted enum variant or a serializer bump changes the
//! bytes on both sides of the round trip at once, so it passes, and only
//! breaks when an `ant-node` and an `ant-client` built from different versions
//! talk to each other.
//!
//! These tests pin the bytes instead. `tests/golden/wire-v5.txt` holds one
//! vector per wire type, captured from `ant-protocol` 5.0.1. Each test builds
//! the same value from fixed inputs and checks that:
//!
//! 1. encoding it gives exactly the captured bytes;
//! 2. decoding the captured bytes gives exactly that value, field by field;
//! 3. re-encoding the decoded value gives the captured bytes again.
//!
//! Check 2 is the one that catches a swap of two same-typed fields, which the
//! other two cannot see: postcard and rmp both encode by position, so a swapped
//! decode re-encodes to the same bytes. Every fixture therefore uses a
//! distinct value per field.
//!
//! **A failure here means the wire format changed**, which is a breaking change
//! for every deployed peer. Don't make it pass by re-capturing. If the change
//! is a deliberate, coordinated cutover, delete the affected lines from the
//! vector file and run the tests once with `ANT_PROTOCOL_WRITE_GOLDEN=1`, which
//! appends missing vectors and never overwrites existing ones, and say so in
//! the changelog.
//!
//! Signature and public-key fields inside quotes, candidates and commitments
//! are short stand-in bytes. The wire carries them as opaque byte strings, so
//! their validity is not a wire property, and real ones would make each
//! vector about 10 KB. The pointer vector is the exception: decoding a pointer
//! verifies its signature, so it carries a real ML-DSA-65 key and signature.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use ant_protocol::evm::{
    Address, Amount, EncodedPeerId, MerklePaymentCandidateNode, MerklePaymentCandidatePool,
    MerklePaymentProof, MerkleTree, PaymentQuote, ProofOfPayment, TxHash,
};
use ant_protocol::payment::commitment::{
    commitment_hash, commitment_signed_payload, StorageCommitment,
};
use ant_protocol::pqc::api::ml_dsa_65;
use ant_protocol::{
    deserialize_merkle_proof, deserialize_proof, serialize_merkle_proof,
    serialize_single_node_proof, state_id_for_body, ChunkGetRequest, ChunkGetResponse,
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteRequestV2, ChunkQuoteResponse, MerkleCandidateQuoteRequest,
    MerkleCandidateQuoteRequestV2, MerkleCandidateQuoteResponse, PaymentProof, Pointer,
    PointerGetRequest, PointerGetResponse, PointerPutRequest, PointerPutResponse, PointerTarget,
    PointerTargetKind, ProtocolError, CURRENT_SETTLEMENT_VERSION, DATA_TYPE_CHUNK,
    POINTER_BODY_LEN, POINTER_WIRE_LEN, PROOF_TAG_MERKLE, PROOF_TAG_SINGLE_NODE,
};
use bytes::Bytes;
use serde::Serialize;
use xor_name::XorName;

// =============================================================================
// Vector file
// =============================================================================

/// The captured vectors, relative to the crate root. One `name hex` pair per
/// line; `#` starts a comment.
const VECTOR_FILE: &str = "tests/golden/wire-v5.txt";

/// Set to append vectors that are missing from [`VECTOR_FILE`].
const WRITE_ENV: &str = "ANT_PROTOCOL_WRITE_GOLDEN";

/// Serializes appends when the tests run in parallel.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTOR_FILE)
}

fn load_vectors() -> BTreeMap<String, Vec<u8>> {
    let text = std::fs::read_to_string(vector_path()).unwrap_or_default();
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, hex_bytes) = line
                .split_once(char::is_whitespace)
                .unwrap_or_else(|| panic!("`{line}` is not a `name hex` line"));
            let bytes = hex::decode(hex_bytes.trim())
                .unwrap_or_else(|e| panic!("vector `{name}` is not valid hex: {e}"));
            (name.to_string(), bytes)
        })
        .collect()
}

/// The captured bytes for `name`.
///
/// `fresh` is what this build encodes. It's only used when the vector is
/// missing: printed in the failure, or appended under [`WRITE_ENV`].
fn golden(name: &str, fresh: &[u8]) -> Vec<u8> {
    if let Some(bytes) = load_vectors().remove(name) {
        return bytes;
    }
    if std::env::var_os(WRITE_ENV).is_some() {
        let _guard = WRITE_LOCK.lock().unwrap();
        if let Some(bytes) = load_vectors().remove(name) {
            return bytes;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(vector_path())
            .unwrap();
        writeln!(file, "{name} {}", hex::encode(fresh)).unwrap();
        return fresh.to_vec();
    }
    panic!(
        "no vector `{name}` in {VECTOR_FILE}; this build encodes it as\n{}\n\
         (set {WRITE_ENV}=1 to append missing vectors)",
        hex::encode(fresh)
    );
}

fn assert_bytes(name: &str, what: &str, actual: &[u8], golden: &[u8]) {
    assert!(
        actual == golden,
        "{name}: {what} no longer matches the captured wire bytes. The wire format \
         changed; see the module docs before touching the vector.\n  captured: {}\n  \
         now:      {}",
        hex::encode(golden),
        hex::encode(actual),
    );
}

/// The three checks from the module docs, for one value.
///
/// `same` compares a decoded value with the expected one. Use `PartialEq`
/// where the type has it. Otherwise compare `Debug` output, but only for types
/// whose `Debug` prints every field (`PaymentQuote`'s doesn't).
fn check<T: Debug>(
    name: &str,
    expected: &T,
    encode: impl Fn(&T) -> Vec<u8>,
    decode: impl Fn(&[u8]) -> T,
    same: impl Fn(&T, &T) -> bool,
) {
    let fresh = encode(expected);
    let golden = golden(name, &fresh);
    assert_bytes(name, "encoding", &fresh, &golden);
    let decoded = decode(&golden);
    assert!(
        same(&decoded, expected),
        "{name}: the captured bytes decode to a different value\n  decoded:  \
         {decoded:?}\n  expected: {expected:?}",
    );
    assert_bytes(name, "re-encoding", &encode(&decoded), &golden);
}

/// For derived values with no decoder of their own (hashes, signed payloads).
fn check_derived(name: &str, fresh: &[u8]) {
    let golden = golden(name, fresh);
    assert_bytes(name, "value", fresh, &golden);
}

// =============================================================================
// Encoders, one per wire format
// =============================================================================

/// `ChunkMessage`: postcard, through the crate's own codec.
fn check_message(name: &str, request_id: u64, body: ChunkMessageBody) {
    let expected = ChunkMessage { request_id, body };
    check(
        name,
        &expected,
        |m| m.encode().unwrap(),
        |b| ChunkMessage::decode(b).unwrap(),
        |a, b| format!("{a:?}") == format!("{b:?}"),
    );
}

/// `MessagePack`, as the node encodes quotes, candidates and commitment
/// sidecars (`rmp_serde::to_vec`).
fn rmp<T: Serialize>(value: &T) -> Vec<u8> {
    rmp_serde::to_vec(value).unwrap()
}

// =============================================================================
// Fixtures
// =============================================================================

/// 32 distinct bytes starting at `seed`.
fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (byte, offset) in out.iter_mut().zip(0u8..) {
        *byte = seed.wrapping_add(offset);
    }
    out
}

/// 20 distinct bytes starting at `seed`.
fn bytes20(seed: u8) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (byte, offset) in out.iter_mut().zip(0u8..) {
        *byte = seed.wrapping_add(offset);
    }
    out
}

const REQUEST_ID: u64 = 0x0102_0304_0506_0708;
const ADDRESS: [u8; 32] = [0xA0; 32];
const STATE_ID: [u8; 32] = [0xA1; 32];
const DATA_SIZE: u64 = 4_194_303;
const MERKLE_TIMESTAMP: u64 = 1_785_855_600;

fn payment_proof_bytes() -> Vec<u8> {
    vec![PROOF_TAG_SINGLE_NODE, 0xDE, 0xAD, 0xBE, 0xEF]
}

fn quote(seed: u8, committed: bool) -> PaymentQuote {
    PaymentQuote {
        content: XorName(bytes32(seed)),
        timestamp: UNIX_EPOCH + Duration::new(1_785_855_000 + u64::from(seed), 123_456_789),
        price: Amount::from(1_000_000_007_u64 + u64::from(seed)),
        rewards_address: Address::new(bytes20(seed ^ 0x55)),
        pub_key: vec![0xB0, seed, 0x01],
        signature: vec![0x5A, seed, 0x02, 0x03],
        committed_key_count: if committed {
            4_096 + u32::from(seed)
        } else {
            0
        },
        commitment_pin: committed.then(|| bytes32(seed ^ 0xC0)),
    }
}

fn commitment() -> StorageCommitment {
    StorageCommitment {
        root: bytes32(0x30),
        key_count: 4_096,
        sender_peer_id: bytes32(0x40),
        sender_public_key: vec![0xB1, 0xB2, 0xB3],
        signature: vec![0x5B, 0x5C, 0x5D, 0x5E],
    }
}

/// Even candidates are baseline quotes, odd ones pin a commitment, so the
/// pool covers both shapes.
fn candidate(i: u8) -> MerklePaymentCandidateNode {
    let committed = i % 2 == 1;
    MerklePaymentCandidateNode {
        pub_key: vec![0xC1, i],
        price: Amount::from(500_000_u64 + u64::from(i)),
        reward_address: Address::new(bytes20(i)),
        merkle_payment_timestamp: MERKLE_TIMESTAMP + 1,
        signature: vec![0x5C, i, 0x09],
        committed_key_count: if committed { 128 + u32::from(i) } else { 0 },
        commitment_pin: committed.then(|| bytes32(0xD0 ^ i)),
    }
}

/// A merkle tree built from fixed leaves and salts.
///
/// `MerkleTree::from_xornames` salts and pads with random bytes, so this goes
/// through the tree's persisted form instead, which is `{ leaves, salts }`.
/// If evmlib changes that form, this fixture fails to decode; that's a fixture
/// problem, not a wire change.
fn merkle_tree() -> MerkleTree {
    #[derive(Serialize)]
    struct TreeSnapshot {
        leaves: Vec<[u8; 32]>,
        salts: Vec<[u8; 32]>,
    }
    let snapshot = TreeSnapshot {
        leaves: (0x60..0x64).map(bytes32).collect(),
        salts: (0x70..0x74).map(bytes32).collect(),
    };
    rmp_serde::from_slice(&rmp(&snapshot)).unwrap()
}

fn merkle_proof() -> MerklePaymentProof {
    let tree = merkle_tree();
    let address = XorName(bytes32(0x61));
    let data_proof = tree.generate_address_proof(1, address).unwrap();
    let midpoint_proof = tree
        .reward_candidates(MERKLE_TIMESTAMP + 1)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let winner_pool = MerklePaymentCandidatePool {
        midpoint_proof,
        candidate_nodes: std::array::from_fn(|i| candidate(u8::try_from(i).unwrap())),
    };
    let mut proof = MerklePaymentProof::new(address, data_proof, winner_pool);
    proof.commitment_sidecars = vec![rmp(&commitment())];
    proof
}

fn single_node_proof() -> PaymentProof {
    PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: vec![
                (EncodedPeerId::new(bytes32(0x90)), quote(1, false)),
                (EncodedPeerId::new(bytes32(0x91)), quote(2, true)),
            ],
        },
        tx_hashes: vec![TxHash::new(bytes32(0xE0))],
        commitment_sidecars: vec![rmp(&commitment())],
    }
}

/// Every `ProtocolError` variant, with distinct field values.
fn protocol_errors() -> Vec<(&'static str, ProtocolError)> {
    vec![
        (
            "serialization_failed",
            ProtocolError::SerializationFailed("ser".into()),
        ),
        (
            "deserialization_failed",
            ProtocolError::DeserializationFailed("de".into()),
        ),
        (
            "message_too_large",
            ProtocolError::MessageTooLarge {
                size: 5_242_881,
                max_size: 5_242_880,
            },
        ),
        (
            "chunk_too_large",
            ProtocolError::ChunkTooLarge {
                size: 4_194_305,
                max_size: 4_194_304,
            },
        ),
        (
            "address_mismatch",
            ProtocolError::AddressMismatch {
                expected: bytes32(0x01),
                actual: bytes32(0x81),
            },
        ),
        (
            "storage_failed",
            ProtocolError::StorageFailed("disk".into()),
        ),
        (
            "payment_failed",
            ProtocolError::PaymentFailed("unpaid".into()),
        ),
        ("quote_failed", ProtocolError::QuoteFailed("busy".into())),
        ("internal", ProtocolError::Internal("oops".into())),
        (
            "client_update_required",
            ProtocolError::ClientUpdateRequired {
                client_settlement_version: 3,
                min_settlement_version: 4,
            },
        ),
        (
            "storer_update_required",
            ProtocolError::StorerUpdateRequired {
                client_settlement_version: 6,
                node_settlement_version: 5,
            },
        ),
    ]
}

fn protocol_error() -> ProtocolError {
    ProtocolError::Internal("wire".into())
}

// =============================================================================
// ChunkMessage: chunks
// =============================================================================

#[test]
fn chunk_put_request() {
    check_message(
        "chunk.put_request",
        REQUEST_ID,
        ChunkMessageBody::PutRequest(ChunkPutRequest::new(
            ADDRESS,
            Bytes::from_static(b"golden chunk"),
        )),
    );
    check_message(
        "chunk.put_request.paid",
        REQUEST_ID + 1,
        ChunkMessageBody::PutRequest(ChunkPutRequest::with_payment(
            ADDRESS,
            Bytes::from_static(b"golden chunk"),
            payment_proof_bytes(),
        )),
    );
}

#[test]
fn chunk_put_response() {
    let cases = [
        ("success", ChunkPutResponse::Success { address: ADDRESS }),
        (
            "already_exists",
            ChunkPutResponse::AlreadyExists { address: ADDRESS },
        ),
        (
            "payment_required",
            ChunkPutResponse::PaymentRequired {
                message: "pay first".into(),
            },
        ),
        ("error", ChunkPutResponse::Error(protocol_error())),
    ];
    for (variant, response) in cases {
        check_message(
            &format!("chunk.put_response.{variant}"),
            REQUEST_ID,
            ChunkMessageBody::PutResponse(response),
        );
    }
}

#[test]
fn chunk_get_request() {
    check_message(
        "chunk.get_request",
        REQUEST_ID,
        ChunkMessageBody::GetRequest(ChunkGetRequest::new(ADDRESS)),
    );
}

#[test]
fn chunk_get_response() {
    let cases = [
        (
            "success",
            ChunkGetResponse::Success {
                address: ADDRESS,
                content: b"golden chunk".to_vec(),
            },
        ),
        ("not_found", ChunkGetResponse::NotFound { address: ADDRESS }),
        ("error", ChunkGetResponse::Error(protocol_error())),
    ];
    for (variant, response) in cases {
        check_message(
            &format!("chunk.get_response.{variant}"),
            REQUEST_ID,
            ChunkMessageBody::GetResponse(response),
        );
    }
}

// =============================================================================
// ChunkMessage: quotes
// =============================================================================

#[test]
fn chunk_quote_request() {
    check_message(
        "chunk.quote_request",
        REQUEST_ID,
        ChunkMessageBody::QuoteRequest(ChunkQuoteRequest::new(ADDRESS, DATA_SIZE)),
    );
}

#[test]
fn chunk_quote_request_v2() {
    let request = ChunkQuoteRequestV2::new(ADDRESS, DATA_SIZE);
    assert_eq!(request.settlement_version, CURRENT_SETTLEMENT_VERSION);
    check_message(
        "chunk.quote_request_v2",
        REQUEST_ID,
        ChunkMessageBody::QuoteRequestV2(request),
    );
}

#[test]
fn chunk_quote_response() {
    let cases = [
        (
            "success",
            ChunkQuoteResponse::Success {
                quote: rmp(&quote(3, true)),
                already_stored: false,
                commitment: Some(rmp(&commitment())),
            },
        ),
        (
            "success.baseline",
            ChunkQuoteResponse::Success {
                quote: rmp(&quote(4, false)),
                already_stored: true,
                commitment: None,
            },
        ),
        ("error", ChunkQuoteResponse::Error(protocol_error())),
    ];
    for (variant, response) in cases {
        check_message(
            &format!("chunk.quote_response.{variant}"),
            REQUEST_ID,
            ChunkMessageBody::QuoteResponse(response),
        );
    }
}

#[test]
fn merkle_candidate_quote_request() {
    check_message(
        "chunk.merkle_candidate_quote_request",
        REQUEST_ID,
        ChunkMessageBody::MerkleCandidateQuoteRequest(MerkleCandidateQuoteRequest {
            address: ADDRESS,
            data_type: DATA_TYPE_CHUNK,
            data_size: DATA_SIZE,
            merkle_payment_timestamp: MERKLE_TIMESTAMP,
        }),
    );
}

#[test]
fn merkle_candidate_quote_request_v2() {
    check_message(
        "chunk.merkle_candidate_quote_request_v2",
        REQUEST_ID,
        ChunkMessageBody::MerkleCandidateQuoteRequestV2(MerkleCandidateQuoteRequestV2::new(
            ADDRESS,
            DATA_SIZE,
            MERKLE_TIMESTAMP,
        )),
    );
}

#[test]
fn merkle_candidate_quote_response() {
    let cases = [
        (
            "success",
            MerkleCandidateQuoteResponse::Success {
                candidate_node: rmp(&candidate(5)),
                commitment: Some(rmp(&commitment())),
            },
        ),
        (
            "error",
            MerkleCandidateQuoteResponse::Error(protocol_error()),
        ),
    ];
    for (variant, response) in cases {
        check_message(
            &format!("chunk.merkle_candidate_quote_response.{variant}"),
            REQUEST_ID,
            ChunkMessageBody::MerkleCandidateQuoteResponse(response),
        );
    }
}

// =============================================================================
// ChunkMessage: pointers
// =============================================================================

#[test]
fn pointer_put_request() {
    let record = Bytes::from_static(b"stand-in pointer record");
    check_message(
        "chunk.pointer_put_request",
        REQUEST_ID,
        ChunkMessageBody::PointerPutRequest(PointerPutRequest::new(record.clone())),
    );
    check_message(
        "chunk.pointer_put_request.paid",
        REQUEST_ID,
        ChunkMessageBody::PointerPutRequest(PointerPutRequest::with_payment(
            record,
            payment_proof_bytes(),
        )),
    );
}

#[test]
fn pointer_put_response() {
    let cases = [
        (
            "success",
            PointerPutResponse::Success {
                address: ADDRESS,
                state_id: STATE_ID,
            },
        ),
        (
            "unchanged",
            PointerPutResponse::Unchanged {
                address: ADDRESS,
                state_id: STATE_ID,
            },
        ),
        (
            "stale",
            PointerPutResponse::Stale {
                address: ADDRESS,
                state_id: STATE_ID,
            },
        ),
        (
            "payment_required",
            PointerPutResponse::PaymentRequired {
                message: "pay first".into(),
            },
        ),
        ("error", PointerPutResponse::Error(protocol_error())),
    ];
    for (variant, response) in cases {
        check_message(
            &format!("chunk.pointer_put_response.{variant}"),
            REQUEST_ID,
            ChunkMessageBody::PointerPutResponse(response),
        );
    }
}

#[test]
fn pointer_get_request() {
    check_message(
        "chunk.pointer_get_request",
        REQUEST_ID,
        ChunkMessageBody::PointerGetRequest(PointerGetRequest::new(ADDRESS)),
    );
}

#[test]
fn pointer_get_response() {
    let cases = [
        (
            "success",
            PointerGetResponse::Success {
                record: Bytes::from_static(b"stand-in pointer record"),
            },
        ),
        (
            "not_found",
            PointerGetResponse::NotFound { address: ADDRESS },
        ),
        ("error", PointerGetResponse::Error(protocol_error())),
    ];
    for (variant, response) in cases {
        check_message(
            &format!("chunk.pointer_get_response.{variant}"),
            REQUEST_ID,
            ChunkMessageBody::PointerGetResponse(response),
        );
    }
}

// =============================================================================
// ProtocolError
// =============================================================================

/// Every variant, encoded on its own. It travels inside the responses above,
/// where postcard writes exactly these bytes.
#[test]
fn protocol_error_variants() {
    for (variant, error) in protocol_errors() {
        check(
            &format!("protocol_error.{variant}"),
            &error,
            |e| postcard::to_stdvec(e).unwrap(),
            |b| postcard::from_bytes(b).unwrap(),
            PartialEq::eq,
        );
    }
}

// =============================================================================
// Payloads inside the messages (MessagePack)
// =============================================================================

/// `ChunkQuoteResponse::Success::quote`.
#[test]
fn payment_quote() {
    for (variant, value) in [("baseline", quote(6, false)), ("committed", quote(7, true))] {
        check(
            &format!("payment_quote.{variant}"),
            &value,
            rmp,
            |b| rmp_serde::from_slice(b).unwrap(),
            PartialEq::eq,
        );
    }
}

/// `MerkleCandidateQuoteResponse::Success::candidate_node`.
#[test]
fn merkle_candidate_node() {
    for (variant, value) in [("baseline", candidate(8)), ("committed", candidate(9))] {
        check(
            &format!("merkle_candidate_node.{variant}"),
            &value,
            rmp,
            |b| rmp_serde::from_slice(b).unwrap(),
            PartialEq::eq,
        );
    }
}

/// The commitment as it travels (quote-response `commitment`, proof
/// `commitment_sidecars`), and the pin a quote names it by.
///
/// The pin hashes the **postcard** encoding, not the `MessagePack` one on
/// the wire, so both are pinned: a postcard layout change would silently
/// change every pin, and every quote would stop resolving to its commitment.
#[test]
fn storage_commitment() {
    let value = commitment();
    check(
        "storage_commitment.rmp",
        &value,
        rmp,
        |b| rmp_serde::from_slice(b).unwrap(),
        PartialEq::eq,
    );
    check(
        "storage_commitment.postcard",
        &value,
        |c| postcard::to_stdvec(c).unwrap(),
        |b| postcard::from_bytes(b).unwrap(),
        PartialEq::eq,
    );
    check_derived("storage_commitment.pin", &commitment_hash(&value).unwrap());
    check_derived(
        "storage_commitment.signed_payload",
        &commitment_signed_payload(
            &value.root,
            value.key_count,
            &value.sender_peer_id,
            &value.sender_public_key,
        ),
    );
}

/// `ChunkPutRequest::payment_proof` for a single-node payment: tag byte, then
/// the `MessagePack` `PaymentProof`.
#[test]
fn single_node_payment_proof() {
    let expected = single_node_proof();
    check(
        "payment_proof.single_node",
        &expected,
        |p| serialize_single_node_proof(p).unwrap(),
        |b| {
            assert_eq!(b.first(), Some(&PROOF_TAG_SINGLE_NODE));
            ant_protocol::payment::proof::deserialize_single_node_proof(b).unwrap()
        },
        |a, b| {
            a.proof_of_payment == b.proof_of_payment
                && a.tx_hashes == b.tx_hashes
                && a.commitment_sidecars == b.commitment_sidecars
        },
    );

    // The older entry point drops the sidecars but must read the same bytes.
    let golden = golden("payment_proof.single_node", &[]);
    let (proof_of_payment, tx_hashes) = deserialize_proof(&golden).unwrap();
    assert_eq!(proof_of_payment, expected.proof_of_payment);
    assert_eq!(tx_hashes, expected.tx_hashes);
}

/// `ChunkPutRequest::payment_proof` for a merkle payment: tag byte, then the
/// `MessagePack` `MerklePaymentProof`.
#[test]
fn merkle_payment_proof() {
    check(
        "payment_proof.merkle",
        &merkle_proof(),
        |p| serialize_merkle_proof(p).unwrap(),
        |b| {
            assert_eq!(b.first(), Some(&PROOF_TAG_MERKLE));
            deserialize_merkle_proof(b).unwrap()
        },
        PartialEq::eq,
    );
}

// =============================================================================
// Pointer record (hand-encoded, see `pointer.rs`)
// =============================================================================

/// The pointer record carried by `PointerPutRequest` and `PointerGetResponse`,
/// plus the two identities derived from it.
///
/// ML-DSA-65 signing is randomized, so the signature can't be rebuilt from the
/// fixture. The record is checked by decoding it, which verifies the captured
/// signature against the seeded owner key, and the signed body is rebuilt and
/// compared byte for byte.
#[test]
fn pointer_record() {
    let (owner, secret) = ml_dsa_65().generate_keypair_from_seed(&[0x42; 32]);
    let target = PointerTarget::new(PointerTargetKind::Chunk, bytes32(0xF0));
    let fresh = Pointer::sign(&secret, &owner, 7, target).unwrap();

    let golden = golden("pointer.record", &fresh.to_bytes());
    assert_eq!(golden.len(), POINTER_WIRE_LEN);
    assert_bytes(
        "pointer.record",
        "signed body",
        &fresh.to_bytes()[..POINTER_BODY_LEN],
        &golden[..POINTER_BODY_LEN],
    );

    let decoded = Pointer::from_bytes(&golden).unwrap();
    assert_eq!(decoded.owner().to_bytes(), owner.to_bytes());
    assert_eq!(decoded.counter(), 7);
    assert_eq!(decoded.target(), target);
    assert_bytes(
        "pointer.record",
        "re-encoding",
        &decoded.to_bytes(),
        &golden,
    );

    check_derived("pointer.address", &decoded.address());
    check_derived("pointer.state_id", &decoded.state_id());
    assert_eq!(
        decoded.state_id(),
        state_id_for_body(&golden[..POINTER_BODY_LEN])
    );
}
