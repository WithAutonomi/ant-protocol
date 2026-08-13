# Changelog

All notable changes to `ant-protocol` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.4.0]

### Added
- **Settlement version on quote requests.** `CURRENT_SETTLEMENT_VERSION`,
  `MIN_SUPPORTED_SETTLEMENT_VERSION` and `settlement_version_is_supported`
  describe which payment rule set a build settles under, tracked separately
  from `PROTOCOL_VERSION` because the wire format and the payment arithmetic
  change independently.
- `ChunkQuoteRequestV2` and `MerkleCandidateQuoteRequestV2`, reached through
  the new `ChunkMessageBody::QuoteRequestV2` and
  `ChunkMessageBody::MerkleCandidateQuoteRequestV2` variants, carry that
  version so a storer can refuse to quote a client that cannot pay correctly.
- `ProtocolError::ClientUpdateRequired` and `client_update_required_message`,
  which tell the user their client is too old, that nothing was charged, and
  how to upgrade.

Additive only: both message variants and the error variant are appended, so
every existing discriminant keeps its wire value and peers built against
`2.3.x` decode unchanged. A peer that does not know the new variants rejects
them cleanly rather than misreading them, and a regression test pins the
existing discriminants so a future insertion cannot break that silently.

Motivated by ADR-0008, which raised the merkle settlement multiplier to 3x in
client and node code without changing any wire type. Nothing tied the two
together, so older clients kept collecting quotes, paid 1x on-chain, and had
every storer refuse the upload after the payment had already settled and
become unrefundable.

## [2.3.0]

### Changed
- **ADR-0004 (commitment-bound quote pricing):** verify the new signed
  commitment fields (`committed_key_count`, `commitment_pin`) on single-node and
  merkle quote types; centralise `StorageCommitment`, `commitment_hash`, sidecar
  handling, and the shared `calculate_price`. Requires `evmlib` 0.9.0. Breaking
  wire change — part of the coordinated ADR-0004 cutover (evmlib → ant-protocol →
  ant-node/ant-client).

## [2.0.0] — Unreleased

First release of the `2.x` series. Not wire-compatible with previous
`1.x` releases published from a different repository under the same
crate name.

### Added

- `chunk` — chunk protocol messages (`ChunkMessage`,
  `ChunkPutRequest`/`Response`, `ChunkGetRequest`/`Response`,
  `ChunkQuoteRequest`/`Response`,
  `MerkleCandidateQuoteRequest`/`Response`), protocol constants
  (`CHUNK_PROTOCOL_ID`, `PROTOCOL_VERSION`, `MAX_CHUNK_SIZE`,
  `MAX_WIRE_MESSAGE_SIZE`, `DATA_TYPE_CHUNK`, `CLOSE_GROUP_SIZE`,
  `CLOSE_GROUP_MAJORITY`, `XORNAME_LEN`), `ProtocolError`, and payment
  proof tag bytes (`PROOF_TAG_SINGLE_NODE`, `PROOF_TAG_MERKLE`).
- `data_types` — address helpers (`compute_address`, `xor_distance`,
  `peer_id_to_xor_name`) and the `DataChunk` container.
- `chunk_protocol::send_and_await_chunk_response` — subscribe/send/poll
  helper for chunk-protocol request/response exchanges over a
  `saorsa-core::P2PNode`.
- `payment::SingleNodePayment` with `pay` (on-chain payment) and
  `verify` (on-chain verification) methods. `verify` rejects proofs
  whose median quote has zero price or zero paid amount.
- `payment::proof` — `PaymentProof`, `ProofType`, and the
  `serialize_single_node_proof` / `serialize_merkle_proof` /
  `deserialize_proof` / `deserialize_merkle_proof` /
  `detect_proof_type` helpers.
- `payment::verify` — ML-DSA-65 signature verification
  (`verify_quote_content`, `verify_quote_signature`,
  `verify_merkle_candidate_signature`).
- `devnet_manifest` — `DevnetManifest` and `DevnetEvmInfo` POJOs for
  the devnet on-disk handoff file.
- Transitive-dep re-export modules `evm`, `transport`, `pqc` so
  downstream crates can consume `evmlib`, `saorsa-core`, and
  `saorsa-pqc` through a single version pin.

### Wire-level semantics

- `ChunkMessageBody`, `ChunkPutResponse`, `ChunkGetResponse`,
  `ChunkQuoteResponse`, `MerkleCandidateQuoteResponse`, `ProofType`,
  `ProtocolError`, and `Error` are `#[non_exhaustive]`.
- `ChunkMessage::decode` rejects inputs larger than
  `MAX_WIRE_MESSAGE_SIZE` before deserialization.
- `chunk_protocol::send_and_await_chunk_response` uses
  `Instant::checked_add` on the deadline to avoid panicking on
  out-of-range durations.
