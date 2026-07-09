//! The signed audit report — shared between node and client (ADR-0005).
//!
//! ADR-0005 gates *reward eligibility* on objective audit history: a client
//! pays a quoter only if a quorum of that quoter's neighbours report having
//! audited it clean for about a week at the size it is monetizing. The
//! neighbours' testimony travels as an **audit report**: the responder's raw
//! per-peer tally of audit outcomes, signed with the same key as its quote and
//! bound to the client's request nonce so it is generated fresh per request.
//!
//! Reports are facts, not opinions: passes per day and the largest commitment
//! size that passed, plus two row-local markers (a conviction the observer
//! itself made, and an unanswered challenge on a pin the subject monetized).
//! They carry no third-party accusations and no evidence payloads; a marker
//! only silences that one observer's testimony, it never excludes anyone on
//! its own (client policy aggregates a quorum).
//!
//! Like the `commitment` module, only the wire type and its verification live
//! here. Tally bookkeeping and signing live in `ant-node`; the eligibility
//! predicate (policy over these facts) lives in the client.

use saorsa_core::MlDsa65;
use saorsa_pqc::pqc::types::{MlDsaPublicKey, MlDsaSignature};
use saorsa_pqc::pqc::MlDsaOperations;
use serde::{Deserialize, Serialize};

/// Domain-separation tag for the audit-report signature.
///
/// Folded into the FRONT of [`audit_report_signed_payload`] (not passed as an
/// ML-DSA signing context) because the report is signed by the node's plain
/// quote signer, which — like quote and merkle-candidate signing — uses the
/// context-free `MlDsa65` API. The prefix gives the same cross-protocol
/// separation: no quote or candidate payload can collide with a report's.
pub const DOMAIN_AUDIT_REPORT: &[u8] = b"autonomi.ant.eligibility.audit_report.v1";

/// Maximum serialized size of a report sidecar blob.
///
/// A full report is ~6 KiB (24 rows x ~110 B + ML-DSA-65 signature 3309 B +
/// framing). 16 KiB bounds the deserialize/verify work a malicious responder
/// can force on the client. The cap is enforced by the CLIENT (the caller)
/// before `rmp_serde` decodes the blob — see the caller precondition on
/// [`verify_audit_report`]; by the time `verify_audit_report` runs the rows
/// are already parsed. The 5 MiB wire-message cap bounds the blast radius.
pub const MAX_AUDIT_REPORT_BYTES: usize = 16 * 1024;

/// Maximum rows (observed peers) per report — the neighbour-sync observation
/// scope (~20) plus slack. Rows beyond this are rejected, not truncated: a
/// report that big is malformed by construction.
pub const MAX_REPORT_ROWS: usize = 24;

/// Maximum day entries per row — the tally window (~14 days) plus slack.
pub const MAX_REPORT_DAYS: usize = 21;

/// One day of audit outcomes for one observed peer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReportDay {
    /// Whole days elapsed since this bucket, relative to the report's
    /// emission (0 = the reporter's current day). Relative ages keep remote
    /// clocks out of the predicate.
    pub age_days: u16,
    /// Audit passes recorded that day.
    pub passes: u32,
    /// Largest committed key count that passed an audit that day. The client
    /// only counts a day toward eligibility if this covers the quoted count
    /// (within its slack policy) — the dues are sustained disk at the
    /// monetized size, not wall-clock.
    pub max_passed_key_count: u32,
}

/// The reporter's tally row for one observed peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReportRow {
    /// The observed peer this row testifies about.
    pub subject_peer_id: [u8; 32],
    /// Per-day outcomes, newest first, within the tally window.
    pub days: Vec<AuditReportDay>,
    /// An audit challenge on a pin the subject monetized went unanswered and
    /// no pass has cleared it since. A fenced row is testimony the client
    /// must not count — nothing more (silence is not portable evidence).
    pub fenced: bool,
    /// This observer deterministically convicted the subject. The row was
    /// zeroed at conviction (the D-day re-grind), and the marker stays **sticky
    /// for the dues period (~D days)** even as fresh passes accrue underneath —
    /// it does NOT clear on the next pass. So one catch costs exactly one
    /// week's re-earning and never compounds into a permanent ban. A client
    /// treats a convicted row as a non-vouching opinion (it counts in the
    /// denominator, never the numerator) until the sticky period ages out on
    /// the reporting node. Node and client MUST share this sticky semantics.
    pub convicted: bool,
}

/// A signed audit report, shipped alongside a quote (ADR-0005).
///
/// Signed with the responder's quote key under [`DOMAIN_AUDIT_REPORT`]; the
/// public key is NOT embedded — the verifier binds the report to the quote
/// (or merkle candidate) that travelled in the same response, whose embedded
/// key it has already peer-bound. Binding the client's request nonce into the
/// signed payload forces fresh generation: a report cannot be precomputed or
/// replayed across requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReport {
    /// The reporting peer (must match the quoter the response came from).
    pub reporter_peer_id: [u8; 32],
    /// Echo of the client's request nonce.
    pub nonce: [u8; 32],
    /// Tally rows as they stand — partial positive evidence, at most
    /// [`MAX_REPORT_ROWS`].
    pub rows: Vec<AuditReportRow>,
    /// ML-DSA-65 signature over [`audit_report_signed_payload`].
    pub signature: Vec<u8>,
}

/// Canonical bytes the report signature covers: everything but the signature,
/// length-framed so no field boundary is ambiguous.
#[must_use]
pub fn audit_report_signed_payload(
    reporter_peer_id: &[u8; 32],
    nonce: &[u8; 32],
    rows: &[AuditReportRow],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(120 + rows.len() * 120);
    v.extend_from_slice(DOMAIN_AUDIT_REPORT);
    v.extend_from_slice(reporter_peer_id);
    v.extend_from_slice(nonce);
    let row_count = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    v.extend_from_slice(&row_count.to_le_bytes());
    for row in rows {
        v.extend_from_slice(&row.subject_peer_id);
        v.push(u8::from(row.fenced));
        v.push(u8::from(row.convicted));
        let day_count = u32::try_from(row.days.len()).unwrap_or(u32::MAX);
        v.extend_from_slice(&day_count.to_le_bytes());
        for day in &row.days {
            v.extend_from_slice(&day.age_days.to_le_bytes());
            v.extend_from_slice(&day.passes.to_le_bytes());
            v.extend_from_slice(&day.max_passed_key_count.to_le_bytes());
        }
    }
    v
}

/// Verify a report against the responder's ML-DSA-65 public key (the one that
/// travelled with — and was already peer-bound to — the quote in the same
/// response) and the nonce the client sent.
///
/// Checks, in order: structural caps (row/day counts), reporter/nonce echo,
/// and the signature. Returns `false` on any mismatch; never panics on
/// untrusted bytes.
///
/// # Precondition (load-bearing)
///
/// The caller MUST pass the **peer-bound quote key** as `reporter_public_key`:
/// the ML-DSA-65 public key that travelled with the quote (or merkle candidate)
/// in the same response and that the caller has ALREADY verified hashes to the
/// responding peer id (`BLAKE3(pub_key) == peer_id`). This function checks the
/// signature against whatever key it is handed and checks that the report's
/// embedded `reporter_peer_id` equals `expected_reporter_peer_id`, but it does
/// NOT itself bind the key to that peer id — so passing an unbound or attacker-
/// chosen key would let a report verify under the wrong identity. Both current
/// callers (single-node `quote.rs`, merkle `merkle.rs`) pass the peer-bound
/// quote key, which is the only correct usage.
///
/// The caller MUST also enforce [`MAX_AUDIT_REPORT_BYTES`] on the serialized
/// blob before decoding it into an [`AuditReport`]; this function receives the
/// already-parsed rows and only bounds their COUNT ([`MAX_REPORT_ROWS`] /
/// [`MAX_REPORT_DAYS`]).
#[must_use]
pub fn verify_audit_report(
    report: &AuditReport,
    reporter_public_key: &[u8],
    expected_reporter_peer_id: &[u8; 32],
    expected_nonce: &[u8; 32],
) -> bool {
    if report.rows.len() > MAX_REPORT_ROWS
        || report.rows.iter().any(|r| r.days.len() > MAX_REPORT_DAYS)
    {
        return false;
    }
    if &report.reporter_peer_id != expected_reporter_peer_id || &report.nonce != expected_nonce {
        return false;
    }
    let Ok(public_key) = MlDsaPublicKey::from_bytes(reporter_public_key) else {
        return false;
    };
    let Ok(sig) = MlDsaSignature::from_bytes(&report.signature) else {
        return false;
    };
    let payload =
        audit_report_signed_payload(&report.reporter_peer_id, &report.nonce, &report.rows);
    MlDsa65::new()
        .verify(&public_key, &payload, &sig)
        .unwrap_or(false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_rows() -> Vec<AuditReportRow> {
        vec![AuditReportRow {
            subject_peer_id: [7u8; 32],
            days: vec![
                AuditReportDay {
                    age_days: 0,
                    passes: 3,
                    max_passed_key_count: 9000,
                },
                AuditReportDay {
                    age_days: 1,
                    passes: 5,
                    max_passed_key_count: 8500,
                },
            ],
            fenced: false,
            convicted: false,
        }]
    }

    fn signed_report(
        reporter: [u8; 32],
        nonce: [u8; 32],
        rows: Vec<AuditReportRow>,
    ) -> (AuditReport, Vec<u8>) {
        let ml_dsa = MlDsa65::new();
        let (pk, sk) = ml_dsa.generate_keypair().unwrap();
        let payload = audit_report_signed_payload(&reporter, &nonce, &rows);
        let sig = ml_dsa.sign(&sk, &payload).unwrap();
        (
            AuditReport {
                reporter_peer_id: reporter,
                nonce,
                rows,
                signature: sig.as_bytes().to_vec(),
            },
            pk.as_bytes().to_vec(),
        )
    }

    #[test]
    fn verify_accepts_a_correctly_signed_report() {
        let (report, pk) = signed_report([1u8; 32], [2u8; 32], sample_rows());
        assert!(verify_audit_report(&report, &pk, &[1u8; 32], &[2u8; 32]));
    }

    #[test]
    fn verify_rejects_wrong_nonce_or_reporter() {
        let (report, pk) = signed_report([1u8; 32], [2u8; 32], sample_rows());
        assert!(
            !verify_audit_report(&report, &pk, &[1u8; 32], &[9u8; 32]),
            "a report echoing a different nonce must not verify"
        );
        assert!(
            !verify_audit_report(&report, &pk, &[9u8; 32], &[2u8; 32]),
            "a report from a different reporter must not verify"
        );
    }

    #[test]
    fn verify_rejects_tampered_rows() {
        let (mut report, pk) = signed_report([1u8; 32], [2u8; 32], sample_rows());
        if let [row, ..] = report.rows.as_mut_slice() {
            if let [day, ..] = row.days.as_mut_slice() {
                day.passes += 1;
            }
        }
        assert!(
            !verify_audit_report(&report, &pk, &[1u8; 32], &[2u8; 32]),
            "tampered passes must fail"
        );

        let (mut report, pk) = signed_report([1u8; 32], [2u8; 32], sample_rows());
        if let [row, ..] = report.rows.as_mut_slice() {
            row.fenced = true;
        }
        assert!(
            !verify_audit_report(&report, &pk, &[1u8; 32], &[2u8; 32]),
            "flipping the fence flag must fail"
        );

        let (mut report, pk) = signed_report([1u8; 32], [2u8; 32], sample_rows());
        if let [row, ..] = report.rows.as_mut_slice() {
            row.days.pop();
        }
        assert!(
            !verify_audit_report(&report, &pk, &[1u8; 32], &[2u8; 32]),
            "dropping a day must fail"
        );
    }

    #[test]
    fn verify_rejects_key_swap() {
        let (report, _pk) = signed_report([1u8; 32], [2u8; 32], sample_rows());
        let (other_pk, _) = MlDsa65::new().generate_keypair().unwrap();
        assert!(
            !verify_audit_report(&report, other_pk.as_bytes(), &[1u8; 32], &[2u8; 32]),
            "verifying under a different key must fail"
        );
    }

    #[test]
    fn verify_rejects_oversized_structure_without_sig_work() {
        let rows: Vec<AuditReportRow> = (0..=MAX_REPORT_ROWS)
            .map(|i| AuditReportRow {
                subject_peer_id: [u8::try_from(i % 256).unwrap(); 32],
                days: Vec::new(),
                fenced: false,
                convicted: false,
            })
            .collect();
        let report = AuditReport {
            reporter_peer_id: [1u8; 32],
            nonce: [2u8; 32],
            rows,
            signature: vec![0u8; 8],
        };
        assert!(
            !verify_audit_report(&report, &[0u8; 8], &[1u8; 32], &[2u8; 32]),
            "row count above cap must be rejected"
        );
    }

    #[test]
    fn verify_rejects_malformed_without_panic() {
        let report = AuditReport {
            reporter_peer_id: [0u8; 32],
            nonce: [0u8; 32],
            rows: Vec::new(),
            signature: vec![0u8; 10],
        };
        assert!(!verify_audit_report(
            &report, &[0u8; 10], &[0u8; 32], &[0u8; 32]
        ));
    }
}
