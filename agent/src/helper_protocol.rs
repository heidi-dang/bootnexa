//! Non-networked security contract for a future, audited Windows local
//! helper. No pipe listener, elevation, OS identity attestation or device I/O
//! is implemented. The *only* request variant is read-only evidence retrieval.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

const MAX_BYTES: usize = 2048;
const PROTOCOL_VERSION: u16 = 1;
const MAX_TTL_MS: u64 = 30_000;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ReadOnlySafetyReport,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlyRequest {
    pub version: u16,
    pub operation: Operation,
    pub challenge: String,
    pub client_binding: String,
    pub expires_at_ms: u64,
    pub mac_hex: String,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("invalid protocol envelope")]
    Invalid,
    #[error("protocol version or operation not supported")]
    Unsupported,
    #[error("replayed or expired request")]
    Expired,
    #[error("peer authentication required")]
    Unauthenticated,
}
/// Future Windows named-pipe boundary MUST construct this from trusted
/// impersonation + OS process-token/signature evidence, not JSON from a peer.
/// There is no production constructor until that OS-bound transport exists.
pub(crate) struct VerifiedPeer {
    sid_binding: String,
}
#[cfg(test)]
impl VerifiedPeer {
    fn synthetic(sid: &str) -> Self {
        Self {
            sid_binding: sid.into(),
        }
    }
}
/// Internal in-memory challenge/response verifier. This is not a broker
/// service; it processes no disks. The future transport must deliver a
/// confidential session key over an authenticated SID-scoped channel.
pub(crate) struct ReadOnlyGuard {
    peer: VerifiedPeer,
    key: [u8; 32],
    challenge: [u8; 16],
    issued_at: u64,
    used: bool,
}
impl ReadOnlyGuard {
    #[cfg(test)]
    pub(crate) fn synthetic(peer: VerifiedPeer, issued_at: u64) -> Self {
        Self {
            peer,
            key: rand::random(),
            challenge: rand::random(),
            issued_at,
            used: false,
        }
    }
    fn challenge_hex(&self) -> String {
        hex::encode(self.challenge)
    }
    fn payload(req: &ReadOnlyRequest) -> Vec<u8> {
        // Delimited canonical MAC input independent of JSON field ordering.
        format!(
            "bootnexa-readonly|{}|read_only_safety_report|{}|{}|{}",
            req.version, req.challenge, req.client_binding, req.expires_at_ms
        )
        .into_bytes()
    }
    pub(crate) fn verify(&mut self, input: &[u8], now_ms: u64) -> Result<(), GuardError> {
        if input.len() > MAX_BYTES || self.used {
            return Err(GuardError::Invalid);
        }
        let req: ReadOnlyRequest =
            serde_json::from_slice(input).map_err(|_| GuardError::Invalid)?;
        if req.version != PROTOCOL_VERSION {
            return Err(GuardError::Unsupported);
        }
        if req.operation != Operation::ReadOnlySafetyReport {
            return Err(GuardError::Unsupported);
        }
        if req.client_binding != self.peer.sid_binding || req.challenge != self.challenge_hex() {
            return Err(GuardError::Unauthenticated);
        }
        if req.expires_at_ms < now_ms
            || now_ms < self.issued_at
            || req.expires_at_ms > self.issued_at.saturating_add(MAX_TTL_MS)
        {
            return Err(GuardError::Expired);
        }
        let provided = hex::decode(&req.mac_hex).map_err(|_| GuardError::Unauthenticated)?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC-SHA256 key length");
        mac.update(&Self::payload(&req));
        mac.verify_slice(&provided)
            .map_err(|_| GuardError::Unauthenticated)?;
        self.used = true; // A successful read-only request cannot be replayed.
        Ok(())
    }
    #[cfg(test)]
    fn test_signed_request(&self, expires_at: u64) -> ReadOnlyRequest {
        let mut req = ReadOnlyRequest {
            version: PROTOCOL_VERSION,
            operation: Operation::ReadOnlySafetyReport,
            challenge: self.challenge_hex(),
            client_binding: self.peer.sid_binding.clone(),
            expires_at_ms: expires_at,
            mac_hex: String::new(),
        };
        let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
        mac.update(&Self::payload(&req));
        req.mac_hex = hex::encode(mac.finalize().into_bytes());
        req
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> ReadOnlyGuard {
        ReadOnlyGuard::synthetic(VerifiedPeer::synthetic("S-1-5-21-TEST-USER"), 1_000)
    }
    #[test]
    fn accepted_read_only_proof_is_single_use() {
        let mut guard = fixture();
        let req = guard.test_signed_request(2_000);
        let bytes = serde_json::to_vec(&req).unwrap();
        assert_eq!(guard.verify(&bytes, 1_200), Ok(()));
        assert_eq!(guard.verify(&bytes, 1_201), Err(GuardError::Invalid));
    }
    #[test]
    fn authentication_tampering_is_rejected() {
        for kind in 0..6 {
            let mut guard = fixture();
            let mut req = guard.test_signed_request(2_000);
            match kind {
                0 => req.mac_hex = "00".repeat(32),
                1 => req.challenge = "0".repeat(32),
                2 => req.client_binding = "S-1-5-18".into(),
                3 => req.expires_at_ms += 1,
                4 => req.mac_hex = "malformed".into(),
                5 => req.mac_hex.pop().map(|_| ()).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                guard
                    .verify(&serde_json::to_vec(&req).unwrap(), 1_200)
                    .is_err()
            );
        }
    }
    #[test]
    fn expired_future_rollback_and_protocol_version_rejected() {
        let mut guard = fixture();
        let req = guard.test_signed_request(2_000);
        let raw = serde_json::to_vec(&req).unwrap();
        assert_eq!(guard.verify(&raw, 2_001), Err(GuardError::Expired));
        assert_eq!(guard.verify(&raw, 999), Err(GuardError::Expired));
        let mut req = guard.test_signed_request(31_001);
        assert_eq!(
            guard.verify(&serde_json::to_vec(&req).unwrap(), 1_200),
            Err(GuardError::Expired)
        );
        req.version = 2;
        assert_eq!(
            guard.verify(&serde_json::to_vec(&req).unwrap(), 1_200),
            Err(GuardError::Unsupported)
        );
    }
    #[test]
    fn unknown_destructive_operations_and_fields_are_invalid() {
        let guard = fixture();
        let req = guard.test_signed_request(2_000);
        let mut val = serde_json::to_value(&req).unwrap();
        for op in [
            "write_disk",
            "format",
            "erase",
            "prepare_plan",
            "request_destructive_consent",
            "execute_signed_plan",
        ] {
            val["operation"] = op.into();
            let mut copy = fixture();
            assert!(
                copy.verify(&serde_json::to_vec(&val).unwrap(), 1_200)
                    .is_err()
            );
        }
        val = serde_json::to_value(&req).unwrap();
        val["target_disk"] = serde_json::json!(0);
        let mut copy = fixture();
        assert_eq!(
            copy.verify(&serde_json::to_vec(&val).unwrap(), 1_200),
            Err(GuardError::Invalid)
        );
        let mut copy = fixture();
        assert_eq!(
            copy.verify(&vec![b'a'; MAX_BYTES + 1], 1_200),
            Err(GuardError::Invalid)
        );
    }
}
