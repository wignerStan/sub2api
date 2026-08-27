//! E2EE record framing shared by the sidecar's two local hops.
//!
//! - Plugin channel: key = HKDF-SHA256(SHA256(plugin binary), salt, info)
//! - Serve-mode loopback: key = HKDF-SHA256(x-s2s-token, salt, info)
//!
//! Record layout: [0xE2][version=1][len u32 BE][nonce 12B][ciphertext+16B tag]
//! where len covers nonce+ciphertext+tag. AEAD: AES-256-GCM (aws-lc-rs),
//! AAD = b"sub2api-e2ee". Records are self-delimiting; a stream decoder
//! handles arbitrary chunk splits.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::{digest, hkdf};

pub const RECORD_MAGIC: u8 = 0xE2;
pub const RECORD_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2 + 4;
pub const E2EE_SALT: &[u8] = b"sub2api-e2ee-v1";
const AEAD_AAD: &[u8] = b"sub2api-e2ee";

/// HKDF-SHA256 to a 32-byte key.
pub fn derive_key(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, E2EE_SALT);
    let prk = salt.extract(ikm);
    let mut out = [0u8; 32];
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, hkdf::HKDF_SHA256)
        .map_err(|e| e.to_string())?;
    okm.fill(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Key derived from the binary itself.
#[allow(dead_code)]
pub fn derive_key_from_binary(binary_bytes: &[u8]) -> Result<[u8; 32], String> {
    let d = digest::digest(&digest::SHA256, binary_bytes);
    derive_key(d.as_ref(), b"forward-channel")
}

/// Loopback key from the shared sidecar token.
pub fn derive_key_from_token(token: &[u8]) -> Result<[u8; 32], String> {
    derive_key(token, b"loopback-channel")
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    let _ = aws_lc_rs::rand::fill(&mut n);
    n
}

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    seal_with_nonce(key, &random_nonce(), plaintext)
}

pub fn seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|e| e.to_string())?;
    let key = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    let nonce_arr = *nonce;
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|e| e.to_string())?;
    key.seal_in_place_append_tag(nonce, Aad::from(AEAD_AAD), &mut in_out)
        .map_err(|e| e.to_string())?;
    let payload_len = (NONCE_LEN + in_out.len()) as u32;
    let mut out = Vec::with_capacity(HEADER_LEN + payload_len as usize);
    out.push(RECORD_MAGIC);
    out.push(RECORD_VERSION);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&nonce_arr);
    out.extend_from_slice(&in_out);
    Ok(out)
}

pub const MAX_PAYLOAD_LEN: usize = 64 * 1024 * 1024; // 64 MB guard

/// Convenience aliases matching existing call sites.
pub fn seal_chunk(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    seal(key, plaintext)
}

#[allow(dead_code)]
pub fn open_chunk(key: &[u8; 32], record: &[u8]) -> Result<Vec<u8>, String> {
    open(key, record)
}

/// Open a full record (header + payload).
pub fn open(key: &[u8; 32], record: &[u8]) -> Result<Vec<u8>, String> {
    if record.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        return Err("e2ee record too short".into());
    }
    if record[0] != RECORD_MAGIC || record[1] != RECORD_VERSION {
        return Err("unsupported e2ee record header".into());
    }
    let payload_len = u32::from_be_bytes([record[2], record[3], record[4], record[5]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err("e2ee record payload too large".into());
    }
    if record.len() < HEADER_LEN + payload_len {
        return Err("e2ee record truncated".into());
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|e| e.to_string())?;
    let key = LessSafeKey::new(unbound);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&record[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|e| e.to_string())?;
    let mut in_out = record[HEADER_LEN + NONCE_LEN..HEADER_LEN + payload_len].to_vec();
    let plain = key
        .open_in_place(nonce, Aad::from(AEAD_AAD), &mut in_out)
        .map_err(|e| e.to_string())?;
    Ok(plain.to_vec())
}

/// Streaming decoder for arbitrarily split sealed byte streams.
#[derive(Default)]
pub struct RecordDecoder {
    buf: Vec<u8>,
}

impl RecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Feed sealed bytes; returns every complete record's plaintext in order.
    pub fn push(&mut self, key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, String> {
        self.buf.extend_from_slice(sealed);
        let mut out = Vec::with_capacity(self.buf.len());
        loop {
            if self.buf.len() < HEADER_LEN {
                break;
            }
            if self.buf[0] != RECORD_MAGIC || self.buf[1] != RECORD_VERSION {
                return Err("unsupported e2ee record header".into());
            }
            let payload_len = u32::from_be_bytes([self.buf[2], self.buf[3], self.buf[4], self.buf[5]]) as usize;
            if payload_len > MAX_PAYLOAD_LEN {
                return Err("e2ee record payload too large".into());
            }
            let total = HEADER_LEN + payload_len;
            if self.buf.len() < total {
                break;
            }
            let record: Vec<u8> = self.buf.drain(..total).collect();
            out.extend_from_slice(&open(key, &record)?);
        }
        if self.buf.is_empty() {
            self.buf.shrink_to_fit();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        k
    }

    #[test]
    fn roundtrip_and_tamper() {
        let key = test_key();
        let pt = b"hello e2ee payload";
        let rec = seal(&key, pt).unwrap();
        assert_eq!(rec[0], RECORD_MAGIC);
        assert_eq!(rec[1], RECORD_VERSION);
        assert_eq!(open(&key, &rec).unwrap(), pt);
        let mut bad = rec.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(open(&key, &bad).is_err());
        let wrong = [0xFFu8; 32];
        assert!(open(&wrong, &rec).is_err());
    }

    #[test]
    fn deterministic_seal_with_fixed_nonce() {
        let key = test_key();
        let n = [7u8; 12];
        let a = seal_with_nonce(&key, &n, b"vector").unwrap();
        let b = seal_with_nonce(&key, &n, b"vector").unwrap();
        assert_eq!(a, b, "same key/nonce/pt must produce identical records");
    }

    #[test]
    fn derivation_is_stable_and_separated() {
        let a = derive_key(b"ikm", b"forward-channel").unwrap();
        let b = derive_key(b"ikm", b"forward-channel").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, derive_key(b"ikm", b"loopback-channel").unwrap());
        assert_ne!(a, derive_key(b"other", b"forward-channel").unwrap());
        let bin = derive_key_from_binary(b"binary").unwrap();
        assert_eq!(bin, derive_key_from_binary(b"binary").unwrap());
    }

    #[test]
    fn decoder_handles_split_and_coalesced_records() {
        let key = test_key();
        let r1 = seal(&key, b"first-").unwrap();
        let r2 = seal(&key, b"second").unwrap();
        let r3 = seal(&key, b"!").unwrap();

        // Split at arbitrary boundaries.
        let mut all = r1.clone();
        all.extend_from_slice(&r2);
        all.extend_from_slice(&r3);
        for split in [1usize, 6, 7, 14, 20, all.len() - 1] {
            let mut dec = RecordDecoder::new();
            let mut got = dec.push(&key, &all[..split]).unwrap();
            got.extend(dec.push(&key, &all[split..]).unwrap());
            assert_eq!(got, b"first-second!", "split at {split}");
        }

        // Byte-at-a-time.
        let mut dec = RecordDecoder::new();
        let mut got = Vec::new();
        for b in &all {
            got.extend(dec.push(&key, &[*b]).unwrap());
        }
        assert_eq!(got, b"first-second!");
    }

    #[test]
    fn chunk_1to1_roundtrip() {
        let key = test_key();
        for size in [0usize, 1, 100, 32 * 1024] {
            let pt = vec![0xABu8; size];
            let sealed = seal(&key, &pt).unwrap();
            assert_eq!(open(&key, &sealed).unwrap(), pt);
        }
    }

    #[test]
    fn decoder_pending_and_limit_guards() {
        let key = test_key();
        let mut dec = RecordDecoder::new();
        assert!(dec.is_empty());
        assert_eq!(dec.pending(), 0);

        let sealed = seal(&key, b"hello").unwrap();
        // Feed partial
        let got = dec.push(&key, &sealed[..3]).unwrap();
        assert!(got.is_empty());
        assert!(!dec.is_empty());
        assert_eq!(dec.pending(), 3);

        // Feed rest
        let got = dec.push(&key, &sealed[3..]).unwrap();
        assert_eq!(got, b"hello");
        assert!(dec.is_empty());
        assert_eq!(dec.pending(), 0);

        // Invalid record header
        let mut bad_header = sealed.clone();
        bad_header[0] = 0x00;
        assert!(dec.push(&key, &bad_header).is_err());
    }
}
