// AES-GCM-SIV v3 verifier for both seal blobs (single chunk) and sealstream
// blobs (N chunks, optionally framed).
//
// Wire format (identical structural shape to XChaCha20 v3; differs only in
// the AEAD primitive and the absence of an HChaCha20-equivalent subkey
// derivation step, AES-GCM-SIV consumes the 32-byte HKDF output directly):
//
//   preamble:  header(20) || commitment(32) = 52 bytes
//
//   header:    formatEnum(1) || nonce(16) || chunkSize(u24be, 3)
//              formatEnum bit 7 = framed flag, bit 6 = reserved (0),
//                           bits 5..0 = format ID. AES-GCM-SIV v3 = 0x04.
//
//   chunk_i:   AES-256-GCM-SIV(streamKey, counterNonce_i, plaintext_i, aad="")
//              counterNonce_i = (i)_be11 || finalFlag(1)
//              finalFlag = TAG_DATA(0x00) for i < N-1, TAG_FINAL(0x01) for i == N-1
//
//   framed:    each chunk on the wire is prefixed with u32be(chunk_len)
//              (only when header bit 7 is set; affects wire only, not crypto)
//
//   streamKey  = HKDF-SHA-256(salt=nonce, ikm=key, info=INFO‖header, len=64)[0..32]
//   commitment                                                       ...len=64)[32..64]
//
// The full 20-byte header is bound into the HKDF info string. Tampering
// with formatEnum, framed flag, nonce, or chunkSize produces different
// derived keys and the AEAD fails on the first chunk.

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::parse::{SealVector, SealStreamVector};

const INFO_V3:     &[u8]  = b"aes-gcm-siv-sealstream-v3";
const HEADER_SIZE: usize  = 20;
const COMMIT_SIZE: usize  = 32;
const TAG_SIZE:    usize  = 16;
const FORMAT_ENUM: u8     = 0x04;
const TAG_DATA:    u8     = 0x00;
const TAG_FINAL:   u8     = 0x01;

#[derive(Debug)]
pub struct DerivedV3 {
    pub key:        [u8; 32],
    pub commitment: [u8; 32],
}

pub fn derive_v3(master_key: &[u8; 32], nonce16: &[u8; 16], header: &[u8]) -> DerivedV3 {
    assert_eq!(header.len(), HEADER_SIZE);
    let mut info = Vec::with_capacity(INFO_V3.len() + header.len());
    info.extend_from_slice(INFO_V3);
    info.extend_from_slice(header);

    let hkdf = Hkdf::<Sha256>::new(Some(nonce16), master_key);
    let mut okm = [0u8; 64];
    hkdf.expand(&info, &mut okm).expect("hkdf expand 64");

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[0..32]);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&okm[32..64]);

    DerivedV3 { key, commitment }
}

fn make_counter_nonce(counter: u64, final_flag: u8) -> [u8; 12] {
    // 11 BE counter bytes + 1 final flag byte = 12 bytes.
    // u64 covers everything we'd ever realistically use; high 3 bytes are 0.
    let mut nonce = [0u8; 12];
    let counter_be = counter.to_be_bytes(); // 8 bytes
    nonce[3..11].copy_from_slice(&counter_be);
    nonce[11] = final_flag;
    nonce
}

fn aead_encrypt(stream_key: &[u8; 32], counter: u64, final_flag: u8, plaintext: &[u8]) -> Vec<u8> {
    let chunk_nonce = make_counter_nonce(counter, final_flag);
    let cipher      = Aes256GcmSiv::new_from_slice(stream_key).expect("AES-256 key");
    let nonce       = Nonce::from_slice(&chunk_nonce);
    cipher.encrypt(nonce, Payload { msg: plaintext, aad: &[] })
        .expect("aead encrypt")
}

// ────────────────────────────────────────────────────────────────────────────
// Common preamble validation. Returns (header_bytes, derived) on success.
// ────────────────────────────────────────────────────────────────────────────

pub struct PreambleCheck<'a> {
    pub header:  &'a [u8],
    pub derived: DerivedV3,
}

pub fn check_preamble<'a>(
    label:    &str,
    key:      &[u8],
    nonce:    &[u8],
    preamble: &'a [u8],
    log:      &mut Vec<String>,
) -> Result<PreambleCheck<'a>, String> {
    if key.len() != 32 {
        return Err(format!("{label}: key must be 32 bytes (got {})", key.len()));
    }
    if nonce.len() != 16 {
        return Err(format!("{label}: nonce must be 16 bytes (got {})", nonce.len()));
    }
    if preamble.len() != HEADER_SIZE + COMMIT_SIZE {
        return Err(format!(
            "{label}: v3 preamble must be {} bytes (got {})",
            HEADER_SIZE + COMMIT_SIZE, preamble.len(),
        ));
    }

    let header             = &preamble[..HEADER_SIZE];
    let pinned_commitment  = &preamble[HEADER_SIZE..HEADER_SIZE + COMMIT_SIZE];

    if header[0] & 0x3F != FORMAT_ENUM {
        return Err(format!(
            "{label}: format byte (low 6 bits) is 0x{:02x}, expected 0x{:02x}",
            header[0] & 0x3F, FORMAT_ENUM,
        ));
    }
    if &header[1..17] != nonce {
        return Err(format!("{label}: header nonce ≠ vector nonce"));
    }

    let chunk_size = ((header[17] as u32) << 16)
                   | ((header[18] as u32) << 8)
                   |  (header[19] as u32);
    let framed_flag = (header[0] & 0x80) != 0;
    log.push(format!("  header bytes: {}", hex::encode(header)));
    log.push(format!("  chunkSize: {chunk_size}, framed: {framed_flag}"));

    let key_arr:   &[u8; 32] = key.try_into().unwrap();
    let nonce_arr: &[u8; 16] = nonce.try_into().unwrap();
    let derived = derive_v3(key_arr, nonce_arr, header);

    log.push(format!("  computed commitment: {}", hex::encode(derived.commitment)));
    log.push(format!("  pinned commitment:   {}", hex::encode(pinned_commitment)));

    if derived.commitment != pinned_commitment {
        return Err(format!(
            "{label}: commitment mismatch, HKDF-SHA-256 bytes 32..64 do not match preamble"
        ));
    }
    log.push("  ✓ commitment matches HKDF(masterKey, nonce, INFO‖header, 64)[32:64]".to_string());

    Ok(PreambleCheck { header, derived })
}

// ────────────────────────────────────────────────────────────────────────────
// Single-shot Seal blob verification (single chunk, TAG_FINAL, no framing).
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_seal(v: &SealVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {} ━━━", v.name));
    log.push(format!("  description: {}", v.description));

    let check = match check_preamble(&v.name, &v.key, &v.nonce, &v.preamble, &mut log) {
        Ok(c)  => c,
        Err(e) => { log.push(format!("  ✗ {}", e)); return (false, log); }
    };

    // Chunk 0, TAG_FINAL.
    let aead_out = aead_encrypt(&check.derived.key, 0, TAG_FINAL, &v.plaintext);
    let ct_len   = aead_out.len().saturating_sub(TAG_SIZE);
    let tag      = &aead_out[ct_len..];
    log.push(format!("  ciphertext length: {ct_len} bytes, tag: {}", hex::encode(tag)));

    let mut computed = Vec::with_capacity(v.preamble.len() + aead_out.len());
    computed.extend_from_slice(&v.preamble);
    computed.extend_from_slice(&aead_out);

    if computed != v.blob {
        log.push(format!("  computed blob: {}", hex::encode(&computed)));
        log.push(format!("  pinned blob:   {}", hex::encode(&v.blob)));
        for (i, (a, b)) in computed.iter().zip(v.blob.iter()).enumerate() {
            if a != b {
                log.push(format!(
                    "  first mismatch at byte {i}: computed=0x{:02x}, pinned=0x{:02x}",
                    a, b,
                ));
                break;
            }
        }
        log.push(format!("  ✗ {}: blob mismatch", v.name));
        return (false, log);
    }

    log.push("  ✓ blob matches preamble ‖ AES-256-GCM-SIV(streamKey, counter=0|FINAL, pt, aad=∅)".to_string());
    log.push(format!("  ✓ {}: PASS", v.name));
    (true, log)
}

// ────────────────────────────────────────────────────────────────────────────
// SealStream verification (N chunks, optionally framed).
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_sealstream(v: &SealStreamVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {} ━━━", v.name));
    log.push(format!("  description: {}", v.description));

    let check = match check_preamble(&v.name, &v.key, &v.nonce, &v.preamble, &mut log) {
        Ok(c)  => c,
        Err(e) => { log.push(format!("  ✗ {}", e)); return (false, log); }
    };

    // Header chunkSize must match the vector's chunkSize field.
    // Both values come from independent sources in the file (one in the
    // header bytes, one as a separate JS field) and must agree.
    let header_chunk_size = ((check.header[17] as u32) << 16)
                          | ((check.header[18] as u32) << 8)
                          |  (check.header[19] as u32);
    if header_chunk_size != v.chunk_size {
        log.push(format!(
            "  ✗ {}: chunkSize mismatch, header says {}, vector field says {}",
            v.name, header_chunk_size, v.chunk_size,
        ));
        return (false, log);
    }

    // The header's framed-flag bit must agree with the vector's `framed` field.
    let header_framed = (check.header[0] & 0x80) != 0;
    if header_framed != v.framed {
        log.push(format!(
            "  ✗ {}: framed flag mismatch, header says {}, vector says {}",
            v.name, header_framed, v.framed,
        ));
        return (false, log);
    }

    if v.chunks.is_empty() {
        log.push(format!("  ✗ {}: no chunks", v.name));
        return (false, log);
    }

    let n = v.chunks.len();
    log.push(format!("  chunks: {} (framed: {})", n, v.framed));

    let mut all_ok = true;
    for (i, chunk) in v.chunks.iter().enumerate() {
        let is_final  = i == n - 1;
        let final_flag = if is_final { TAG_FINAL } else { TAG_DATA };
        let counter   = i as u64;

        let aead_out = aead_encrypt(&check.derived.key, counter, final_flag, &chunk.plaintext);

        // Wire shape per chunk:
        //   unframed: ciphertext field IS aead_out (ct || tag)
        //   framed:   ciphertext field is u32be(aead_out.len()) || aead_out
        let expected_wire: Vec<u8> = if v.framed {
            let mut w = Vec::with_capacity(4 + aead_out.len());
            w.extend_from_slice(&(aead_out.len() as u32).to_be_bytes());
            w.extend_from_slice(&aead_out);
            w
        } else {
            aead_out.clone()
        };

        if expected_wire != chunk.ciphertext {
            log.push(format!(
                "  ✗ chunk {}: ciphertext mismatch (counter={}, flag=0x{:02x}, framed={})",
                i, counter, final_flag, v.framed,
            ));
            log.push(format!("    computed: {}", hex::encode(&expected_wire)));
            log.push(format!("    pinned:   {}", hex::encode(&chunk.ciphertext)));
            for (j, (a, b)) in expected_wire.iter().zip(chunk.ciphertext.iter()).enumerate() {
                if a != b {
                    log.push(format!(
                        "    first mismatch at byte {j}: computed=0x{:02x}, pinned=0x{:02x}",
                        a, b,
                    ));
                    break;
                }
            }
            all_ok = false;
        }
    }

    if all_ok {
        log.push(format!("  ✓ all {} chunks match per-chunk AEAD output", n));
        log.push(format!("  ✓ {}: PASS", v.name));
    } else {
        log.push(format!("  ✗ {}: FAIL", v.name));
    }
    (all_ok, log)
}
