// Serpent v3 verifier for both seal blobs (single chunk) and sealstream
// blobs (N chunks, optionally framed).
//
// Wire format:
//
//   preamble:  header(20) = 20 bytes (NO commitment, Serpent's HMAC-SHA-256
//              tag is collision-resistant under SHA-256 and is therefore
//              key-committing natively)
//
//   header:    formatEnum(1) || nonce(16) || chunkSize(u24be, 3)
//              formatEnum bit 7 = framed flag, bit 6 = reserved (0),
//                           bits 5..0 = cipher format ID. Serpent = 0x02.
//
//   per-chunk: ct = Serpent-CBC-PKCS7(enc_key, iv, plaintext)
//              tag = HMAC-SHA-256(mac_key, counterNonce || u32be(aad_len) || aad || ct)
//              wire = ct || tag (32-byte tag, IV is NOT transmitted)
//
//              counterNonce = (i)_be11 || finalFlag(1)
//              iv           = HMAC-SHA-256(iv_key, counterNonce)[0..16]
//              finalFlag    = TAG_DATA(0x00) for i < N-1, TAG_FINAL(0x01) for i == N-1
//
//   framed:    each chunk on the wire is prefixed with u32be(chunk_len)
//              (only when header bit 7 is set; affects wire only, not crypto)
//
//   keys:      96-byte HKDF-SHA-256 output split as:
//                enc_key = okm[0..32]  , Serpent-256 encryption
//                mac_key = okm[32..64] , HMAC-SHA-256 chunk authentication
//                iv_key  = okm[64..96] , per-chunk IV derivation via HMAC
//              info string is plain b'serpent-sealstream-v3' (no header bound).

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serpent::Serpent;
use serpent::cipher::{BlockCipherEncrypt, KeyInit, array::Array, consts::U16};

use crate::primitives::cbc::cbc_encrypt;
use crate::primitives::pkcs7::pad;
use crate::parse::{SealVector, SealStreamVector};

type HmacSha256 = Hmac<Sha256>;
type Block      = Array<u8, U16>;

const INFO_V3:     &[u8] = b"serpent-sealstream-v3";
const HEADER_SIZE: usize = 20;
const TAG_SIZE:    usize = 32;
const FORMAT_ENUM: u8    = 0x02;
const TAG_DATA:    u8    = 0x00;
const TAG_FINAL:   u8    = 0x01;

#[derive(Debug)]
pub struct DerivedV3 {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub iv_key:  [u8; 32],
}

pub fn derive_v3(master_key: &[u8; 32], nonce16: &[u8; 16]) -> DerivedV3 {
    let hkdf = Hkdf::<Sha256>::new(Some(nonce16), master_key);
    let mut okm = [0u8; 96];
    hkdf.expand(INFO_V3, &mut okm).expect("hkdf expand 96");

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&okm[0..32]);
    let mut mac_key = [0u8; 32];
    mac_key.copy_from_slice(&okm[32..64]);
    let mut iv_key = [0u8; 32];
    iv_key.copy_from_slice(&okm[64..96]);

    DerivedV3 { enc_key, mac_key, iv_key }
}

fn make_counter_nonce(counter: u64, final_flag: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let counter_be = counter.to_be_bytes();
    nonce[3..11].copy_from_slice(&counter_be);
    nonce[11] = final_flag;
    nonce
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

// Encrypt one chunk: PKCS#7-pad, CBC-chain, HMAC-tag, return ct || tag.
//
// leviathan-crypto v3 uses NIST natural byte order at the public Serpent
// API, matching RustCrypto's `serpent` crate, FIPS 197, and AB&K's NESSIE
// submission. Keys and blocks pass through unmodified.
fn seal_chunk_serpent(
    keys:        &DerivedV3,
    counter:     u64,
    final_flag:  u8,
    plaintext:   &[u8],
) -> Vec<u8> {
    let counter_nonce = make_counter_nonce(counter, final_flag);

    // IV = HMAC-SHA-256(iv_key, counterNonce)[0..16]
    let iv_full = hmac_sha256(&keys.iv_key, &counter_nonce);
    let iv      = &iv_full[..16];

    let cipher = Serpent::new_from_slice(&keys.enc_key).expect("Serpent::new_from_slice");

    let padded = pad(plaintext);
    let ct = cbc_encrypt(iv, &padded, |block| {
        let mut arr: Block = Array::try_from(&block[..]).unwrap();
        cipher.encrypt_block(&mut arr);
        block.copy_from_slice(arr.as_slice());
    });

    // tag = HMAC-SHA-256(mac_key, counterNonce || u32be(aad_len=0) || aad="" || ct)
    let mut tag_input = Vec::with_capacity(12 + 4 + ct.len());
    tag_input.extend_from_slice(&counter_nonce);
    tag_input.extend_from_slice(&0u32.to_be_bytes());
    tag_input.extend_from_slice(&ct);
    let tag = hmac_sha256(&keys.mac_key, &tag_input);

    let mut wire = Vec::with_capacity(ct.len() + TAG_SIZE);
    wire.extend_from_slice(&ct);
    wire.extend_from_slice(&tag);
    wire
}

// ────────────────────────────────────────────────────────────────────────────
// Common preamble validation. Serpent v3 has no commitment, so this is much
// simpler than the XChaCha20 v3 case. Just header sanity checks plus key
// derivation.
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
    if preamble.len() != HEADER_SIZE {
        return Err(format!(
            "{label}: v3 preamble must be {} bytes (got {})",
            HEADER_SIZE, preamble.len(),
        ));
    }

    let header = &preamble[..HEADER_SIZE];

    if header[0] & 0x3F != FORMAT_ENUM {
        return Err(format!(
            "{label}: format byte (low 6 bits) is 0x{:02x}, expected 0x{:02x}",
            header[0] & 0x3F, FORMAT_ENUM,
        ));
    }
    if &header[1..17] != nonce {
        return Err(format!("{label}: header nonce ≠ vector nonce"));
    }

    let chunk_size  = ((header[17] as u32) << 16)
                    | ((header[18] as u32) << 8)
                    |  (header[19] as u32);
    let framed_flag = (header[0] & 0x80) != 0;
    log.push(format!("  header bytes: {}", hex::encode(header)));
    log.push(format!("  chunkSize: {chunk_size}, framed: {framed_flag}"));

    let key_arr:   &[u8; 32] = key.try_into().unwrap();
    let nonce_arr: &[u8; 16] = nonce.try_into().unwrap();
    let derived = derive_v3(key_arr, nonce_arr);

    log.push("  derived 96 bytes from HKDF-SHA-256: enc_key[0..32] || mac_key[32..64] || iv_key[64..96]".to_string());

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

    // Single chunk, counter 0, TAG_FINAL.
    let wire = seal_chunk_serpent(&check.derived, 0, TAG_FINAL, &v.plaintext);
    let ct_len = wire.len().saturating_sub(TAG_SIZE);
    let tag = &wire[ct_len..];
    log.push(format!("  ciphertext length: {ct_len} bytes (PKCS#7-padded), tag: {}", hex::encode(tag)));

    let mut computed = Vec::with_capacity(v.preamble.len() + wire.len());
    computed.extend_from_slice(&v.preamble);
    computed.extend_from_slice(&wire);

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

    log.push("  ✓ blob matches preamble ‖ Serpent-CBC-PKCS7(enc_key, iv, pt) ‖ HMAC-SHA-256(mac_key, ...)".to_string());
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

        let wire_inner = seal_chunk_serpent(&check.derived, counter, final_flag, &chunk.plaintext);

        // Wire shape per chunk:
        //   unframed: ciphertext field IS wire_inner (ct || tag)
        //   framed:   ciphertext field is u32be(wire_inner.len()) || wire_inner
        let expected_wire: Vec<u8> = if v.framed {
            let mut w = Vec::with_capacity(4 + wire_inner.len());
            w.extend_from_slice(&(wire_inner.len() as u32).to_be_bytes());
            w.extend_from_slice(&wire_inner);
            w
        } else {
            wire_inner.clone()
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
        log.push(format!("  ✓ all {} chunks match per-chunk Serpent-CBC + HMAC output", n));
        log.push(format!("  ✓ {}: PASS", v.name));
    } else {
        log.push(format!("  ✗ {}: FAIL", v.name));
    }
    (all_ok, log)
}
