// Independent verifier for ML-DSA (FIPS 204 final) vectors.
//
// Reads `mldsa_keygen.ts`, `mldsa_siggen.ts`, and `mldsa_sigver.ts` (parsed
// by `parse::parse_mldsa_*_array`) and runs each record through RustCrypto's
// `ml-dsa` crate. ACVP vsId=42 corpus, including HashML-DSA merged via the
// per-record `preHash` discriminator.
//
// The verifier reproduces ACVP's expected outputs byte-for-byte:
//
//   keyGen — `KeyGen::from_seed(xi)` returns a `SigningKey<P>`; the
//            matching pk and expanded sk encodings (FIPS 204 Algorithms 22 +
//            24) are compared to ACVP `pk` and `sk`.
//
//   sigGen — `ExpandedSigningKey::from_expanded(sk_bytes)` rehydrates the
//            key; we then build M' according to (signatureInterface,
//            preHash, externalMu) per FIPS 204 §6.2 / §5.4 and call
//            `sign_internal(&[Mp], &rnd)` (or `sign_mu_*` for externalMu).
//            For deterministic=true, rnd is the all-zero 32-byte vector.
//
//   sigVer — `VerifyingKey::decode(pk_bytes)` plus `Signature::decode(...)`,
//            then `verify_internal(&Mp, &sig)` (or `verify_mu(mu, &sig)`).
//            The bool is compared to ACVP `testPassed`.
//
// Different crate, different lineage, same bytes out. RustCrypto's `ml-dsa`
// is independent of leviathan-crypto's WASM stack; if both verifiers agree,
// the vector transcription is correct.
//
// Note (security): rc.4 fixed GHSA-5x2r-hc65-25f9 (verifier accepted hint
// vectors with non-strictly-increasing indices). The pinned rc.9 is on the
// patched side of that advisory, so sigVer fail-because-of-hint-malleability
// vectors are correctly rejected by this oracle.

#![allow(deprecated)] // ExpandedSigningKey::{from_expanded, to_expanded} is the
                      // only API path that round-trips ACVP's encoded sk bytes.

use core::convert::Infallible;

use ml_dsa::{
    KeyGen, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
    Signature, VerifyingKey, B32,
};
use ml_dsa::signature::Keypair;
use rand_core::TryRng;

use crate::parse::{MlDsaKeyGenVector, MlDsaSigGenVector, MlDsaSigVerVector};

// ────────────────────────────────────────────────────────────────────────────
// Diff helpers
// ────────────────────────────────────────────────────────────────────────────

fn first_diff(computed: &[u8], expected: &[u8]) -> Option<(usize, u8, u8)> {
    for (i, (a, b)) in computed.iter().zip(expected.iter()).enumerate() {
        if a != b { return Some((i, *a, *b)); }
    }
    None
}

fn log_byte_diff(log: &mut Vec<String>, label: &str, computed: &[u8], expected: &[u8]) {
    if computed != expected {
        if let Some((i, a, b)) = first_diff(computed, expected) {
            log.push(format!(
                "  ✗ {label} first byte mismatch at offset {i}: computed=0x{a:02x}, expected=0x{b:02x}",
            ));
        }
        if computed.len() != expected.len() {
            log.push(format!(
                "  ✗ {label} length mismatch: computed={} expected={}",
                computed.len(), expected.len(),
            ));
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// FixedRng: a deterministic Rng impl that returns ACVP-supplied rnd bytes
// for `sign_mu_randomized` (the only public API that lets the caller pick
// rnd alongside an explicit µ — needed for hedged externalMu sigGen tests).
// All other paths feed `sign_internal` or `sign_mu_deterministic` directly.
// ────────────────────────────────────────────────────────────────────────────

struct FixedRng {
    buf: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    fn new(bytes: &[u8]) -> Self { Self { buf: bytes.to_vec(), pos: 0 } }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        // Cycle the supplied bytes if a caller asks for more than were given;
        // in practice ml-dsa's sign_mu_randomized requests exactly 32 bytes
        // of rnd, matching the FixedRng buffer length. Cycling preserves the
        // total-function shape without panicking on speculative reads.
        for byte in dst.iter_mut() {
            if self.buf.is_empty() {
                *byte = 0;
            } else {
                *byte = self.buf[self.pos % self.buf.len()];
                self.pos += 1;
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

// ────────────────────────────────────────────────────────────────────────────
// HashML-DSA OID + pre-hash dispatch (FIPS 204 §5.4 + Table 4)
// Each entry is the 11-byte DER-encoded OID for the named hashAlg plus a
// boxed closure that produces PH_M = H_hashAlg(M) at the spec'd output size.
// ────────────────────────────────────────────────────────────────────────────

fn pre_hash_for(hash_alg: &str, m: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // OID structure: 06 09 60 86 48 01 65 03 04 02 NN
    // where NN is the trailing arc number from joint-iso-itu-t.country.us
    // .organization.gov.csor.nistalgorithm.hashalgs.<hashAlg> (2.16.840.1.101.3.4.2.NN).
    fn oid(arc: u8) -> Vec<u8> {
        vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc]
    }

    match hash_alg {
        "SHA2-224" => {
            use sha2::{Digest, Sha224};
            Some((oid(0x04), Sha224::digest(m).to_vec()))
        }
        "SHA2-256" => {
            use sha2::{Digest, Sha256};
            Some((oid(0x01), Sha256::digest(m).to_vec()))
        }
        "SHA2-384" => {
            use sha2::{Digest, Sha384};
            Some((oid(0x02), Sha384::digest(m).to_vec()))
        }
        "SHA2-512" => {
            use sha2::{Digest, Sha512};
            Some((oid(0x03), Sha512::digest(m).to_vec()))
        }
        "SHA2-512/224" => {
            use sha2::{Digest, Sha512_224};
            Some((oid(0x05), Sha512_224::digest(m).to_vec()))
        }
        "SHA2-512/256" => {
            use sha2::{Digest, Sha512_256};
            Some((oid(0x06), Sha512_256::digest(m).to_vec()))
        }
        "SHA3-224" => {
            use sha3::{Digest, Sha3_224};
            Some((oid(0x07), Sha3_224::digest(m).to_vec()))
        }
        "SHA3-256" => {
            use sha3::{Digest, Sha3_256};
            Some((oid(0x08), Sha3_256::digest(m).to_vec()))
        }
        "SHA3-384" => {
            use sha3::{Digest, Sha3_384};
            Some((oid(0x09), Sha3_384::digest(m).to_vec()))
        }
        "SHA3-512" => {
            use sha3::{Digest, Sha3_512};
            Some((oid(0x0A), Sha3_512::digest(m).to_vec()))
        }
        "SHAKE-128" => {
            use sha3::{Shake128, digest::{ExtendableOutput, Update, XofReader}};
            let mut h = Shake128::default();
            h.update(m);
            let mut r = h.finalize_xof();
            let mut out = vec![0u8; 32]; // PH_M: 256 bits per FIPS 204 Table 4
            r.read(&mut out);
            Some((oid(0x0B), out))
        }
        "SHAKE-256" => {
            use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
            let mut h = Shake256::default();
            h.update(m);
            let mut r = h.finalize_xof();
            let mut out = vec![0u8; 64]; // PH_M: 512 bits per FIPS 204 Table 4
            r.read(&mut out);
            Some((oid(0x0C), out))
        }
        _ => None,
    }
}

// Build the FIPS 204 M' input expected by `sign_internal` / `verify_internal`
// for external pure / external preHash. Returns Err if ctx is too long.
fn build_m_prime(
    signature_interface: &str,
    pre_hash: &str,
    hash_alg: &str,
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, String> {
    if context.len() > 255 {
        return Err(format!("context length {} > 255", context.len()));
    }
    match (signature_interface, pre_hash) {
        ("internal", _) => Ok(message.to_vec()),
        ("external", "pure") => {
            // M' = 0x00 || ctx_len_u8 || ctx || M
            let mut out = Vec::with_capacity(2 + context.len() + message.len());
            out.push(0x00);
            out.push(context.len() as u8);
            out.extend_from_slice(context);
            out.extend_from_slice(message);
            Ok(out)
        }
        ("external", "preHash") => {
            let (oid, ph_m) = pre_hash_for(hash_alg, message)
                .ok_or_else(|| format!("unsupported hashAlg {}", hash_alg))?;
            // M' = 0x01 || ctx_len_u8 || ctx || OID || PH_M
            let mut out = Vec::with_capacity(2 + context.len() + oid.len() + ph_m.len());
            out.push(0x01);
            out.push(context.len() as u8);
            out.extend_from_slice(context);
            out.extend_from_slice(&oid);
            out.extend_from_slice(&ph_m);
            Ok(out)
        }
        _ => Err(format!("unsupported (signatureInterface={}, preHash={})", signature_interface, pre_hash)),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Per-parameter-set verifiers, expanded by macro for keygen / sigGen / sigVer
// ────────────────────────────────────────────────────────────────────────────

macro_rules! mldsa_verifier {
    ($paramset:ty, $kg_fn:ident, $sg_fn:ident, $sv_fn:ident) => {

        pub fn $kg_fn(v: &MlDsaKeyGenVector) -> (bool, Vec<String>) {
            let mut log = Vec::new();
            log.push(format!("━━━ keygen tcId {} ━━━", v.tc_id));

            if v.seed.len() != 32 {
                log.push(format!("  ✗ seed.len()={} (expected 32)", v.seed.len()));
                return (false, log);
            }
            let mut xi_bytes = [0u8; 32];
            xi_bytes.copy_from_slice(&v.seed);
            let xi: B32 = ml_dsa::B32::from(xi_bytes);

            let kp = <$paramset as KeyGen>::from_seed(&xi);
            let pk_bytes: Vec<u8> = kp.verifying_key().encode().as_slice().to_vec();
            let sk_bytes: Vec<u8> = kp.signing_key().to_expanded().as_slice().to_vec();

            log_byte_diff(&mut log, "pk", &pk_bytes, &v.pk);
            log_byte_diff(&mut log, "sk", &sk_bytes, &v.sk);

            if pk_bytes == v.pk && sk_bytes == v.sk {
                log.push(format!("  ✓ pk ({} B) and sk ({} B) match", v.pk.len(), v.sk.len()));
                (true, log)
            } else {
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $sg_fn(v: &MlDsaSigGenVector) -> (bool, Vec<String>) {
            type Sk = ml_dsa::ExpandedSigningKey<$paramset>;
            type SkBytes = ml_dsa::ExpandedSigningKeyBytes<$paramset>;
            type Sig = Signature<$paramset>;
            type SigBytes = ml_dsa::EncodedSignature<$paramset>;

            let mut log = Vec::new();
            log.push(format!(
                "━━━ sigGen tcId {} (tg={}, sigInt={}, preHash={}, extMu={}, det={}) ━━━",
                v.tc_id, v.tg_id, v.signature_interface, v.pre_hash, v.external_mu, v.deterministic,
            ));

            // 1. Decode sk via the deprecated expanded-key path. ACVP gives sk
            //    as the encoded skEncode bytes; KeyGen::from_seed re-derives it
            //    but is keyed on xi rather than the bytes, so we use the
            //    deprecated decoder. Length mismatch is hard fail.
            let sk_arr = match SkBytes::try_from(v.sk.as_slice()) {
                Ok(a)  => a,
                Err(e) => { log.push(format!("  ✗ sk length error: {e:?}")); return (false, log); }
            };
            let sk = Sk::from_expanded(&sk_arr);

            // 2. Build rnd: 32 zero bytes if deterministic, else the supplied rnd.
            let mut rnd_bytes = [0u8; 32];
            if !v.deterministic {
                let r = match v.rnd.as_ref() {
                    Some(r) if r.len() == 32 => r,
                    _ => {
                        log.push(format!("  ✗ deterministic=false but rnd missing or wrong length"));
                        return (false, log);
                    }
                };
                rnd_bytes.copy_from_slice(r);
            }
            let rnd: B32 = ml_dsa::B32::from(rnd_bytes);

            // 3. Sign by branch.
            let sig: Sig = if v.external_mu {
                if v.signature_interface != "internal" {
                    log.push(format!("  ✗ unexpected externalMu=true with signatureInterface={}", v.signature_interface));
                    return (false, log);
                }
                let mu_bytes = match v.mu.as_ref() {
                    Some(m) if m.len() == 64 => m,
                    _ => { log.push(format!("  ✗ externalMu=true but mu missing or wrong length")); return (false, log); }
                };
                let mut mu_arr = [0u8; 64];
                mu_arr.copy_from_slice(mu_bytes);
                let mu: hybrid_array::Array<u8, hybrid_array::typenum::U64> =
                    hybrid_array::Array::from(mu_arr);
                if v.deterministic {
                    sk.sign_mu_deterministic(&mu)
                } else {
                    let mut rng = FixedRng::new(&rnd_bytes);
                    match sk.sign_mu_randomized(&mu, &mut rng) {
                        Ok(s)  => s,
                        Err(e) => { log.push(format!("  ✗ sign_mu_randomized failed: {e:?}")); return (false, log); }
                    }
                }
            } else {
                let message = match v.message.as_ref() {
                    Some(m) => m.as_slice(),
                    None    => { log.push(format!("  ✗ message missing")); return (false, log); }
                };
                let context: &[u8] = v.context.as_deref().unwrap_or(&[]);
                let m_prime = match build_m_prime(&v.signature_interface, &v.pre_hash, &v.hash_alg, message, context) {
                    Ok(m)  => m,
                    Err(e) => { log.push(format!("  ✗ M' build failed: {e}")); return (false, log); }
                };
                sk.sign_internal(&[&m_prime], &rnd)
            };

            let sig_bytes: Vec<u8> = sig.encode().as_slice().to_vec();
            log_byte_diff(&mut log, "signature", &sig_bytes, &v.signature);

            if sig_bytes == v.signature {
                log.push(format!("  ✓ signature ({} B) matches", v.signature.len()));
                (true, log)
            } else {
                // Surface the round-trip viability of the expected signature
                // (so we can tell "wrong bytes" from "fundamental encoding shift").
                let _ = SigBytes::try_from(v.signature.as_slice())
                    .map_err(|e| log.push(format!("  ✗ expected sigBytes failed length check: {e:?}")));
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $sv_fn(v: &MlDsaSigVerVector) -> (bool, Vec<String>) {
            type Vk = VerifyingKey<$paramset>;
            type VkBytes = ml_dsa::EncodedVerifyingKey<$paramset>;
            type Sig = Signature<$paramset>;
            type SigBytes = ml_dsa::EncodedSignature<$paramset>;

            let mut log = Vec::new();
            log.push(format!(
                "━━━ sigVer tcId {} (tg={}, sigInt={}, preHash={}, extMu={}) → expected={} ━━━",
                v.tc_id, v.tg_id, v.signature_interface, v.pre_hash, v.external_mu, v.test_passed,
            ));

            let vk_arr = match VkBytes::try_from(v.pk.as_slice()) {
                Ok(a)  => a,
                Err(e) => {
                    // pk-length mismatch is a verification failure outright.
                    log.push(format!("  pk length error: {e:?}"));
                    return finalize(&mut log, false, v.test_passed);
                }
            };
            let vk: Vk = Vk::decode(&vk_arr);

            let sig_arr = match SigBytes::try_from(v.signature.as_slice()) {
                Ok(a)  => a,
                Err(_) => {
                    return finalize(&mut log, false, v.test_passed);
                }
            };
            let sig: Sig = match Sig::decode(&sig_arr) {
                Some(s) => s,
                None    => {
                    return finalize(&mut log, false, v.test_passed);
                }
            };

            let ok = if v.external_mu {
                if v.signature_interface != "internal" {
                    return finalize(&mut log, false, v.test_passed);
                }
                let mu_bytes = match v.mu.as_ref() {
                    Some(m) if m.len() == 64 => m,
                    _ => return finalize(&mut log, false, v.test_passed),
                };
                let mut mu_arr = [0u8; 64];
                mu_arr.copy_from_slice(mu_bytes);
                let mu: hybrid_array::Array<u8, hybrid_array::typenum::U64> =
                    hybrid_array::Array::from(mu_arr);
                vk.verify_mu(&mu, &sig)
            } else {
                let message = match v.message.as_ref() {
                    Some(m) => m.as_slice(),
                    None    => return finalize(&mut log, false, v.test_passed),
                };
                let context: &[u8] = v.context.as_deref().unwrap_or(&[]);
                match build_m_prime(&v.signature_interface, &v.pre_hash, &v.hash_alg, message, context) {
                    Ok(m_prime) => vk.verify_internal(&m_prime, &sig),
                    Err(_)      => false,
                }
            };

            finalize(&mut log, ok, v.test_passed)
        }
    };
}

// Common sigVer outcome formatting — kept outside the macro so the help-text
// does not need to expand into every parameter-set's verifier.
fn finalize(log: &mut Vec<String>, computed: bool, expected: bool) -> (bool, Vec<String>) {
    if computed == expected {
        log.push(format!("  ✓ verification {} matches expected", computed));
        (true, std::mem::take(log))
    } else {
        log.push(format!("  ✗ verification {} ≠ expected {}", computed, expected));
        (false, std::mem::take(log))
    }
}

mldsa_verifier!(MlDsa44, verify_keygen_44, verify_siggen_44, verify_sigver_44);
mldsa_verifier!(MlDsa65, verify_keygen_65, verify_siggen_65, verify_sigver_65);
mldsa_verifier!(MlDsa87, verify_keygen_87, verify_siggen_87, verify_sigver_87);

// MlDsaParams trait bound is needed by the generic helpers above.
#[allow(dead_code)]
fn _use_paramset_trait<P: MlDsaParams>() {}
