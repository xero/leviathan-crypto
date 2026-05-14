// Independent verifier for SLH-DSA (FIPS 205) vectors.
//
// Reads `slhdsa_keygen.ts`, `slhdsa_siggen.ts`, and `slhdsa_sigver.ts`
// (parsed by `parse::parse_slhdsa_*_array`) and runs each record through
// RustCrypto's `slh-dsa` crate. Phase 2 scope: SHAKE-fast variants
// (SLH-DSA-SHAKE-{128f,192f,256f}) only.
//
// The verifier reproduces ACVP's expected outputs byte-for-byte:
//
//   keyGen,  SigningKey::slh_keygen_internal(skSeed, skPrf, pkSeed) per
//            FIPS 205 §9 Algorithm 17. The encoded sk/pk (skEncode /
//            pkEncode per §9) are compared to ACVP `sk` / `pk`.
//
//   sigGen,  SigningKey deserialized via TryFrom<&[u8]>; the verifier
//            then builds the M' the crate expects per (signatureInterface,
//            preHash) and calls slh_sign_internal(M', opt_rand). For
//            deterministic=true, opt_rand=None (the crate substitutes
//            PK.seed per FIPS 205 §3.4); for hedged tests, opt_rand is
//            the ACVP `additionalRandomness` value.
//
//   sigVer,  VerifyingKey::try_from(pk_bytes) and Signature::try_from
//            (sig_bytes), then slh_verify_internal(M', sig). The bool is
//            compared to ACVP `testPassed`.
//
// HashSLH-DSA (preHash) records compose the M' manually here, since the
// crate does not expose a hash-and-sign convenience wrapper. The OID +
// digest-length table comes from FIPS 205 §10.2 (which aligns with
// FIPS 204 §5.4 Table 1: same OID arc 2.16.840.1.101.3.4.2.NN per
// hashAlg, so the byte layout is shared with the ML-DSA pre-hash path
// in src/mldsa.rs).
//
// Different crate, different lineage, same bytes out. RustCrypto's
// `slh-dsa` is independent of leviathan-crypto's WASM stack; if both
// verifiers agree, the vector transcription is correct.

use slh_dsa::{
    Shake128f, Shake192f, Shake256f,
    Signature, SigningKey, VerifyingKey,
};

use crate::byte_diff::log_byte_diff;
use crate::parse::{SlhDsaKeyGenVector, SlhDsaSigGenVector, SlhDsaSigVerVector};

// ────────────────────────────────────────────────────────────────────────────
// HashSLH-DSA pre-hash table (FIPS 205 §10.2, OID alignment per §10.2 Table 11
// which is identical to FIPS 204 §5.4 Table 1 for the shared hashAlg set).
// Returns (OID DER bytes, PH_M = H_hashAlg(M)) at the FIPS-spec'd output
// length. Shake-128 / Shake-256 produce 32 / 64 bytes respectively.
// ────────────────────────────────────────────────────────────────────────────

fn pre_hash_for(hash_alg: &str, m: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // OID DER: 06 09 60 86 48 01 65 03 04 02 NN
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
            let mut out = vec![0u8; 32]; // FIPS 205 §10.2 Table 11, 256 bits
            r.read(&mut out);
            Some((oid(0x0B), out))
        }
        "SHAKE-256" => {
            use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
            let mut h = Shake256::default();
            h.update(m);
            let mut r = h.finalize_xof();
            let mut out = vec![0u8; 64]; // FIPS 205 §10.2 Table 11, 512 bits
            r.read(&mut out);
            Some((oid(0x0C), out))
        }
        _ => None,
    }
}

// Build the FIPS 205 M' input for slh_sign_internal / slh_verify_internal.
//
//   external/pure:    M' = 0x00 || ctx_len_u8 || ctx || M
//   external/preHash: M' = 0x01 || ctx_len_u8 || ctx || OID || PH_M
//   internal/none:    M' = M
//
// Errors: ctx too long, unknown preHash hashAlg, or unknown
// (signatureInterface, preHash) pair.
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
            let mut out = Vec::with_capacity(2 + context.len() + oid.len() + ph_m.len());
            out.push(0x01);
            out.push(context.len() as u8);
            out.extend_from_slice(context);
            out.extend_from_slice(&oid);
            out.extend_from_slice(&ph_m);
            Ok(out)
        }
        _ => Err(format!(
            "unsupported (signatureInterface={}, preHash={})",
            signature_interface, pre_hash
        )),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Per-parameter-set verifiers, expanded by macro for keygen / sigGen / sigVer.
// ────────────────────────────────────────────────────────────────────────────

macro_rules! slhdsa_verifier {
    ($paramset:ty, $kg_fn:ident, $sg_fn:ident, $sv_fn:ident) => {

        pub fn $kg_fn(v: &SlhDsaKeyGenVector) -> (bool, Vec<String>) {
            let mut log = Vec::new();
            log.push(format!("━━━ slhdsa keygen tcId {} ━━━", v.tc_id));

            // slh_keygen_internal takes three byte slices of length n. The
            // crate asserts internally; we surface a clean error if the
            // vector's seed bytes are missing or wrong size.
            let sk = SigningKey::<$paramset>::slh_keygen_internal(
                &v.sk_seed, &v.sk_prf, &v.pk_seed,
            );

            let sk_bytes: Vec<u8> = sk.to_bytes().as_slice().to_vec();
            let pk_bytes: Vec<u8> = sk.as_ref().to_bytes().as_slice().to_vec();

            log_byte_diff(&mut log, "pk", &pk_bytes, &v.pk);
            log_byte_diff(&mut log, "sk", &sk_bytes, &v.sk);

            if pk_bytes == v.pk && sk_bytes == v.sk {
                log.push(format!(
                    "  ✓ pk ({} B) and sk ({} B) match",
                    v.pk.len(), v.sk.len(),
                ));
                (true, log)
            } else {
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $sg_fn(v: &SlhDsaSigGenVector) -> (bool, Vec<String>) {
            let mut log = Vec::new();
            log.push(format!(
                "━━━ slhdsa sigGen tcId {} (tg={}, sigInt={}, preHash={}, det={}) ━━━",
                v.tc_id, v.tg_id, v.signature_interface, v.pre_hash, v.deterministic,
            ));

            let sk = match SigningKey::<$paramset>::try_from(v.sk.as_slice()) {
                Ok(s)  => s,
                Err(e) => {
                    log.push(format!("  ✗ sk decode failed: {e:?}"));
                    return (false, log);
                }
            };

            let m_prime = match build_m_prime(
                &v.signature_interface, &v.pre_hash, &v.hash_alg,
                &v.message, &v.context,
            ) {
                Ok(m)  => m,
                Err(e) => { log.push(format!("  ✗ M' build failed: {e}")); return (false, log); }
            };

            // opt_rand = additionalRandomness (hedged) or None (deterministic
            // → crate substitutes PK.seed per FIPS 205 §3.4).
            let opt_rand: Option<&[u8]> = if v.deterministic {
                None
            } else {
                match v.additional_randomness.as_deref() {
                    Some(r) => Some(r),
                    None => {
                        log.push("  ✗ deterministic=false but additionalRandomness missing".to_string());
                        return (false, log);
                    }
                }
            };

            let sig = sk.slh_sign_internal(&[&m_prime], opt_rand);
            let sig_bytes: Vec<u8> = sig.to_bytes().as_slice().to_vec();

            log_byte_diff(&mut log, "signature", &sig_bytes, &v.signature);

            if sig_bytes == v.signature {
                log.push(format!("  ✓ signature ({} B) matches", v.signature.len()));
                (true, log)
            } else {
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $sv_fn(v: &SlhDsaSigVerVector) -> (bool, Vec<String>) {
            let mut log = Vec::new();
            log.push(format!(
                "━━━ slhdsa sigVer tcId {} (tg={}, sigInt={}, preHash={}) → expected={} ━━━",
                v.tc_id, v.tg_id, v.signature_interface, v.pre_hash, v.test_passed,
            ));

            let vk = match VerifyingKey::<$paramset>::try_from(v.pk.as_slice()) {
                Ok(v) => v,
                Err(_) => return finalize(&mut log, false, v.test_passed),
            };

            let sig = match Signature::<$paramset>::try_from(v.signature.as_slice()) {
                Ok(s) => s,
                Err(_) => return finalize(&mut log, false, v.test_passed),
            };

            let m_prime = match build_m_prime(
                &v.signature_interface, &v.pre_hash, &v.hash_alg,
                &v.message, &v.context,
            ) {
                Ok(m)  => m,
                Err(_) => return finalize(&mut log, false, v.test_passed),
            };

            let ok = vk.slh_verify_internal(&[&m_prime], &sig).is_ok();
            finalize(&mut log, ok, v.test_passed)
        }
    };
}

fn finalize(log: &mut Vec<String>, computed: bool, expected: bool) -> (bool, Vec<String>) {
    if computed == expected {
        log.push(format!("  ✓ verification {} matches expected", computed));
        (true, std::mem::take(log))
    } else {
        log.push(format!("  ✗ verification {} ≠ expected {}", computed, expected));
        (false, std::mem::take(log))
    }
}

slhdsa_verifier!(Shake128f, verify_keygen_128f, verify_siggen_128f, verify_sigver_128f);
slhdsa_verifier!(Shake192f, verify_keygen_192f, verify_siggen_192f, verify_sigver_192f);
slhdsa_verifier!(Shake256f, verify_keygen_256f, verify_siggen_256f, verify_sigver_256f);
