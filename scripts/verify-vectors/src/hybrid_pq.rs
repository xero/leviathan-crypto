// Independent verifier for PQ-only hybrid composite vectors
// (sign_hybrid_pq.ts).
//
// The leviathan-defined hybrid wire format concatenates ML-DSA first then
// SLH-DSA, with no length prefixes (sizes are catalog-known per hybrid):
//
//   pk_combined  = pk_mldsa  || pk_slhdsa
//   sk_combined  = sk_mldsa  || sk_slhdsa
//   sig_combined = sig_mldsa || sig_slhdsa
//
// Each half is signed over the same prehash digest under the same
// effective_ctx, where effective_ctx wraps user_ctx with the hybrid's
// ctxDomain string per docs/signaturesuite.md. The OID + M' layout for
// ML-DSA pre-hash (FIPS 204 §5.4) and SLH-DSA pre-hash (FIPS 205 §10.2)
// coincide for the SHAKE family (same OIDs, same M' framing), so the
// two halves see byte-identical input despite invoking different
// primitives.
//
// This verifier reproduces the suite's verify path by:
//   1. Parsing each vector and splitting the catalog-sized pk and sig.
//   2. Hashing msg with SHAKE128 (cat-1) or SHAKE256 (cat-3 / cat-5).
//   3. Building effective_ctx = [1, |dom|, dom, 1, |ctx|, ctx] per the
//      leviathan suite layer (matches `buildEffectiveCtx`).
//   4. Building each half's M' separately via build_m_prime() shared with
//      the standalone ML-DSA / SLH-DSA verifiers.
//   5. Calling RustCrypto verify on each half and AND-ing the booleans.
//
// Different crates (ml-dsa, slh-dsa), different lineage, same verdict.

use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
    Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
};
use slh_dsa::{
    Shake128f, Shake192f, Shake256f,
    Signature as SlhSignature, VerifyingKey as SlhVerifyingKey,
};

use crate::parse::SignHybridPqVector;

// ────────────────────────────────────────────────────────────────────────────
// Catalog-known sizes per hybrid (FIPS 204 §4 Table 1 + FIPS 205 §11.1 Table 2)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct HybridSizes {
    mldsa_pk:  usize,
    mldsa_sk:  usize,
    mldsa_sig: usize,
    slh_pk:    usize,
    slh_sk:    usize,
    slh_sig:   usize,
}

impl HybridSizes {
    const fn pk(&self)  -> usize { self.mldsa_pk  + self.slh_pk  }
    const fn sk(&self)  -> usize { self.mldsa_sk  + self.slh_sk  }
    const fn sig(&self) -> usize { self.mldsa_sig + self.slh_sig }
}

const SIZES_30: HybridSizes = HybridSizes {
    mldsa_pk:  1312, mldsa_sk:  2560, mldsa_sig: 2420,
    slh_pk:      32, slh_sk:      64, slh_sig:  17088,
};
const SIZES_31: HybridSizes = HybridSizes {
    mldsa_pk:  1952, mldsa_sk:  4032, mldsa_sig: 3309,
    slh_pk:      48, slh_sk:      96, slh_sig:  35664,
};
const SIZES_32: HybridSizes = HybridSizes {
    mldsa_pk:  2592, mldsa_sk:  4896, mldsa_sig: 4627,
    slh_pk:      64, slh_sk:     128, slh_sig:  49856,
};

// Domain-separator strings; mirror src/ts/sign/suites/hybrid-pq.ts.
const CTX_DOMAIN_30: &str = "mldsa44-slhdsa128f-envelope-v3";
const CTX_DOMAIN_31: &str = "mldsa65-slhdsa192f-envelope-v3";
const CTX_DOMAIN_32: &str = "mldsa87-slhdsa256f-envelope-v3";

// SHAKE128 / SHAKE256 OID DER (same in FIPS 204 §5.4.1 Table 1 and
// FIPS 205 §10.2 Table 11).
fn shake_oid(arc: u8) -> Vec<u8> {
    vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc]
}

fn shake_digest(algo: &str, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match algo {
        "shake-128" => {
            use sha3::{Shake128, digest::{ExtendableOutput, Update, XofReader}};
            let mut h = Shake128::default();
            h.update(msg);
            let mut r = h.finalize_xof();
            let mut out = vec![0u8; 32];
            r.read(&mut out);
            (shake_oid(0x0B), out)
        }
        "shake-256" => {
            use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};
            let mut h = Shake256::default();
            h.update(msg);
            let mut r = h.finalize_xof();
            let mut out = vec![0u8; 64];
            r.read(&mut out);
            (shake_oid(0x0C), out)
        }
        _ => (Vec::new(), Vec::new()),
    }
}

// Build effective_ctx exactly as src/ts/sign/ctx.ts: buildEffectiveCtx
// writes [u8 |dom|, dom bytes, u8 |user_ctx|, user_ctx bytes].
fn build_effective_ctx(ctx_domain: &str, user_ctx: &[u8]) -> Vec<u8> {
    let dom = ctx_domain.as_bytes();
    let mut out = Vec::with_capacity(2 + dom.len() + user_ctx.len());
    out.push(dom.len() as u8);
    out.extend_from_slice(dom);
    out.push(user_ctx.len() as u8);
    out.extend_from_slice(user_ctx);
    out
}

// FIPS 204 §5.4 / FIPS 205 §10.2 prehash M':
//   M' = 0x01 || |ctx| || ctx || OID(ph) || PH_M
fn build_prehash_m_prime(oid: &[u8], ph_m: &[u8], effective_ctx: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + effective_ctx.len() + oid.len() + ph_m.len());
    out.push(0x01);
    out.push(effective_ctx.len() as u8);
    out.extend_from_slice(effective_ctx);
    out.extend_from_slice(oid);
    out.extend_from_slice(ph_m);
    out
}

fn parse_envelope_blob<'a>(
    blob: &'a [u8],
    expected_format: u8,
    sig_size: usize,
) -> Option<(&'a [u8], &'a [u8], &'a [u8])> {
    // v3 wire: [format_byte u8][ctx_len u8][ctx][payload_len u32 BE][payload][sig]
    if blob.len() < 6 + sig_size { return None; }
    if blob[0] != expected_format { return None; }
    let ctx_len = blob[1] as usize;
    let payload_len_off = 2 + ctx_len;
    let payload_off = payload_len_off + 4;
    if blob.len() < payload_off { return None; }
    let payload_len =
        ((blob[payload_len_off] as usize)     << 24)
        | ((blob[payload_len_off + 1] as usize) << 16)
        | ((blob[payload_len_off + 2] as usize) <<  8)
        |  (blob[payload_len_off + 3] as usize);
    let sig_off = payload_off + payload_len;
    if sig_off + sig_size != blob.len() { return None; }
    let ctx = &blob[2..2 + ctx_len];
    let payload = &blob[payload_off..sig_off];
    let sig = &blob[sig_off..];
    Some((ctx, payload, sig))
}

// ────────────────────────────────────────────────────────────────────────────
// Per-hybrid verifier: split pk/sig, run both halves, AND the results.
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_vector(v: &SignHybridPqVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ hybrid-pq {} {} (format 0x{:02x}) ━━━",
        v.id, v.description, v.format_enum,
    ));

    let (sizes, ctx_domain) = match v.format_enum {
        0x30 => (SIZES_30, CTX_DOMAIN_30),
        0x31 => (SIZES_31, CTX_DOMAIN_31),
        0x32 => (SIZES_32, CTX_DOMAIN_32),
        other => {
            log.push(format!("  ✗ unknown formatEnum 0x{other:02x}"));
            return (false, log);
        }
    };

    // Size sanity-check the recorded fields.
    if v.pk.len() != sizes.pk() {
        log.push(format!("  ✗ pk.len()={} != expected {}", v.pk.len(), sizes.pk()));
        return (false, log);
    }
    if v.sk.len() != sizes.sk() {
        log.push(format!("  ✗ sk.len()={} != expected {}", v.sk.len(), sizes.sk()));
        return (false, log);
    }
    if v.blob.len() != 2 + v.ctx.len() + 4 + v.msg.len() + sizes.sig() {
        log.push(format!(
            "  ✗ blob.len()={} != expected {} (2 + ctx {} + 4 payload_len + msg {} + sig {})",
            v.blob.len(),
            2 + v.ctx.len() + 4 + v.msg.len() + sizes.sig(),
            v.ctx.len(), v.msg.len(), sizes.sig(),
        ));
        return (false, log);
    }

    let (ctx, payload, sig_combined) = match parse_envelope_blob(&v.blob, v.format_enum as u8, sizes.sig()) {
        Some(x) => x,
        None => {
            log.push("  ✗ envelope parse failed".to_string());
            return (false, log);
        }
    };
    if ctx != v.ctx.as_slice() {
        log.push("  ✗ wire ctx != recorded ctx".to_string());
        return (false, log);
    }
    if payload != v.msg.as_slice() {
        log.push("  ✗ wire payload != recorded msg".to_string());
        return (false, log);
    }

    // Split pk / sig at the documented mldsa/slhdsa boundary.
    let pk_mldsa  = &v.pk[..sizes.mldsa_pk];
    let pk_slh    = &v.pk[sizes.mldsa_pk..];
    let sig_mldsa = &sig_combined[..sizes.mldsa_sig];
    let sig_slh   = &sig_combined[sizes.mldsa_sig..];

    // Compute the shared SHAKE digest of the payload and the effective_ctx.
    let (oid, ph_m) = shake_digest(&v.prehash_algorithm, payload);
    if oid.is_empty() {
        log.push(format!("  ✗ unsupported prehashAlgorithm '{}'", v.prehash_algorithm));
        return (false, log);
    }
    let effective_ctx = build_effective_ctx(ctx_domain, ctx);
    let m_prime = build_prehash_m_prime(&oid, &ph_m, &effective_ctx);

    // ML-DSA half verify.
    let mldsa_ok = match v.format_enum {
        0x30 => verify_mldsa::<MlDsa44>(pk_mldsa, sig_mldsa, &m_prime),
        0x31 => verify_mldsa::<MlDsa65>(pk_mldsa, sig_mldsa, &m_prime),
        0x32 => verify_mldsa::<MlDsa87>(pk_mldsa, sig_mldsa, &m_prime),
        _ => false,
    };
    // SLH-DSA half verify.
    let slh_ok = match v.format_enum {
        0x30 => verify_slh::<Shake128f>(pk_slh, sig_slh, &m_prime),
        0x31 => verify_slh::<Shake192f>(pk_slh, sig_slh, &m_prime),
        0x32 => verify_slh::<Shake256f>(pk_slh, sig_slh, &m_prime),
        _ => false,
    };

    if mldsa_ok && slh_ok {
        log.push(format!(
            "  ✓ both halves verify (sig {} B: ml-dsa {} B + slh-dsa {} B)",
            sizes.sig(), sizes.mldsa_sig, sizes.slh_sig,
        ));
        (true, log)
    } else {
        log.push(format!(
            "  ✗ mldsa_ok={} slh_ok={}",
            mldsa_ok, slh_ok,
        ));
        (false, log)
    }
}

fn verify_mldsa<P: MlDsaParams>(pk_bytes: &[u8], sig_bytes: &[u8], m_prime: &[u8]) -> bool {
    let vk_arr = match ml_dsa::EncodedVerifyingKey::<P>::try_from(pk_bytes) {
        Ok(a)  => a,
        Err(_) => return false,
    };
    let vk: MlDsaVerifyingKey<P> = MlDsaVerifyingKey::decode(&vk_arr);
    let sig_arr = match ml_dsa::EncodedSignature::<P>::try_from(sig_bytes) {
        Ok(a)  => a,
        Err(_) => return false,
    };
    let sig: MlDsaSignature<P> = match MlDsaSignature::decode(&sig_arr) {
        Some(s) => s,
        None    => return false,
    };
    vk.verify_internal(m_prime, &sig)
}

fn verify_slh<P: slh_dsa::ParameterSet>(pk_bytes: &[u8], sig_bytes: &[u8], m_prime: &[u8]) -> bool {
    let vk = match SlhVerifyingKey::<P>::try_from(pk_bytes) {
        Ok(v)  => v,
        Err(_) => return false,
    };
    let sig = match SlhSignature::<P>::try_from(sig_bytes) {
        Ok(s)  => s,
        Err(_) => return false,
    };
    vk.slh_verify_internal(&[m_prime], &sig).is_ok()
}
