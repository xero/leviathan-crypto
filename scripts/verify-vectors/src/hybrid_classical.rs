// Independent verifier for Composite ML-DSA classical+PQ hybrid vectors
// (sign_hybrid_classical.ts).
//
// Per draft-ietf-lamps-pq-composite-sigs-19 (Composite Module-Lattice-Based
// Digital Signature Algorithm) §3.3 (Composite-ML-DSA.Verify), each of the
// four suites in scope (id-MLDSA44-Ed25519-SHA512, id-MLDSA65-Ed25519-SHA512,
// id-MLDSA44-ECDSA-P256-SHA256, id-MLDSA65-ECDSA-P256-SHA512) accepts iff
// both the ML-DSA half and the traditional half verify under their own
// component standards over the same composite M' construction
// (composite-sigs §2.2 / §3.2 step 2):
//
//   composite_M' = Prefix || Label || len(user_ctx) || user_ctx || PH(M)
//
// where Prefix is the 32-byte ASCII string `CompositeAlgorithmSignatures2025`
// (composite-sigs §2.2), Label is the per-suite ASCII identifier from §6,
// PH is the per-suite Pre-Hash function from §6 (SHA-512 for the three
// SHA512-suffixed suites, SHA-256 for id-MLDSA44-ECDSA-P256-SHA256), and
// user_ctx is the caller-supplied application context bound to M.
//
// The ML-DSA sub-signer is invoked with ctx = Label, not with user_ctx and
// not empty (composite-sigs §3.3 step 4 plus the explanatory note). At the
// FIPS 204 (Module-Lattice-Based Digital Signature Standard) primitive
// level this means the ML-DSA half verifies under
//
//   mldsa_M' = 0x00 || |Label| || Label || composite_M'
//
// per FIPS 204 §5.2 (the pure external M' shape; the leading 0x00 marks
// external pure mode, not preHash).
//
// The traditional sub-signer signs composite_M' directly (composite-sigs
// §3.2 step 4 / §3.3 step 4: `Trad.Verify(tradPK, M', tradSig)`):
//
//   Ed25519:  RFC 8032 (Edwards-Curve Digital Signature Algorithm) §5.1.7
//             strict verify of composite_M' against the 32-byte raw R||S.
//   ECDSA:    FIPS 186-5 (Digital Signature Standard) §6.4.4 verify of
//             SHA-256(composite_M') against the DER-encoded
//             RFC 3279 §2.2.3 Ecdsa-Sig-Value (Note: SHA-256 even for
//             id-MLDSA65-ECDSA-P256-SHA512, per composite-sigs §6 which
//             pins the traditional algorithm to ecdsa-with-SHA256
//             regardless of the composite PH).
//
// Leviathan house style runs both sub-verifies and AND-s the booleans,
// strictly stronger than the draft's permitted early-fail on the first
// component (composite-sigs §3.3 explanatory note). This verifier
// matches that posture and additionally surfaces which half failed for
// debug visibility.
//
// Different crates (ml-dsa, ed25519-dalek, p256, ecdsa, sha2_v11), different
// lineage, same verdict.

use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};
use ml_dsa::{
    MlDsa44, MlDsa65, MlDsaParams,
    Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
};
use p256::ecdsa::{Signature as EcSignature, VerifyingKey as EcVerifyingKey};
use sha2_v11::{Digest, Sha256, Sha512};

use crate::parse::SignHybridClassicalVector;

// ────────────────────────────────────────────────────────────────────────────
// Per-suite constants (composite-sigs §2.2 Prefix; §6 Labels and per-suite
// Pre-Hash functions).
// ────────────────────────────────────────────────────────────────────────────

// composite-sigs §2.2: 32-byte ASCII Prefix common to every Composite ML-DSA
// suite. Spelled out as bytes here for transparency at audit time.
const COMPOSITE_PREFIX: [u8; 32] = *b"CompositeAlgorithmSignatures2025";

// composite-sigs §6 per-suite Labels (ASCII, no length prefix, no terminator).
const LABEL_MLDSA44_ED25519:     &[u8] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
const LABEL_MLDSA65_ED25519:     &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
const LABEL_MLDSA44_ECDSA_P256:  &[u8] = b"COMPSIG-MLDSA44-ECDSA-P256-SHA256";
const LABEL_MLDSA65_ECDSA_P256:  &[u8] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";

#[derive(Debug, Clone, Copy)]
enum TradHalf { Ed25519, EcdsaP256 }

#[derive(Debug, Clone, Copy)]
enum PreHash { Sha256, Sha512 }

#[derive(Debug, Clone, Copy)]
enum MlDsaVariant { V44, V65 }

#[derive(Debug, Clone, Copy)]
struct SuiteParams {
    mldsa:    MlDsaVariant,
    trad:     TradHalf,
    pre_hash: PreHash,
    label:    &'static [u8],
}

fn params_for(format_enum: u8) -> Option<SuiteParams> {
    match format_enum {
        0x20 => Some(SuiteParams { mldsa: MlDsaVariant::V44, trad: TradHalf::Ed25519,   pre_hash: PreHash::Sha512, label: LABEL_MLDSA44_ED25519 }),
        0x21 => Some(SuiteParams { mldsa: MlDsaVariant::V65, trad: TradHalf::Ed25519,   pre_hash: PreHash::Sha512, label: LABEL_MLDSA65_ED25519 }),
        0x22 => Some(SuiteParams { mldsa: MlDsaVariant::V44, trad: TradHalf::EcdsaP256, pre_hash: PreHash::Sha256, label: LABEL_MLDSA44_ECDSA_P256 }),
        0x23 => Some(SuiteParams { mldsa: MlDsaVariant::V65, trad: TradHalf::EcdsaP256, pre_hash: PreHash::Sha512, label: LABEL_MLDSA65_ECDSA_P256 }),
        _    => None,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// composite_M' construction (composite-sigs §2.2 / §3.2 step 2)
// ────────────────────────────────────────────────────────────────────────────

fn ph_digest(ph: PreHash, msg: &[u8]) -> Vec<u8> {
    match ph {
        // composite-sigs §6 pins SHA-256 as the Pre-Hash function only for
        // id-MLDSA44-ECDSA-P256-SHA256; every other suite in scope uses SHA-512.
        PreHash::Sha256 => Sha256::digest(msg).to_vec(),
        PreHash::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

fn build_composite_m_prime(label: &[u8], user_ctx: &[u8], ph_m: &[u8]) -> Option<Vec<u8>> {
    // composite-sigs §3.2 step 1: user_ctx is bounded at 255 bytes.
    if user_ctx.len() > 255 { return None; }
    let mut out = Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + user_ctx.len() + ph_m.len());
    out.extend_from_slice(&COMPOSITE_PREFIX);
    out.extend_from_slice(label);
    out.push(user_ctx.len() as u8);
    out.extend_from_slice(user_ctx);
    out.extend_from_slice(ph_m);
    Some(out)
}

// FIPS 204 §5.2 pure external M': 0x00 || |ctx| || ctx || M. ctx for the
// composite case is the Label bytes (composite-sigs §3.2 step 4).
fn build_mldsa_pure_m_prime(ctx: &[u8], m: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + ctx.len() + m.len());
    out.push(0x00);
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(m);
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Envelope parsing (v3 attached wire format, leviathan-specific)
// ────────────────────────────────────────────────────────────────────────────

fn parse_envelope_blob<'a>(
    blob:            &'a [u8],
    expected_format: u8,
    mldsa_sig_bytes: usize,
) -> Option<(&'a [u8], &'a [u8], &'a [u8])> {
    // v3 wire: [format_byte u8][ctx_len u8][ctx][payload_len u32 BE][payload][sig].
    // The sig tail must be at least the ML-DSA-fixed prefix length; the
    // traditional half is variable (ECDSA DER) or exact (Ed25519 64-byte),
    // and the composite split is performed by the caller.
    if blob.len() < 6 + mldsa_sig_bytes { return None; }
    if blob[0] != expected_format       { return None; }
    let ctx_len = blob[1] as usize;
    let payload_len_off = 2 + ctx_len;
    let payload_off = payload_len_off + 4;
    if blob.len() < payload_off { return None; }
    let payload_len =
          ((blob[payload_len_off    ] as usize) << 24)
        | ((blob[payload_len_off + 1] as usize) << 16)
        | ((blob[payload_len_off + 2] as usize) <<  8)
        |  (blob[payload_len_off + 3] as usize);
    let sig_off = payload_off + payload_len;
    if sig_off > blob.len() { return None; }
    if blob.len() - sig_off < mldsa_sig_bytes { return None; }
    Some((&blob[2..2 + ctx_len], &blob[payload_off..sig_off], &blob[sig_off..]))
}

// ────────────────────────────────────────────────────────────────────────────
// Per-vector verifier
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_vector(v: &SignHybridClassicalVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ hybrid-classical {} (tcId {} / format 0x{:02x}) ━━━",
        v.id, v.tc_id, v.format_enum,
    ));

    let Some(params) = params_for(v.format_enum as u8) else {
        log.push(format!("  ✗ unknown formatEnum 0x{:02x}", v.format_enum));
        return (false, log);
    };

    let mldsa_pk_bytes  = v.mldsa_pk_bytes  as usize;
    let mldsa_sig_bytes = v.mldsa_sig_bytes as usize;
    let trad_pk_bytes   = v.trad_pk_bytes   as usize;

    // Composite pk = mldsaPk || tradPk (composite-sigs §4.1 SerializePublicKey).
    if v.pk.len() != mldsa_pk_bytes + trad_pk_bytes {
        log.push(format!(
            "  ✗ pk.len()={} != {} (mldsa {} + trad {})",
            v.pk.len(), mldsa_pk_bytes + trad_pk_bytes, mldsa_pk_bytes, trad_pk_bytes,
        ));
        return (false, log);
    }
    let pk_mldsa = &v.pk[..mldsa_pk_bytes];
    let pk_trad  = &v.pk[mldsa_pk_bytes..];

    // Envelope parse: sig tail comes off the back, ctx and payload match
    // the recorded fields.
    let (env_ctx, env_msg, env_sig) = match parse_envelope_blob(&v.blob, v.format_enum as u8, mldsa_sig_bytes) {
        Some(t) => t,
        None    => { log.push("  ✗ envelope parse failed".to_string()); return (false, log); }
    };
    if env_ctx != v.ctx.as_slice() {
        log.push("  ✗ envelope ctx != recorded ctx".to_string());
        return (false, log);
    }
    if env_msg != v.msg.as_slice() {
        log.push("  ✗ envelope payload != recorded msg".to_string());
        return (false, log);
    }
    if env_sig != v.sig.as_slice() {
        log.push("  ✗ envelope sig tail != recorded sig".to_string());
        return (false, log);
    }

    // Composite sig = mldsaSig || tradSig (composite-sigs §4.3
    // SerializeSignatureValue). ML-DSA half is catalog-fixed; trad half
    // is the remainder, length-checked downstream.
    if v.sig.len() < mldsa_sig_bytes {
        log.push(format!(
            "  ✗ sig.len()={} < mldsa_sig_bytes={}",
            v.sig.len(), mldsa_sig_bytes,
        ));
        return (false, log);
    }
    let sig_mldsa = &v.sig[..mldsa_sig_bytes];
    let sig_trad  = &v.sig[mldsa_sig_bytes..];

    if !v.trad_sig_variable && sig_trad.len() != 64 {
        // RFC 8032 §5.1.6 Ed25519 sig is fixed 64-byte R||S.
        log.push(format!(
            "  ✗ Ed25519 trad sig length {} != 64",
            sig_trad.len(),
        ));
        return (false, log);
    }

    // Build composite M' (composite-sigs §2.2 / §3.2 step 2).
    let ph_m = ph_digest(params.pre_hash, &v.msg);
    let Some(composite_m_prime) = build_composite_m_prime(params.label, &v.ctx, &ph_m) else {
        log.push(format!("  ✗ user_ctx length {} > 255", v.ctx.len()));
        return (false, log);
    };

    // ML-DSA half: pure verify with ctx = Label, M = composite M' (composite-sigs
    // §3.3 step 4). At the FIPS 204 level this means M_internal = 0x00 || |Label|
    // || Label || composite_M'.
    let mldsa_m_prime = build_mldsa_pure_m_prime(params.label, &composite_m_prime);
    let mldsa_ok = match params.mldsa {
        MlDsaVariant::V44 => verify_mldsa::<MlDsa44>(pk_mldsa, sig_mldsa, &mldsa_m_prime),
        MlDsaVariant::V65 => verify_mldsa::<MlDsa65>(pk_mldsa, sig_mldsa, &mldsa_m_prime),
    };

    // Traditional half: signs composite M' directly. RFC 8032 §5.1.7 strict
    // verify for Ed25519; FIPS 186-5 §6.4.4 verify of SHA-256(M') against
    // the RFC 3279 §2.2.3 DER signature for ECDSA-P256.
    let trad_ok = match params.trad {
        TradHalf::Ed25519   => verify_ed25519(pk_trad, sig_trad, &composite_m_prime),
        TradHalf::EcdsaP256 => verify_ecdsa_p256(pk_trad, sig_trad, &composite_m_prime),
    };

    if mldsa_ok && trad_ok {
        log.push(format!(
            "  ✓ both halves verify (sig {} B: ml-dsa {} B + trad {} B)",
            v.sig.len(), mldsa_sig_bytes, sig_trad.len(),
        ));
        (true, log)
    } else {
        log.push(format!(
            "  ✗ mldsa_ok={} trad_ok={}",
            mldsa_ok, trad_ok,
        ));
        (false, log)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Per-component verifiers
// ────────────────────────────────────────────────────────────────────────────

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

fn verify_ed25519(pk_bytes: &[u8], sig_bytes: &[u8], m: &[u8]) -> bool {
    // Composite-sigs §4 / RFC 8032 §5.1.5: Ed25519 raw 32-byte pk and 64-byte sig.
    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a)  => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a)  => a,
        Err(_) => return false,
    };
    let vk = match EdVerifyingKey::from_bytes(&pk_arr) {
        Ok(v)  => v,
        Err(_) => return false,
    };
    let sig = EdSignature::from_bytes(&sig_arr);
    // verify_strict applies RFC 8032 §5.1.7 cofactored verification, matching
    // FIPS 186-5 §7.6.4. The non-strict path would diverge on mixed-order
    // public keys but the suite uses strict on its side too.
    vk.verify_strict(m, &sig).is_ok()
}

fn verify_ecdsa_p256(pk_bytes: &[u8], sig_bytes: &[u8], m: &[u8]) -> bool {
    // Composite-sigs §4: 65-byte uncompressed SEC1 §2.3.3 pk (0x04 || X || Y).
    let vk = match EcVerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(v)  => v,
        Err(_) => return false,
    };
    // Composite-sigs §6 pins the traditional sub-signer to ecdsa-with-SHA256
    // for both ECDSA suites; the composite PH (which may be SHA-512 for the
    // 0x23 suite) does NOT change the ECDSA-internal hash.
    let digest = Sha256::digest(m);
    // RFC 3279 §2.2.3 Ecdsa-Sig-Value DER. Strict parse: rejects non-canonical
    // length prefixes, leading zeros, and trailing junk per the ecdsa crate's
    // DER reader.
    let sig = match EcSignature::from_der(sig_bytes) {
        Ok(s)  => s,
        Err(_) => return false,
    };
    // p256's verify_prehash routes through hazmat::verify_prehashed; the
    // NistP256 NORMALIZE_S=false setting means low-S is not enforced here,
    // matching FIPS 186-5 §6.4.4 (the leviathan suite layer enforces low-S
    // on its side; this oracle just oracles the FIPS verdict).
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(digest.as_slice(), &sig).is_ok()
}
