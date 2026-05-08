// Independent verifier for ML-KEM (FIPS 203 final) vectors.
//
// Reads `kyber_keygen.ts` and `kyber_encapdecap.ts` (parsed by
// parse::parse_mlkem_*_array) and runs each record through RustCrypto's
// `ml-kem` crate. For each cipher operation the bytes are compared against
// the ACVP-published expected values: pk+sk for keygen, ciphertext+sharedKey
// for encap, sharedKey for decap, validity bool for keyCheck.
//
// Different crate, different lineage, same bytes out. RustCrypto's `ml-kem`
// is independent of leviathan-crypto's WASM stack; if both verifiers agree,
// the vector transcription is correct.
//
// FIPS 203 split:
//   §6.1 ML-KEM.KeyGen_internal   — `from_seed(d || z)` returns dk; the
//                                    matching ek lives at `dk.encapsulation_key()`.
//                                    ACVP supplies d and z (32 B each); the
//                                    crate's seed is d concat z (matches
//                                    `to_seed()`'s `d.concat(z)` layout).
//   §6.2 ML-KEM.Encaps_internal   — `EncapsulationKey::encapsulate_deterministic(m)`
//                                    reproduces ACVP's expected (c, k) given
//                                    the published 32-byte message m.
//   §6.3 ML-KEM.Decaps_internal   — `Decapsulate::decapsulate_slice(c)` reproduces
//                                    the expected k. For "modified ciphertext"
//                                    tcIds the FO transform's implicit-rejection
//                                    branch returns a pseudorandom secret; the
//                                    published k field is that pseudorandom value.
//   §7.2 encap-key validity       — `EncapsulationKey::new` natively performs
//                                    the §7.2 modulus round-trip check and
//                                    returns Err on failure.
//   §7.3 decap-key validity       — the deprecated `from_expanded` performs
//                                    both §7.2 (on the embedded ek_pke) and
//                                    §7.3 (H(ek) integrity tag); we use it
//                                    behind `#[allow(deprecated)]` since
//                                    that is the canonical validation path.
//
// Generics over P: Kem don't compile cleanly because the crate's KemParams
// trait is `pub(crate)` and the trait constraints leak through associated
// types. We therefore specialize per parameter set via a macro and dispatch
// from main.rs by paramset-aware export name. The body is identical; the
// macro keeps a single source of truth.

#![allow(deprecated)] // ExpandedKeyEncoding is the only validation path for §7.3

use ml_kem::{MlKem512, MlKem768, MlKem1024};

use crate::parse::{
    MlKemDecapVector, MlKemEncapVector, MlKemKeyCheckVector, MlKemKeyGenVector,
};

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
// Per-parameter-set verifier sets, expanded by macro
// ────────────────────────────────────────────────────────────────────────────

macro_rules! mlkem_verifier {
    ($paramset:ty, $keygen_fn:ident, $encap_fn:ident, $decap_fn:ident,
     $encap_keycheck_fn:ident, $decap_keycheck_fn:ident) => {

        pub fn $keygen_fn(v: &MlKemKeyGenVector) -> (bool, Vec<String>) {
            use ml_kem::ExpandedKeyEncoding;
            use ml_kem::kem::{KeyExport, KeyInit};
            type Dk = ml_kem::DecapsulationKey<$paramset>;

            let mut log = Vec::new();
            log.push(format!("━━━ tcId {} ━━━", v.tc_id));

            if v.d.len() != 32 || v.z.len() != 32 {
                log.push(format!("  ✗ d.len()={} z.len()={} (expected 32 each)", v.d.len(), v.z.len()));
                return (false, log);
            }
            let mut seed_bytes = [0u8; 64];
            seed_bytes[..32].copy_from_slice(&v.d);
            seed_bytes[32..].copy_from_slice(&v.z);

            let dk = match Dk::new_from_slice(&seed_bytes) {
                Ok(k)  => k,
                Err(e) => { log.push(format!("  ✗ from_seed failed: {e:?}")); return (false, log); }
            };

            let ek_bytes: Vec<u8> = dk.encapsulation_key().to_bytes().as_slice().to_vec();
            let dk_bytes: Vec<u8> = dk.to_expanded_bytes().as_slice().to_vec();

            log_byte_diff(&mut log, "ek", &ek_bytes, &v.ek);
            log_byte_diff(&mut log, "dk", &dk_bytes, &v.dk);

            if ek_bytes == v.ek && dk_bytes == v.dk {
                log.push(format!("  ✓ ek ({} B) and dk ({} B) match", v.ek.len(), v.dk.len()));
                (true, log)
            } else {
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $encap_fn(v: &MlKemEncapVector) -> (bool, Vec<String>) {
            use ml_kem::array::Array;
            use ml_kem::kem::TryKeyInit;
            type Ek = ml_kem::EncapsulationKey<$paramset>;

            let mut log = Vec::new();
            log.push(format!("━━━ tcId {} ━━━", v.tc_id));

            let ek = match Ek::new_from_slice(&v.ek) {
                Ok(k)  => k,
                Err(e) => { log.push(format!("  ✗ ek decode failed: {e:?}")); return (false, log); }
            };

            if v.m.len() != 32 {
                log.push(format!("  ✗ m.len()={} (expected 32)", v.m.len()));
                return (false, log);
            }
            let mut m_bytes = [0u8; 32];
            m_bytes.copy_from_slice(&v.m);
            let m_arr: Array<u8, ml_kem::array::sizes::U32> = Array::from(m_bytes);

            let (c, k) = ek.encapsulate_deterministic(&m_arr);
            let c_bytes: Vec<u8> = c.as_slice().to_vec();
            let k_bytes: Vec<u8> = k.as_slice().to_vec();

            log_byte_diff(&mut log, "c", &c_bytes, &v.c);
            log_byte_diff(&mut log, "k", &k_bytes, &v.k);

            if c_bytes == v.c && k_bytes == v.k {
                log.push(format!("  ✓ c ({} B) and k ({} B) match", v.c.len(), v.k.len()));
                (true, log)
            } else {
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $decap_fn(v: &MlKemDecapVector) -> (bool, Vec<String>) {
            use ml_kem::ExpandedKeyEncoding;
            use ml_kem::array::Array;
            use ml_kem::kem::Decapsulate;
            type Dk = ml_kem::DecapsulationKey<$paramset>;

            let mut log = Vec::new();
            log.push(format!("━━━ tcId {} ({}) ━━━", v.tc_id, v.reason));

            let dk_arr_res = <Array<u8, <Dk as ExpandedKeyEncoding>::EncodedSize> as TryFrom<&[u8]>>::try_from(v.dk.as_slice());
            let dk_arr = match dk_arr_res {
                Ok(a)  => a,
                Err(e) => { log.push(format!("  ✗ dk length error: {e:?}")); return (false, log); }
            };
            let dk = match Dk::from_expanded_bytes(&dk_arr) {
                Ok(k)  => k,
                Err(e) => { log.push(format!("  ✗ dk decode failed: {e:?}")); return (false, log); }
            };

            let k = match dk.decapsulate_slice(&v.c) {
                Ok(k)  => k,
                Err(e) => { log.push(format!("  ✗ ciphertext length error: {e:?}")); return (false, log); }
            };
            let k_bytes: Vec<u8> = k.as_slice().to_vec();

            log_byte_diff(&mut log, "k", &k_bytes, &v.k);

            if k_bytes == v.k {
                log.push(format!("  ✓ k ({} B) matches", v.k.len()));
                (true, log)
            } else {
                log.push("  ✗ FAIL".to_string());
                (false, log)
            }
        }

        pub fn $encap_keycheck_fn(v: &MlKemKeyCheckVector) -> (bool, Vec<String>) {
            use ml_kem::kem::TryKeyInit;
            type Ek = ml_kem::EncapsulationKey<$paramset>;

            let mut log = Vec::new();
            log.push(format!("━━━ tcId {} ({}) ━━━", v.tc_id, v.reason));

            let ok = Ek::new_from_slice(&v.ek).is_ok();
            if ok == v.test_passed {
                log.push(format!("  ✓ encap-key validity {} matches expected", ok));
                (true, log)
            } else {
                log.push(format!("  ✗ encap-key validity {} ≠ expected {}", ok, v.test_passed));
                (false, log)
            }
        }

        pub fn $decap_keycheck_fn(v: &MlKemKeyCheckVector) -> (bool, Vec<String>) {
            use ml_kem::ExpandedKeyEncoding;
            use ml_kem::array::Array;
            type Dk = ml_kem::DecapsulationKey<$paramset>;

            let mut log = Vec::new();
            log.push(format!("━━━ tcId {} ({}) ━━━", v.tc_id, v.reason));

            let arr_res = <Array<u8, <Dk as ExpandedKeyEncoding>::EncodedSize> as TryFrom<&[u8]>>::try_from(v.dk.as_slice());
            let ok = match arr_res {
                Ok(arr) => Dk::from_expanded_bytes(&arr).is_ok(),
                Err(_)  => false,
            };

            if ok == v.test_passed {
                log.push(format!("  ✓ decap-key validity {} matches expected", ok));
                (true, log)
            } else {
                log.push(format!("  ✗ decap-key validity {} ≠ expected {}", ok, v.test_passed));
                (false, log)
            }
        }
    };
}

mlkem_verifier!(MlKem512,
    verify_keygen_512, verify_encap_512, verify_decap_512,
    verify_encap_keycheck_512, verify_decap_keycheck_512);

mlkem_verifier!(MlKem768,
    verify_keygen_768, verify_encap_768, verify_decap_768,
    verify_encap_keycheck_768, verify_decap_keycheck_768);

mlkem_verifier!(MlKem1024,
    verify_keygen_1024, verify_encap_1024, verify_decap_1024,
    verify_encap_keycheck_1024, verify_decap_keycheck_1024);
