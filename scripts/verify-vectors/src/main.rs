// Independent verifier for leviathan-crypto's seal/sealstream test vectors.
//
// Reproduces the wire format from primitives that share zero code with
// leviathan-crypto:
//
//   XChaCha20 v3:
//     - HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates
//     - HChaCha20 hand-rolled here from RFC 8439 §2.3
//     - ChaCha20-Poly1305 from RustCrypto's `chacha20poly1305` crate
//
//   Serpent v3:
//     - HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates
//     - HMAC-SHA-256 from RustCrypto's `hmac` crate (per-chunk IV + tag)
//     - Serpent block cipher from RustCrypto's `serpent` crate (NIST natural byte order, matches v3 leviathan-crypto)
//     - CBC chaining + PKCS#7 padding hand-rolled here
//
// Different language, different libraries, different person who wrote the
// code, same bytes out. The verifier draws its primitives from several
// independent Rust implementation lineages. Most are RustCrypto crates:
// `aes`, `cbc`, `ctr`, `aes-gcm`, `aes-gcm-siv`, `chacha20poly1305`,
// `serpent`, `hkdf`, `hmac`, `sha2`, `sha3`, `polyval`, `ml-kem`, and
// `ml-dsa`. KMAC and cSHAKE (SP 800-185) use `tiny-keccak` instead,
// because RustCrypto's `kmac` crate is a 0.0.0 placeholder at this
// pinning and the `sha3` version we pin does not yet expose CShake.
// tiny-keccak's Keccak[1600] permutation is a separate lineage from
// RustCrypto's `sha3`, so the SP 800-185 corpus keeps the same
// independence story as every other target. All of these lineages share
// no source code, build system, or author with leviathan-crypto's WASM
// stack; if a verifier and the WASM agree on a record's bytes, the wire
// format is reproducible across independent crypto stacks.
//
// Usage:
//   cargo run --release                                       # all ciphers, all targets
//   cargo run --release -- --cipher xchacha                   # XChaCha20 v3 only (seal + sealstream)
//   cargo run --release -- --cipher serpent --target seal     # Serpent v3 single-chunk only
//   cargo run --release -- --cipher kmac                      # SP 800-185 KMAC and cSHAKE only
//   cargo run --release -- --cipher blake3                    # BLAKE3 official KAT corpus only
//
// Vector paths are computed relative to CARGO_MANIFEST_DIR.

use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

mod parse;
mod primitives;
mod byte_diff;
mod xchacha;
mod serpent;
mod aes_seal;
mod kmac;
mod aes_gcm_siv;
mod polyval;
mod aes;
mod aes_cbc;
mod aes_ctr;
mod aes_gcm;
mod mlkem;
mod mldsa;
mod slhdsa;
mod hybrid_pq;
mod blake3;

const GREEN: &str = "\x1b[32m";
const RED:   &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

fn colorize(use_color: bool, color: &str, text: &str) -> String {
    if use_color { format!("{color}{text}{RESET}") } else { text.to_string() }
}

fn print_log(log: &[String], use_color: bool) {
    for line in log {
        if line.contains("✓ ") {
            println!("{}", colorize(use_color, GREEN, line));
        } else if line.contains("✗ ") {
            println!("{}", colorize(use_color, RED, line));
        } else {
            println!("{line}");
        }
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn vector_path(filename: &str) -> PathBuf {
    manifest_dir().join("../../test/vectors").join(filename)
}

fn print_section(label: &str) {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("{label}");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

// ────────────────────────────────────────────────────────────────────────────
// ML-KEM (FIPS 203) dispatcher
// ────────────────────────────────────────────────────────────────────────────

fn run_mlkem(use_color: bool) -> bool {
    let kg_path = vector_path("kyber_keygen.ts");
    let ed_path = vector_path("kyber_encapdecap.ts");
    print_section("ML-KEM, FIPS 203 (keygen + encap + decap + key validity)");

    println!("Reading keygen vectors from   {}", kg_path.display());
    println!("Reading encapDecap vectors from {}\n", ed_path.display());

    let kg_src = match fs::read_to_string(&kg_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", kg_path.display(), e))); return false; }
    };
    let ed_src = match fs::read_to_string(&ed_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", ed_path.display(), e))); return false; }
    };

    let kg_512  = parse::parse_mlkem_keygen_array(&kg_src,  "ml_kem_512_keygen");
    let kg_768  = parse::parse_mlkem_keygen_array(&kg_src,  "ml_kem_768_keygen");
    let kg_1024 = parse::parse_mlkem_keygen_array(&kg_src,  "ml_kem_1024_keygen");

    let en_512  = parse::parse_mlkem_encap_array(&ed_src, "ml_kem_512_encap");
    let en_768  = parse::parse_mlkem_encap_array(&ed_src, "ml_kem_768_encap");
    let en_1024 = parse::parse_mlkem_encap_array(&ed_src, "ml_kem_1024_encap");

    let de_512  = parse::parse_mlkem_decap_array(&ed_src, "ml_kem_512_decap_val");
    let de_768  = parse::parse_mlkem_decap_array(&ed_src, "ml_kem_768_decap_val");
    let de_1024 = parse::parse_mlkem_decap_array(&ed_src, "ml_kem_1024_decap_val");

    let ekc_512  = parse::parse_mlkem_keycheck_array(&ed_src, "ml_kem_512_encap_key_check");
    let ekc_768  = parse::parse_mlkem_keycheck_array(&ed_src, "ml_kem_768_encap_key_check");
    let ekc_1024 = parse::parse_mlkem_keycheck_array(&ed_src, "ml_kem_1024_encap_key_check");

    let dkc_512  = parse::parse_mlkem_keycheck_array(&ed_src, "ml_kem_512_decap_key_check");
    let dkc_768  = parse::parse_mlkem_keycheck_array(&ed_src, "ml_kem_768_decap_key_check");
    let dkc_1024 = parse::parse_mlkem_keycheck_array(&ed_src, "ml_kem_1024_decap_key_check");

    println!(
        "Parsed: keygen 512/768/1024 = {}/{}/{}, encap = {}/{}/{}, decap = {}/{}/{}, ekc = {}/{}/{}, dkc = {}/{}/{}\n",
        kg_512.len(), kg_768.len(), kg_1024.len(),
        en_512.len(), en_768.len(), en_1024.len(),
        de_512.len(), de_768.len(), de_1024.len(),
        ekc_512.len(), ekc_768.len(), ekc_1024.len(),
        dkc_512.len(), dkc_768.len(), dkc_1024.len(),
    );

    // Empty-array guard: a successful parse always returns >0 vectors for
    // every published export. A zero count means an export-name mismatch
    // (or a corpus structure change ACVP didn't telegraph) and would
    // silently pass the run otherwise.
    let parsed_lens: [(&str, usize); 15] = [
        ("ml_kem_512_keygen",       kg_512.len()),
        ("ml_kem_768_keygen",       kg_768.len()),
        ("ml_kem_1024_keygen",      kg_1024.len()),
        ("ml_kem_512_encap",        en_512.len()),
        ("ml_kem_768_encap",        en_768.len()),
        ("ml_kem_1024_encap",       en_1024.len()),
        ("ml_kem_512_decap_val",    de_512.len()),
        ("ml_kem_768_decap_val",    de_768.len()),
        ("ml_kem_1024_decap_val",   de_1024.len()),
        ("ml_kem_512_encap_key_check",  ekc_512.len()),
        ("ml_kem_768_encap_key_check",  ekc_768.len()),
        ("ml_kem_1024_encap_key_check", ekc_1024.len()),
        ("ml_kem_512_decap_key_check",  dkc_512.len()),
        ("ml_kem_768_decap_key_check",  dkc_768.len()),
        ("ml_kem_1024_decap_key_check", dkc_1024.len()),
    ];
    if parsed_lens.iter().any(|(_, n)| *n == 0) {
        eprintln!("{}", colorize(use_color, RED, "✗ one or more ML-KEM arrays parsed as empty (export-name mismatch?)"));
        for (name, n) in &parsed_lens {
            if *n == 0 { eprintln!("    {}: 0", name); }
        }
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;

    let mut run = |label: &str, ok: bool, log: Vec<String>| {
        if !ok {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        } else {
            count_ok += 1;
            // Compact mode: one ✓ line per ok result, no per-test header.
            let _ = label; // label kept for future per-section summaries
        }
    };

    for v in &kg_512  { let (ok, log) = mlkem::verify_keygen_512(v);  run("keygen-512", ok, log); }
    for v in &kg_768  { let (ok, log) = mlkem::verify_keygen_768(v);  run("keygen-768", ok, log); }
    for v in &kg_1024 { let (ok, log) = mlkem::verify_keygen_1024(v); run("keygen-1024", ok, log); }
    for v in &en_512  { let (ok, log) = mlkem::verify_encap_512(v);   run("encap-512",  ok, log); }
    for v in &en_768  { let (ok, log) = mlkem::verify_encap_768(v);   run("encap-768",  ok, log); }
    for v in &en_1024 { let (ok, log) = mlkem::verify_encap_1024(v);  run("encap-1024", ok, log); }
    for v in &de_512  { let (ok, log) = mlkem::verify_decap_512(v);   run("decap-512",  ok, log); }
    for v in &de_768  { let (ok, log) = mlkem::verify_decap_768(v);   run("decap-768",  ok, log); }
    for v in &de_1024 { let (ok, log) = mlkem::verify_decap_1024(v);  run("decap-1024", ok, log); }
    for v in &ekc_512  { let (ok, log) = mlkem::verify_encap_keycheck_512(v);  run("ekc-512",  ok, log); }
    for v in &ekc_768  { let (ok, log) = mlkem::verify_encap_keycheck_768(v);  run("ekc-768",  ok, log); }
    for v in &ekc_1024 { let (ok, log) = mlkem::verify_encap_keycheck_1024(v); run("ekc-1024", ok, log); }
    for v in &dkc_512  { let (ok, log) = mlkem::verify_decap_keycheck_512(v);  run("dkc-512",  ok, log); }
    for v in &dkc_768  { let (ok, log) = mlkem::verify_decap_keycheck_768(v);  run("dkc-768",  ok, log); }
    for v in &dkc_1024 { let (ok, log) = mlkem::verify_decap_keycheck_1024(v); run("dkc-1024", ok, log); }

    println!(
        "ML-KEM: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// ML-DSA (FIPS 204) dispatcher, implementation in src/mldsa.rs
// ────────────────────────────────────────────────────────────────────────────

fn run_mldsa(use_color: bool) -> bool {
    let kg_path = vector_path("mldsa_keygen.ts");
    let sg_path = vector_path("mldsa_siggen.ts");
    let sv_path = vector_path("mldsa_sigver.ts");
    print_section("ML-DSA, FIPS 204 (keygen + sigGen + sigVer, incl. HashML-DSA)");

    println!("Reading keygen vectors from   {}", kg_path.display());
    println!("Reading sigGen vectors from   {}", sg_path.display());
    println!("Reading sigVer vectors from   {}\n", sv_path.display());

    let kg_src = match fs::read_to_string(&kg_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", kg_path.display(), e))); return false; }
    };
    let sg_src = match fs::read_to_string(&sg_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", sg_path.display(), e))); return false; }
    };
    let sv_src = match fs::read_to_string(&sv_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", sv_path.display(), e))); return false; }
    };

    let kg_44 = parse::parse_mldsa_keygen_array(&kg_src, "ml_dsa_44_keygen");
    let kg_65 = parse::parse_mldsa_keygen_array(&kg_src, "ml_dsa_65_keygen");
    let kg_87 = parse::parse_mldsa_keygen_array(&kg_src, "ml_dsa_87_keygen");

    let sg_44 = parse::parse_mldsa_siggen_array(&sg_src, "ml_dsa_44_siggen");
    let sg_65 = parse::parse_mldsa_siggen_array(&sg_src, "ml_dsa_65_siggen");
    let sg_87 = parse::parse_mldsa_siggen_array(&sg_src, "ml_dsa_87_siggen");

    let sv_44 = parse::parse_mldsa_sigver_array(&sv_src, "ml_dsa_44_sigver");
    let sv_65 = parse::parse_mldsa_sigver_array(&sv_src, "ml_dsa_65_sigver");
    let sv_87 = parse::parse_mldsa_sigver_array(&sv_src, "ml_dsa_87_sigver");

    println!(
        "Parsed: keygen 44/65/87 = {}/{}/{}, sigGen = {}/{}/{}, sigVer = {}/{}/{}\n",
        kg_44.len(), kg_65.len(), kg_87.len(),
        sg_44.len(), sg_65.len(), sg_87.len(),
        sv_44.len(), sv_65.len(), sv_87.len(),
    );

    // Empty-array guard: same rationale as run_mlkem. A zero count for
    // any published ACVP export means an export-name mismatch or corpus
    // shape change, not a successful run.
    let parsed_lens: [(&str, usize); 9] = [
        ("ml_dsa_44_keygen", kg_44.len()),
        ("ml_dsa_65_keygen", kg_65.len()),
        ("ml_dsa_87_keygen", kg_87.len()),
        ("ml_dsa_44_siggen", sg_44.len()),
        ("ml_dsa_65_siggen", sg_65.len()),
        ("ml_dsa_87_siggen", sg_87.len()),
        ("ml_dsa_44_sigver", sv_44.len()),
        ("ml_dsa_65_sigver", sv_65.len()),
        ("ml_dsa_87_sigver", sv_87.len()),
    ];
    if parsed_lens.iter().any(|(_, n)| *n == 0) {
        eprintln!("{}", colorize(use_color, RED, "✗ one or more ML-DSA arrays parsed as empty (export-name mismatch?)"));
        for (name, n) in &parsed_lens {
            if *n == 0 { eprintln!("    {}: 0", name); }
        }
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;

    let mut run = |ok: bool, log: Vec<String>| {
        if !ok {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        } else {
            count_ok += 1;
        }
    };

    for v in &kg_44 { let (ok, log) = mldsa::verify_keygen_44(v); run(ok, log); }
    for v in &kg_65 { let (ok, log) = mldsa::verify_keygen_65(v); run(ok, log); }
    for v in &kg_87 { let (ok, log) = mldsa::verify_keygen_87(v); run(ok, log); }

    for v in &sg_44 { let (ok, log) = mldsa::verify_siggen_44(v); run(ok, log); }
    for v in &sg_65 { let (ok, log) = mldsa::verify_siggen_65(v); run(ok, log); }
    for v in &sg_87 { let (ok, log) = mldsa::verify_siggen_87(v); run(ok, log); }

    for v in &sv_44 { let (ok, log) = mldsa::verify_sigver_44(v); run(ok, log); }
    for v in &sv_65 { let (ok, log) = mldsa::verify_sigver_65(v); run(ok, log); }
    for v in &sv_87 { let (ok, log) = mldsa::verify_sigver_87(v); run(ok, log); }

    println!(
        "ML-DSA: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// SLH-DSA (FIPS 205) dispatcher, implementation in src/slhdsa.rs.
// Phase 2 scope: SHAKE-fast variants only (128f / 192f / 256f).
// ────────────────────────────────────────────────────────────────────────────

fn run_slhdsa(use_color: bool) -> bool {
    let kg_path = vector_path("slhdsa_keygen.ts");
    let sg_path = vector_path("slhdsa_siggen.ts");
    let sv_path = vector_path("slhdsa_sigver.ts");
    print_section("SLH-DSA, FIPS 205 (keyGen + sigGen + sigVer, SHAKE-fast subset)");

    println!("Reading keygen vectors from   {}", kg_path.display());
    println!("Reading sigGen vectors from   {}", sg_path.display());
    println!("Reading sigVer vectors from   {}\n", sv_path.display());

    let kg_src = match fs::read_to_string(&kg_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", kg_path.display(), e))); return false; }
    };
    let sg_src = match fs::read_to_string(&sg_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", sg_path.display(), e))); return false; }
    };
    let sv_src = match fs::read_to_string(&sv_path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", sv_path.display(), e))); return false; }
    };

    let kg_128f = parse::parse_slhdsa_keygen_array(&kg_src, "slh_dsa_128f_keygen");
    let kg_192f = parse::parse_slhdsa_keygen_array(&kg_src, "slh_dsa_192f_keygen");
    let kg_256f = parse::parse_slhdsa_keygen_array(&kg_src, "slh_dsa_256f_keygen");

    let sg_128f = parse::parse_slhdsa_siggen_array(&sg_src, "slh_dsa_128f_siggen");
    let sg_192f = parse::parse_slhdsa_siggen_array(&sg_src, "slh_dsa_192f_siggen");
    let sg_256f = parse::parse_slhdsa_siggen_array(&sg_src, "slh_dsa_256f_siggen");

    let sv_128f = parse::parse_slhdsa_sigver_array(&sv_src, "slh_dsa_128f_sigver");
    let sv_192f = parse::parse_slhdsa_sigver_array(&sv_src, "slh_dsa_192f_sigver");
    let sv_256f = parse::parse_slhdsa_sigver_array(&sv_src, "slh_dsa_256f_sigver");

    println!(
        "Parsed: keygen 128f/192f/256f = {}/{}/{}, sigGen = {}/{}/{}, sigVer = {}/{}/{}\n",
        kg_128f.len(), kg_192f.len(), kg_256f.len(),
        sg_128f.len(), sg_192f.len(), sg_256f.len(),
        sv_128f.len(), sv_192f.len(), sv_256f.len(),
    );

    // Empty-array guard: a successful parse always returns >0 vectors for
    // every curated export. A zero count means an export-name mismatch
    // (or a corpus structure change) and would silently pass otherwise.
    let parsed_lens: [(&str, usize); 9] = [
        ("slh_dsa_128f_keygen", kg_128f.len()),
        ("slh_dsa_192f_keygen", kg_192f.len()),
        ("slh_dsa_256f_keygen", kg_256f.len()),
        ("slh_dsa_128f_siggen", sg_128f.len()),
        ("slh_dsa_192f_siggen", sg_192f.len()),
        ("slh_dsa_256f_siggen", sg_256f.len()),
        ("slh_dsa_128f_sigver", sv_128f.len()),
        ("slh_dsa_192f_sigver", sv_192f.len()),
        ("slh_dsa_256f_sigver", sv_256f.len()),
    ];
    if parsed_lens.iter().any(|(_, n)| *n == 0) {
        eprintln!("{}", colorize(use_color, RED, "✗ one or more SLH-DSA arrays parsed as empty (export-name mismatch?)"));
        for (name, n) in &parsed_lens {
            if *n == 0 { eprintln!("    {}: 0", name); }
        }
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;

    let mut run = |ok: bool, log: Vec<String>| {
        if !ok {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        } else {
            count_ok += 1;
        }
    };

    for v in &kg_128f { let (ok, log) = slhdsa::verify_keygen_128f(v); run(ok, log); }
    for v in &kg_192f { let (ok, log) = slhdsa::verify_keygen_192f(v); run(ok, log); }
    for v in &kg_256f { let (ok, log) = slhdsa::verify_keygen_256f(v); run(ok, log); }

    for v in &sg_128f { let (ok, log) = slhdsa::verify_siggen_128f(v); run(ok, log); }
    for v in &sg_192f { let (ok, log) = slhdsa::verify_siggen_192f(v); run(ok, log); }
    for v in &sg_256f { let (ok, log) = slhdsa::verify_siggen_256f(v); run(ok, log); }

    for v in &sv_128f { let (ok, log) = slhdsa::verify_sigver_128f(v); run(ok, log); }
    for v in &sv_192f { let (ok, log) = slhdsa::verify_sigver_192f(v); run(ok, log); }
    for v in &sv_256f { let (ok, log) = slhdsa::verify_sigver_256f(v); run(ok, log); }

    println!(
        "SLH-DSA: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// PQ-only hybrid dispatcher (sign_hybrid_pq.ts), implementation in
// src/hybrid_pq.rs. Three composite KAT vectors, one per format byte.
// ────────────────────────────────────────────────────────────────────────────

fn run_hybrid_pq(use_color: bool) -> bool {
    let path = vector_path("sign_hybrid_pq.ts");
    print_section("Hybrid PQ (sign_hybrid_pq.ts), composite ML-DSA || SLH-DSA verify");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };

    let vectors = parse::parse_sign_hybrid_pq_array(&src, "signHybridPqVectors");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = hybrid_pq::verify_vector(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "Hybrid PQ: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// BLAKE3 dispatcher, implementation in src/blake3.rs.
// 35 records × 3 modes (hash, keyed_hash, derive_key) = 105 KAT assertions
// against the official BLAKE3-team Rust crate as an independent-lineage
// oracle for blake3.ts.
// ────────────────────────────────────────────────────────────────────────────

fn run_blake3(use_color: bool, mode: blake3::BlakeXofMode) -> bool {
    let path = vector_path("blake3.ts");
    let header = match mode {
        blake3::BlakeXofMode::Prefix32 => "BLAKE3 (BLAKE3-team upstream KAT corpus, hash + keyed_hash + derive_key, 32-byte digest)",
        blake3::BlakeXofMode::FullXof  => "BLAKE3 (BLAKE3-team upstream KAT corpus, hash + keyed_hash + derive_key, 131-byte XOF)",
    };
    print_section(header);
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };

    let (key, context, vectors) = match blake3::load(&src) {
        Ok(t)  => t,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ {e}")));
            return false;
        }
    };

    println!("Parsed {} vectors", vectors.len());
    println!("  blake3Key           = {:?} ({} ASCII bytes)", String::from_utf8_lossy(&key), key.len());
    println!("  blake3ContextString = {:?} ({} ASCII bytes)", context, context.len());
    println!("  mode = {:?}\n", mode);

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = blake3::verify_vector(v, &key, &context, mode);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "BLAKE3: {} ok, {} failed (out of {} total, 3 modes × {} records)",
        count_ok, count_fail, count_ok + count_fail, vectors.len(),
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// KMAC and cSHAKE (SP 800-185) dispatcher, implementation in src/kmac.rs
// ────────────────────────────────────────────────────────────────────────────

fn run_kmac(use_color: bool) -> bool {
    let path = vector_path("kmac.ts");
    print_section("KMAC and cSHAKE, SP 800-185 (NIST CSRC samples + ACVP-Server byte-aligned subset)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e))); return false; }
    };

    let cs128_sa = parse::parse_cshake_sample_array(&src, "cshake128_appendix_a");
    let cs128_av = parse::parse_cshake_acvp_array  (&src, "cshake128_acvp");
    let cs256_sa = parse::parse_cshake_sample_array(&src, "cshake256_appendix_a");
    let cs256_av = parse::parse_cshake_acvp_array  (&src, "cshake256_acvp");
    let km128_sa = parse::parse_kmac_sample_array  (&src, "kmac128_appendix_a");
    let km128_av = parse::parse_kmac_acvp_array    (&src, "kmac128_acvp");
    let km256_sa = parse::parse_kmac_sample_array  (&src, "kmac256_appendix_a");
    let km256_av = parse::parse_kmac_acvp_array    (&src, "kmac256_acvp");
    let kx128_sa = parse::parse_kmac_sample_array  (&src, "kmacxof128_appendix_a");
    let kx128_av = parse::parse_kmac_acvp_array    (&src, "kmacxof128_acvp");
    let kx256_sa = parse::parse_kmac_sample_array  (&src, "kmacxof256_appendix_a");
    let kx256_av = parse::parse_kmac_acvp_array    (&src, "kmacxof256_acvp");

    println!(
        "Parsed: cshake128 sample/acvp = {}/{}, cshake256 = {}/{}, kmac128 = {}/{}, kmac256 = {}/{}, kmacxof128 = {}/{}, kmacxof256 = {}/{}\n",
        cs128_sa.len(), cs128_av.len(),
        cs256_sa.len(), cs256_av.len(),
        km128_sa.len(), km128_av.len(),
        km256_sa.len(), km256_av.len(),
        kx128_sa.len(), kx128_av.len(),
        kx256_sa.len(), kx256_av.len(),
    );

    // Empty-array guard: the four sample exports each carry 2 (cshake128/256)
    // or 3 (kmac128/256, kmacxof128/256) records and must never parse empty.
    // The two acvp exports kmac256_acvp and kmacxof128_acvp are deliberately
    // empty (Phase 1 byte-alignment filter dropped them all) and are excluded
    // from this guard. cshake128_acvp, cshake256_acvp, kmac128_acvp, and
    // kmacxof256_acvp all carry surviving records and must parse non-empty.
    let nonempty_lens: [(&str, usize); 10] = [
        ("cshake128_appendix_a",  cs128_sa.len()),
        ("cshake128_acvp",        cs128_av.len()),
        ("cshake256_appendix_a",  cs256_sa.len()),
        ("cshake256_acvp",        cs256_av.len()),
        ("kmac128_appendix_a",    km128_sa.len()),
        ("kmac128_acvp",          km128_av.len()),
        ("kmac256_appendix_a",    km256_sa.len()),
        ("kmacxof128_appendix_a", kx128_sa.len()),
        ("kmacxof256_appendix_a", kx256_sa.len()),
        ("kmacxof256_acvp",       kx256_av.len()),
    ];
    if nonempty_lens.iter().any(|(_, n)| *n == 0) {
        eprintln!("{}", colorize(use_color, RED, "✗ one or more non-empty KMAC arrays parsed as empty (export-name mismatch?)"));
        for (name, n) in &nonempty_lens {
            if *n == 0 { eprintln!("    {}: 0", name); }
        }
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;

    let mut run = |ok: bool, log: Vec<String>| {
        if !ok {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        } else {
            count_ok += 1;
        }
    };

    for v in &cs128_sa { let (ok, log) = kmac::verify_cshake_sample("cshake128_appendix_a",  128, v); run(ok, log); }
    for v in &cs128_av { let (ok, log) = kmac::verify_cshake_acvp  ("cshake128_acvp",        128, v); run(ok, log); }
    for v in &cs256_sa { let (ok, log) = kmac::verify_cshake_sample("cshake256_appendix_a",  256, v); run(ok, log); }
    for v in &cs256_av { let (ok, log) = kmac::verify_cshake_acvp  ("cshake256_acvp",        256, v); run(ok, log); }
    for v in &km128_sa { let (ok, log) = kmac::verify_kmac_sample  ("kmac128_appendix_a",    128, false, v); run(ok, log); }
    for v in &km128_av { let (ok, log) = kmac::verify_kmac_acvp    ("kmac128_acvp",          128, v); run(ok, log); }
    for v in &km256_sa { let (ok, log) = kmac::verify_kmac_sample  ("kmac256_appendix_a",    256, false, v); run(ok, log); }
    for v in &km256_av { let (ok, log) = kmac::verify_kmac_acvp    ("kmac256_acvp",          256, v); run(ok, log); }
    for v in &kx128_sa { let (ok, log) = kmac::verify_kmac_sample  ("kmacxof128_appendix_a", 128, true,  v); run(ok, log); }
    for v in &kx128_av { let (ok, log) = kmac::verify_kmac_acvp    ("kmacxof128_acvp",       128, v); run(ok, log); }
    for v in &kx256_sa { let (ok, log) = kmac::verify_kmac_sample  ("kmacxof256_appendix_a", 256, true,  v); run(ok, log); }
    for v in &kx256_av { let (ok, log) = kmac::verify_kmac_acvp    ("kmacxof256_acvp",       256, v); run(ok, log); }

    println!(
        "KMAC and cSHAKE: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// Per-cipher dispatchers
// ────────────────────────────────────────────────────────────────────────────

fn run_xchacha_seal(use_color: bool) -> bool {
    let path = vector_path("seal_xchacha_v3.ts");
    print_section("XChaCha20 v3, seal (single-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_seal_file(&src, "SealXChachaV3Vector");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = xchacha::verify_seal(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "XChaCha20 v3 seal: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_xchacha_sealstream(use_color: bool) -> bool {
    let path = vector_path("sealstream_xchacha_v3.ts");
    print_section("XChaCha20 v3, sealstream (multi-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_sealstream_file(&src, "SealStreamXChachaV3Vector");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = xchacha::verify_sealstream(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "XChaCha20 v3 sealstream: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_serpent_seal(use_color: bool) -> bool {
    let path = vector_path("seal_serpent_v3.ts");
    print_section("Serpent v3, seal (single-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_seal_file(&src, "SealSerpentV3Vector");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = serpent::verify_seal(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "Serpent v3 seal: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_serpent_sealstream(use_color: bool) -> bool {
    let path = vector_path("sealstream_serpent_v3.ts");
    print_section("Serpent v3, sealstream (multi-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_sealstream_file(&src, "SealStreamSerpentV3Vector");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = serpent::verify_sealstream(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "Serpent v3 sealstream: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_aes_seal(use_color: bool) -> bool {
    let path = vector_path("seal_aes_v3.ts");
    print_section("AES-GCM-SIV v3, seal (single-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_seal_file(&src, "SealAesV3Vector");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = aes_seal::verify_seal(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "AES-GCM-SIV v3 seal: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_aes_sealstream(use_color: bool) -> bool {
    let path = vector_path("sealstream_aes_v3.ts");
    print_section("AES-GCM-SIV v3, sealstream (multi-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_sealstream_file(&src, "SealStreamAesV3Vector");
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no vectors parsed"));
        return false;
    }

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = aes_seal::verify_sealstream(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "AES-GCM-SIV v3 sealstream: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_aes_gcm_siv(use_color: bool) -> bool {
    let path = vector_path("aes_gcm_siv.ts");
    print_section("AES-GCM-SIV, RFC 8452 Appendix C");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let (v128, v256, vwrap) = parse::parse_aes_gcm_siv_file(&src);
    println!("Parsed C.1 (AES-128) = {} vectors, C.2 (AES-256) = {} vectors, C.3 (counter-wrap) = {} vectors",
             v128.len(), v256.len(), vwrap.len());
    if v128.len() != 24 || v256.len() != 24 || vwrap.len() != 2 {
        eprintln!("{}", colorize(use_color, RED, "✗ unexpected vector counts"));
        return false;
    }
    println!();

    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in v128.iter().chain(v256.iter()).chain(vwrap.iter()) {
        let (ok, log) = aes_gcm_siv::verify_one(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "AES-GCM-SIV: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_polyval(use_color: bool) -> bool {
    let path = vector_path("polyval.ts");
    print_section("POLYVAL, RFC 8452 §7 + Appendix A");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let (field_ops, mul_x, hashes) = parse::parse_polyval_file(&src);

    let mut all_ok = true;

    println!("Algebraic / mulX vectors are unit-test fixtures; verifier carries them but does not exercise them.\n");

    if let Some(fo) = &field_ops {
        for line in polyval::carry_field_ops(fo) { println!("{line}"); }
    } else {
        eprintln!("{}", colorize(use_color, RED, "✗ polyvalFieldOps missing"));
        all_ok = false;
    }
    for v in &mul_x {
        for line in polyval::carry_mul_x(v) { println!("{line}"); }
    }
    println!();

    if hashes.is_empty() {
        eprintln!("{}", colorize(use_color, RED, "✗ no POLYVAL hash vectors parsed"));
        return false;
    }
    println!("Verifying {} POLYVAL hash trace(s) end-to-end against RustCrypto's polyval crate:\n", hashes.len());
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &hashes {
        let (ok, log) = polyval::verify_one_hash(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "POLYVAL: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// AES (FIPS 197 + SP 800-38A + McGrew-Viega) dispatchers
// ────────────────────────────────────────────────────────────────────────────

fn run_aes(use_color: bool) -> bool {
    let path = vector_path("aes.ts");
    print_section("AES, FIPS 197 (cipher example + key schedule + S-box + round trace)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e))); return false; }
    };
    let av = parse::parse_aes_file(&src);
    println!("Parsed: cipher_128={}, cipher_192={}, cipher_256={}, key_expansion={}, round_inter_128={}, round_inter_192={}, round_inter_256={}\n",
        av.cipher_128.len(), av.cipher_192.len(), av.cipher_256.len(),
        av.key_expansion.len(),
        av.round_inter_128.len(), av.round_inter_192.len(), av.round_inter_256.len(),
    );
    if av.cipher_128.len() != 1 || av.cipher_192.len() != 1 || av.cipher_256.len() != 1 {
        eprintln!("{}", colorize(use_color, RED, "✗ expected one cipher record per keysize"));
        return false;
    }
    let (ok, log) = aes::verify(&av);
    if !ok {
        print_log(&log, use_color);
        println!();
        println!("AES (FIPS 197): 0 ok, 1 failed (out of 1 total)");
    } else {
        println!("AES (FIPS 197): 1 ok, 0 failed (out of 1 total)");
    }
    ok
}

fn run_aes_cbc(use_color: bool) -> bool {
    let path = vector_path("aes_cbc.ts");
    print_section("AES-CBC, SP 800-38A §F.2");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e))); return false; }
    };
    let (enc, dec) = parse::parse_aes_cbc_file(&src);
    println!("Parsed encrypt = {} vectors, decrypt = {} vectors\n", enc.len(), dec.len());
    if enc.len() != 3 || dec.len() != 3 {
        eprintln!("{}", colorize(use_color, RED, "✗ expected 3 encrypt + 3 decrypt vectors"));
        return false;
    }
    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &enc {
        let (ok, log) = aes_cbc::verify_encrypt(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    for v in &dec {
        let (ok, log) = aes_cbc::verify_decrypt(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "AES-CBC: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_aes_ctr(use_color: bool) -> bool {
    let path = vector_path("aes_ctr.ts");
    print_section("AES-CTR, SP 800-38A §F.5 (Ctr128BE / 128-bit BE counter)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e))); return false; }
    };
    let (enc, dec) = parse::parse_aes_ctr_file(&src);
    println!("Parsed encrypt = {} vectors, decrypt = {} vectors\n", enc.len(), dec.len());
    if enc.len() != 3 || dec.len() != 3 {
        eprintln!("{}", colorize(use_color, RED, "✗ expected 3 encrypt + 3 decrypt vectors"));
        return false;
    }
    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &enc {
        let (ok, log) = aes_ctr::verify_encrypt(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    for v in &dec {
        let (ok, log) = aes_ctr::verify_decrypt(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "AES-CTR: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

fn run_aes_gcm(use_color: bool) -> bool {
    let path = vector_path("aes_gcm.ts");
    print_section("AES-GCM, McGrew-Viega Appendix B (18 vectors, mixed 96/64/480-bit IVs)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => { eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e))); return false; }
    };
    let vectors = parse::parse_aes_gcm_file(&src);
    println!("Parsed {} vectors\n", vectors.len());
    if vectors.len() != 18 {
        eprintln!("{}", colorize(use_color, RED, "✗ expected 18 vectors"));
        return false;
    }
    let mut all_ok = true;
    let mut count_ok: usize = 0;
    let mut count_fail: usize = 0;
    for v in &vectors {
        let (ok, log) = aes_gcm::verify_one(v);
        if ok {
            count_ok += 1;
        } else {
            print_log(&log, use_color);
            println!();
            count_fail += 1;
            all_ok = false;
        }
    }
    println!(
        "AES-GCM: {} ok, {} failed (out of {} total)",
        count_ok, count_fail, count_ok + count_fail,
    );
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// CLI parsing
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherSel {
    Xchacha, Serpent, AesSeal, AesGcmSiv, Polyval,
    Aes, AesCbc, AesCtr, AesGcm,
    Mlkem, Mldsa, Slhdsa, HybridPq, Kmac, Blake3,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetSel { Seal, Sealstream, Prefix32, FullXof, All }

fn parse_cipher(s: &str) -> Result<CipherSel, String> {
    match s {
        "xchacha"     => Ok(CipherSel::Xchacha),
        "serpent"     => Ok(CipherSel::Serpent),
        "aes-seal"    => Ok(CipherSel::AesSeal),
        "aes-gcm-siv" => Ok(CipherSel::AesGcmSiv),
        "polyval"     => Ok(CipherSel::Polyval),
        "aes"         => Ok(CipherSel::Aes),
        "aes-cbc"     => Ok(CipherSel::AesCbc),
        "aes-ctr"     => Ok(CipherSel::AesCtr),
        "aes-gcm"     => Ok(CipherSel::AesGcm),
        "mlkem"       => Ok(CipherSel::Mlkem),
        "mldsa"       => Ok(CipherSel::Mldsa),
        "slhdsa"      => Ok(CipherSel::Slhdsa),
        "hybrid-pq"   => Ok(CipherSel::HybridPq),
        "kmac"        => Ok(CipherSel::Kmac),
        "blake3"      => Ok(CipherSel::Blake3),
        "all"         => Ok(CipherSel::All),
        other         => Err(format!("unknown --cipher value: '{other}' (expected: xchacha, serpent, aes-seal, aes-gcm-siv, polyval, aes, aes-cbc, aes-ctr, aes-gcm, mlkem, mldsa, slhdsa, hybrid-pq, kmac, blake3, all)")),
    }
}

fn parse_target(s: &str) -> Result<TargetSel, String> {
    match s {
        "seal"       => Ok(TargetSel::Seal),
        "sealstream" => Ok(TargetSel::Sealstream),
        "prefix-32"  => Ok(TargetSel::Prefix32),
        "full-xof"   => Ok(TargetSel::FullXof),
        "all"        => Ok(TargetSel::All),
        other        => Err(format!("unknown --target value: '{other}' (expected: seal, sealstream, prefix-32, full-xof, all)")),
    }
}

fn print_usage() {
    eprintln!("Usage: verify-vectors [--cipher xchacha|serpent|aes-seal|aes-gcm-siv|polyval|aes|aes-cbc|aes-ctr|aes-gcm|mlkem|mldsa|slhdsa|hybrid-pq|kmac|blake3|all]");
    eprintln!("                       [--target seal|sealstream|prefix-32|full-xof|all]");
    eprintln!("Defaults: --cipher all --target all");
    eprintln!("Note: --target seal/sealstream apply only to --cipher xchacha / serpent / aes-seal.");
    eprintln!("      --target prefix-32 / full-xof apply only to --cipher blake3 (32-byte digest");
    eprintln!("      vs full 131-byte XOF assertion). For aes-gcm-siv, polyval, aes-cbc, aes-ctr,");
    eprintln!("      aes-gcm, mlkem, mldsa, slhdsa, hybrid-pq, kmac (no seal/sealstream/xof split),");
    eprintln!("      --target is silently ignored.");
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let use_color = std::io::stdout().is_terminal();

    let mut cipher = CipherSel::All;
    let mut target = TargetSel::All;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--cipher" => {
                if i + 1 >= args.len() { eprintln!("--cipher requires a value"); print_usage(); return ExitCode::from(2); }
                match parse_cipher(&args[i + 1]) {
                    Ok(c)  => cipher = c,
                    Err(e) => { eprintln!("{e}"); return ExitCode::from(2); }
                }
                i += 2;
            }
            "--target" => {
                if i + 1 >= args.len() { eprintln!("--target requires a value"); print_usage(); return ExitCode::from(2); }
                match parse_target(&args[i + 1]) {
                    Ok(t)  => target = t,
                    Err(e) => { eprintln!("{e}"); return ExitCode::from(2); }
                }
                i += 2;
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    let want_xchacha     = matches!(cipher, CipherSel::Xchacha   | CipherSel::All);
    let want_serpent     = matches!(cipher, CipherSel::Serpent   | CipherSel::All);
    let want_aes_seal    = matches!(cipher, CipherSel::AesSeal   | CipherSel::All);
    let want_aes_gcm_siv = matches!(cipher, CipherSel::AesGcmSiv | CipherSel::All);
    let want_polyval     = matches!(cipher, CipherSel::Polyval   | CipherSel::All);
    let want_aes         = matches!(cipher, CipherSel::Aes       | CipherSel::All);
    let want_aes_cbc     = matches!(cipher, CipherSel::AesCbc    | CipherSel::All);
    let want_aes_ctr     = matches!(cipher, CipherSel::AesCtr    | CipherSel::All);
    let want_aes_gcm     = matches!(cipher, CipherSel::AesGcm    | CipherSel::All);
    let want_mlkem       = matches!(cipher, CipherSel::Mlkem     | CipherSel::All);
    let want_mldsa       = matches!(cipher, CipherSel::Mldsa     | CipherSel::All);
    let want_slhdsa      = matches!(cipher, CipherSel::Slhdsa    | CipherSel::All);
    let want_hybrid_pq   = matches!(cipher, CipherSel::HybridPq  | CipherSel::All);
    let want_kmac        = matches!(cipher, CipherSel::Kmac      | CipherSel::All);
    let want_blake3      = matches!(cipher, CipherSel::Blake3    | CipherSel::All);
    let want_seal       = matches!(target, TargetSel::Seal       | TargetSel::All);
    let want_sealstream = matches!(target, TargetSel::Sealstream | TargetSel::All);

    let mut all_ok = true;

    if want_xchacha && want_seal       { if !run_xchacha_seal(use_color)        { all_ok = false; } }
    if want_xchacha && want_sealstream { if !run_xchacha_sealstream(use_color)  { all_ok = false; } }
    if want_serpent && want_seal       { if !run_serpent_seal(use_color)        { all_ok = false; } }
    if want_serpent && want_sealstream { if !run_serpent_sealstream(use_color)  { all_ok = false; } }
    if want_aes_seal && want_seal       { if !run_aes_seal(use_color)       { all_ok = false; } }
    if want_aes_seal && want_sealstream { if !run_aes_sealstream(use_color) { all_ok = false; } }
    // aes-gcm-siv, polyval, and the FIPS-197 / SP 800-38A / McGrew-Viega
    // ciphers are independent of --target.
    if want_aes_gcm_siv { if !run_aes_gcm_siv(use_color) { all_ok = false; } }
    if want_polyval     { if !run_polyval(use_color)     { all_ok = false; } }
    if want_aes         { if !run_aes(use_color)         { all_ok = false; } }
    if want_aes_cbc     { if !run_aes_cbc(use_color)     { all_ok = false; } }
    if want_aes_ctr     { if !run_aes_ctr(use_color)     { all_ok = false; } }
    if want_aes_gcm     { if !run_aes_gcm(use_color)     { all_ok = false; } }
    if want_mlkem       { if !run_mlkem(use_color)       { all_ok = false; } }
    if want_mldsa       { if !run_mldsa(use_color)       { all_ok = false; } }
    if want_slhdsa      { if !run_slhdsa(use_color)      { all_ok = false; } }
    if want_hybrid_pq   { if !run_hybrid_pq(use_color)   { all_ok = false; } }
    if want_kmac        { if !run_kmac(use_color)        { all_ok = false; } }
    if want_blake3 {
        // --target full-xof / prefix-32 are blake3-specific. Default
        // (--target all or omitted) runs the full 131-byte XOF
        // assertion; --target prefix-32 limits the comparison to the
        // first 32 default-length digest bytes. --target seal /
        // sealstream are silently ignored for blake3.
        let mode = match target {
            TargetSel::Prefix32 => blake3::BlakeXofMode::Prefix32,
            TargetSel::FullXof
            | TargetSel::All
            | TargetSel::Seal
            | TargetSel::Sealstream => blake3::BlakeXofMode::FullXof,
        };
        if !run_blake3(use_color, mode) { all_ok = false; }
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if all_ok {
        println!("{}", colorize(use_color, GREEN, "✓ all vectors verified"));
        ExitCode::SUCCESS
    } else {
        println!("{}", colorize(use_color, RED, "✗ verification FAILED"));
        ExitCode::FAILURE
    }
}
