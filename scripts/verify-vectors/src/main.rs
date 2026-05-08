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
// code, same bytes out. RustCrypto is a separate implementation lineage
// from leviathan-crypto's WASM stack; if both verifiers agree, the wire
// format is reproducible across two independent crypto stacks.
//
// Usage:
//   cargo run --release                                       # all ciphers, all targets
//   cargo run --release -- --cipher xchacha                   # XChaCha20 v3 only (seal + sealstream)
//   cargo run --release -- --cipher serpent --target seal     # Serpent v3 single-chunk only
//
// Vector paths are computed relative to CARGO_MANIFEST_DIR.

use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

mod parse;
mod primitives;
mod xchacha;
mod serpent;
mod aes_gcm_siv;
mod polyval;
mod aes;
mod aes_cbc;
mod aes_ctr;
mod aes_gcm;
mod mlkem;
mod mldsa;

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
    print_section("ML-KEM — FIPS 203 (keygen + encap + decap + key validity)");

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
// ML-DSA (FIPS 204) dispatcher — implementation in src/mldsa.rs
// ────────────────────────────────────────────────────────────────────────────

fn run_mldsa(use_color: bool) -> bool {
    let kg_path = vector_path("mldsa_keygen.ts");
    let sg_path = vector_path("mldsa_siggen.ts");
    let sv_path = vector_path("mldsa_sigver.ts");
    print_section("ML-DSA — FIPS 204 (keygen + sigGen + sigVer, incl. HashML-DSA)");

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
// Per-cipher dispatchers
// ────────────────────────────────────────────────────────────────────────────

fn run_xchacha_seal(use_color: bool) -> bool {
    let path = vector_path("seal_xchacha_v3.ts");
    print_section("XChaCha20 v3 — seal (single-chunk)");
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
    for v in &vectors {
        let (ok, log) = xchacha::verify_seal(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_xchacha_sealstream(use_color: bool) -> bool {
    let path = vector_path("sealstream_xchacha_v3.ts");
    print_section("XChaCha20 v3 — sealstream (multi-chunk)");
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
    for v in &vectors {
        let (ok, log) = xchacha::verify_sealstream(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_serpent_seal(use_color: bool) -> bool {
    let path = vector_path("seal_serpent_v3.ts");
    print_section("Serpent v3 — seal (single-chunk)");
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
    for v in &vectors {
        let (ok, log) = serpent::verify_seal(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_serpent_sealstream(use_color: bool) -> bool {
    let path = vector_path("sealstream_serpent_v3.ts");
    print_section("Serpent v3 — sealstream (multi-chunk)");
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
    for v in &vectors {
        let (ok, log) = serpent::verify_sealstream(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_aes_gcm_siv(use_color: bool) -> bool {
    let path = vector_path("aes_gcm_siv.ts");
    print_section("AES-GCM-SIV — RFC 8452 Appendix C");
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
    for v in v128.iter().chain(v256.iter()).chain(vwrap.iter()) {
        let (ok, log) = aes_gcm_siv::verify_one(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_polyval(use_color: bool) -> bool {
    let path = vector_path("polyval.ts");
    print_section("POLYVAL — RFC 8452 §7 + Appendix A");
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
    for v in &hashes {
        let (ok, log) = polyval::verify_one_hash(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// AES (FIPS 197 + SP 800-38A + McGrew-Viega) dispatchers
// ────────────────────────────────────────────────────────────────────────────

fn run_aes(use_color: bool) -> bool {
    let path = vector_path("aes.ts");
    print_section("AES — FIPS 197 (cipher example + key schedule + S-box + round trace)");
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
    print_log(&log, use_color);
    println!();
    ok
}

fn run_aes_cbc(use_color: bool) -> bool {
    let path = vector_path("aes_cbc.ts");
    print_section("AES-CBC — SP 800-38A §F.2");
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
    for v in &enc {
        let (ok, log) = aes_cbc::verify_encrypt(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    for v in &dec {
        let (ok, log) = aes_cbc::verify_decrypt(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_aes_ctr(use_color: bool) -> bool {
    let path = vector_path("aes_ctr.ts");
    print_section("AES-CTR — SP 800-38A §F.5 (Ctr128BE / 128-bit BE counter)");
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
    for v in &enc {
        let (ok, log) = aes_ctr::verify_encrypt(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    for v in &dec {
        let (ok, log) = aes_ctr::verify_decrypt(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

fn run_aes_gcm(use_color: bool) -> bool {
    let path = vector_path("aes_gcm.ts");
    print_section("AES-GCM — McGrew-Viega Appendix B (18 vectors, mixed 96/64/480-bit IVs)");
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
    for v in &vectors {
        let (ok, log) = aes_gcm::verify_one(v);
        print_log(&log, use_color);
        println!();
        if !ok { all_ok = false; }
    }
    all_ok
}

// ────────────────────────────────────────────────────────────────────────────
// CLI parsing
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherSel {
    Xchacha, Serpent, AesGcmSiv, Polyval,
    Aes, AesCbc, AesCtr, AesGcm,
    Mlkem, Mldsa,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetSel { Seal, Sealstream, All }

fn parse_cipher(s: &str) -> Result<CipherSel, String> {
    match s {
        "xchacha"     => Ok(CipherSel::Xchacha),
        "serpent"     => Ok(CipherSel::Serpent),
        "aes-gcm-siv" => Ok(CipherSel::AesGcmSiv),
        "polyval"     => Ok(CipherSel::Polyval),
        "aes"         => Ok(CipherSel::Aes),
        "aes-cbc"     => Ok(CipherSel::AesCbc),
        "aes-ctr"     => Ok(CipherSel::AesCtr),
        "aes-gcm"     => Ok(CipherSel::AesGcm),
        "mlkem"       => Ok(CipherSel::Mlkem),
        "mldsa"       => Ok(CipherSel::Mldsa),
        "all"         => Ok(CipherSel::All),
        other         => Err(format!("unknown --cipher value: '{other}' (expected: xchacha, serpent, aes-gcm-siv, polyval, aes, aes-cbc, aes-ctr, aes-gcm, mlkem, mldsa, all)")),
    }
}

fn parse_target(s: &str) -> Result<TargetSel, String> {
    match s {
        "seal"       => Ok(TargetSel::Seal),
        "sealstream" => Ok(TargetSel::Sealstream),
        "all"        => Ok(TargetSel::All),
        other        => Err(format!("unknown --target value: '{other}' (expected: seal, sealstream, all)")),
    }
}

fn print_usage() {
    eprintln!("Usage: verify-vectors [--cipher xchacha|serpent|aes-gcm-siv|polyval|aes|aes-cbc|aes-ctr|aes-gcm|mlkem|mldsa|all]");
    eprintln!("                       [--target seal|sealstream|all]");
    eprintln!("Defaults: --cipher all --target all");
    eprintln!("Note: --target is silently ignored for --cipher aes-gcm-siv, polyval, aes,");
    eprintln!("      aes-cbc, aes-ctr, aes-gcm, mlkem, and mldsa (those corpora have no seal/sealstream split).");
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
    let want_aes_gcm_siv = matches!(cipher, CipherSel::AesGcmSiv | CipherSel::All);
    let want_polyval     = matches!(cipher, CipherSel::Polyval   | CipherSel::All);
    let want_aes         = matches!(cipher, CipherSel::Aes       | CipherSel::All);
    let want_aes_cbc     = matches!(cipher, CipherSel::AesCbc    | CipherSel::All);
    let want_aes_ctr     = matches!(cipher, CipherSel::AesCtr    | CipherSel::All);
    let want_aes_gcm     = matches!(cipher, CipherSel::AesGcm    | CipherSel::All);
    let want_mlkem       = matches!(cipher, CipherSel::Mlkem     | CipherSel::All);
    let want_mldsa       = matches!(cipher, CipherSel::Mldsa     | CipherSel::All);
    let want_seal       = matches!(target, TargetSel::Seal       | TargetSel::All);
    let want_sealstream = matches!(target, TargetSel::Sealstream | TargetSel::All);

    let mut all_ok = true;

    if want_xchacha && want_seal       { if !run_xchacha_seal(use_color)        { all_ok = false; } }
    if want_xchacha && want_sealstream { if !run_xchacha_sealstream(use_color)  { all_ok = false; } }
    if want_serpent && want_seal       { if !run_serpent_seal(use_color)        { all_ok = false; } }
    if want_serpent && want_sealstream { if !run_serpent_sealstream(use_color)  { all_ok = false; } }
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

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if all_ok {
        println!("{}", colorize(use_color, GREEN, "✓ all vectors verified"));
        ExitCode::SUCCESS
    } else {
        println!("{}", colorize(use_color, RED, "✗ verification FAILED"));
        ExitCode::FAILURE
    }
}
