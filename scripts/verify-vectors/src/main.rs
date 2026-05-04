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
//   Serpent v2:
//     - HKDF-SHA-256 from RustCrypto's `hkdf` + `sha2` crates
//     - HMAC-SHA-256 from RustCrypto's `hmac` crate (per-chunk IV + tag)
//     - Serpent block cipher from RustCrypto's `serpent` crate (NESSIE-correct)
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
//   cargo run --release -- --cipher serpent --target seal     # Serpent v2 single-chunk only
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
    let path = vector_path("seal_serpent_v2.ts");
    print_section("Serpent v2 — seal (single-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_seal_file(&src, "SealSerpentV2Vector");
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
    let path = vector_path("sealstream_serpent_v2.ts");
    print_section("Serpent v2 — sealstream (multi-chunk)");
    println!("Reading vectors from {}\n", path.display());

    let src = match fs::read_to_string(&path) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("{}", colorize(use_color, RED, &format!("✗ failed to read {}: {}", path.display(), e)));
            return false;
        }
    };
    let vectors = parse::parse_sealstream_file(&src, "SealStreamSerpentV2Vector");
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

// ────────────────────────────────────────────────────────────────────────────
// CLI parsing
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherSel { Xchacha, Serpent, All }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetSel { Seal, Sealstream, All }

fn parse_cipher(s: &str) -> Result<CipherSel, String> {
    match s {
        "xchacha" => Ok(CipherSel::Xchacha),
        "serpent" => Ok(CipherSel::Serpent),
        "all"     => Ok(CipherSel::All),
        other     => Err(format!("unknown --cipher value: '{other}' (expected: xchacha, serpent, all)")),
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
    eprintln!("Usage: verify-vectors [--cipher xchacha|serpent|all] [--target seal|sealstream|all]");
    eprintln!("Defaults: --cipher all --target all");
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

    let want_xchacha = matches!(cipher, CipherSel::Xchacha | CipherSel::All);
    let want_serpent = matches!(cipher, CipherSel::Serpent | CipherSel::All);
    let want_seal       = matches!(target, TargetSel::Seal       | TargetSel::All);
    let want_sealstream = matches!(target, TargetSel::Sealstream | TargetSel::All);

    let mut all_ok = true;

    if want_xchacha && want_seal       { if !run_xchacha_seal(use_color)        { all_ok = false; } }
    if want_xchacha && want_sealstream { if !run_xchacha_sealstream(use_color)  { all_ok = false; } }
    if want_serpent && want_seal       { if !run_serpent_seal(use_color)        { all_ok = false; } }
    if want_serpent && want_sealstream { if !run_serpent_sealstream(use_color)  { all_ok = false; } }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if all_ok {
        println!("{}", colorize(use_color, GREEN, "✓ all vectors verified"));
        ExitCode::SUCCESS
    } else {
        println!("{}", colorize(use_color, RED, "✗ verification FAILED"));
        ExitCode::FAILURE
    }
}
