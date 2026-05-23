//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
//     ████████      ███▀▀     ████▀  █▀ █▀       Leviathan Crypto Library
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Repository & Mirror:
//       ▀██████   ▄▄██            ▀▀  ██▄    github.com/xero/leviathan-crypto
//         ▀█████▄   ▄██▄             ▄▀▄▀    unpkg.com/leviathan-crypto
//            ▀████▄   ▄██▄
//              ▐████   ▐███                  Author: xero (https://x-e.ro)
//       ▄▄██████████    ▐███         ▄▄      License: MIT
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// src/ts/ecdsa/validate.ts
//
// ECDSA-P256 caller-side input validation. Pure length / type checks;
// curve membership, canonical-encoding rejection, scalar-range checks
// ([1, n-1] for d, r, s), low-S enforcement, and the fault-injection
// pk-mismatch trap all live inside the WASM layer.
//
// TypeError for non-Uint8Array, RangeError for wrong-length. Matches
// the ed25519 / mldsa / mlkem validation conventions.

export function validateSeed(seed: Uint8Array): void {
	if (!(seed instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 seed must be a Uint8Array');
	if (seed.length !== 32)
		throw new RangeError(`leviathan-crypto: ecdsa-p256 seed must be 32 bytes (got ${seed.length})`);
}

export function validateSecretKey(sk: Uint8Array): void {
	// 32-byte big-endian scalar d per FIPS 186-5 §6.2.1, private-key
	// generation. The d ∈ [1, n-1] range check lives in WASM
	// (scalarIsZero rejection plus scalar arithmetic mod n).
	if (!(sk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 secret key must be a Uint8Array');
	if (sk.length !== 32)
		throw new RangeError(`leviathan-crypto: ecdsa-p256 secret key must be 32 bytes (got ${sk.length})`);
}

/**
 * Accepts both 33-byte compressed (SEC 1 §2.3.3, 0x02 / 0x03 || x) and
 * 65-byte uncompressed (SEC 1 §2.3.4, 0x04 || x || y) inputs. The WASM
 * ABI consumes only the 33-byte compressed form; the wrapper layer
 * normalises 65-byte inputs to compressed before staging into WASM
 * memory (see `normalizePublicKey` in `./index.ts`). Constant-time is
 * not required at pk import since pk is public material.
 *
 * Length-only at this layer; on-curve / canonical-x checks happen in
 * `pointDecompress` (verify) or via the fault-injection pk-mismatch
 * trap (sign).
 */
export function validatePublicKey(pk: Uint8Array): void {
	if (!(pk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 public key must be a Uint8Array');
	if (pk.length !== 33 && pk.length !== 65)
		throw new RangeError(
			'leviathan-crypto: ecdsa-p256 public key must be 33 bytes (compressed, SEC 1 §2.3.3) '
			+ `or 65 bytes (uncompressed, SEC 1 §2.3.4) (got ${pk.length})`,
		);
}

export function validateMessageHash(h: Uint8Array): void {
	// ECDSA-P256 takes a 32-byte SHA-256 digest; the suite layer drives
	// the actual hashing. FIPS 186-5 §6.4.1 requires hlen = qlen = 256
	// for P-256 + SHA-256 so the bits2int truncation is a no-op.
	if (!(h instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 message hash must be a Uint8Array');
	if (h.length !== 32)
		throw new RangeError(`leviathan-crypto: ecdsa-p256 message hash must be 32 bytes (got ${h.length})`);
}

export function validateSignature(sig: Uint8Array): void {
	// Raw r || s wire form, 64 bytes total. DER-wrapped signatures pass
	// through `ecdsaSignatureFromDer` first; that helper produces a
	// 64-byte output. The r, s ∈ [1, n-1] and low-S checks happen in
	// WASM during ecdsaVerify.
	if (!(sig instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 signature must be a Uint8Array');
	if (sig.length !== 64)
		throw new RangeError(`leviathan-crypto: ecdsa-p256 signature must be 64 bytes raw r||s (got ${sig.length})`);
}

export function validateEntropy(rnd: Uint8Array): void {
	// Per-call entropy Z, 32 bytes. All-zero selects the deterministic
	// RFC 6979 §3.2 K-derivation path; non-zero selects the hedged
	// path per draft-irtf-cfrg-det-sigs-with-noise-05.
	if (!(rnd instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 entropy must be a Uint8Array');
	if (rnd.length !== 32)
		throw new RangeError(`leviathan-crypto: ecdsa-p256 entropy must be 32 bytes (got ${rnd.length})`);
}
