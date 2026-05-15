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
// src/ts/blake3/validate.ts
//
// BLAKE3 caller-side input validation. Pure length / type checks, no
// crypto. BLAKE3 is a hash family, not a signature scheme; rejected
// inputs throw `RangeError` / `TypeError` (no `SigningError`).

/**
 * BLAKE3 §2.3 Modes: keyed_hash takes a 32-byte key. The key seeds the chunk
 * machine in place of the BLAKE3 IV and every compress carries the
 * KEYED_HASH flag. A key of any other length is a contract violation.
 */
export function validateKey(key: Uint8Array): void {
	if (!(key instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: blake3 key must be a Uint8Array');
	if (key.length !== 32)
		throw new RangeError(
			`leviathan-crypto: blake3 key must be 32 bytes (got ${key.length})`,
		);
}

/**
 * BLAKE3 §2.3 Modes: derive_key takes a context string and produces a
 * derived key. The context string is a domain separator and is
 * conventionally a UTF-8 hardcoded application constant. An empty context
 * defeats the domain separation §2.3 is designed to provide; reject it.
 *
 * Accepts either a JS string (UTF-8 encoded here) or a Uint8Array (passed
 * through). No upper cap on length; xero's substrate-code preference is
 * caller-trust without hard caps. A long context is a design smell but
 * not a spec violation.
 */
export function validateContext(context: string | Uint8Array): Uint8Array {
	let bytes: Uint8Array;
	if (typeof context === 'string') {
		bytes = new TextEncoder().encode(context);
	} else if (context instanceof Uint8Array) {
		bytes = context;
	} else {
		throw new TypeError(
			'leviathan-crypto: blake3 derive_key context must be a string or Uint8Array',
		);
	}
	if (bytes.length === 0)
		throw new RangeError(
			'leviathan-crypto: blake3 derive_key context must be non-empty '
			+ '(empty context defeats §2.3 domain separation)',
		);
	return bytes;
}

/**
 * BLAKE3 §2.6 XOF: default-length output is 32 bytes; the XOF can in principle
 * produce up to 2^64 - 1 bytes. The one-shot path (BLAKE3.hash /
 * BLAKE3KeyedHash.hash / BLAKE3DeriveKey.derive and the streaming
 * finalize(outLen) counterparts) writes outLen bytes through a single
 * WASM call sized by the OUTPUT_STAGING region, so the practical
 * upper bound is `OUTPUT_STAGING_SIZE` (1024 bytes); larger consumers
 * use `finalizeXof()` and stream from `BLAKE3OutputReader.read(n)`
 * which squeezes 64 bytes at a time off the WASM-side root snapshot.
 * This validator rejects nonsense (zero, negative, non-finite,
 * non-integer); the one-shot wrappers enforce the per-call ceiling.
 */
export function validateOutputLen(outLen: number): void {
	if (typeof outLen !== 'number' || !Number.isFinite(outLen) || !Number.isInteger(outLen))
		throw new RangeError(
			`leviathan-crypto: blake3 outLen must be a finite integer (got ${String(outLen)})`,
		);
	if (outLen < 1)
		throw new RangeError(
			`leviathan-crypto: blake3 outLen must be >= 1 (got ${outLen})`,
		);
}
