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
// src/ts/ed25519/validate.ts
//
// Ed25519 caller-side input validation. Pure length / type checks; curve
// membership, canonical-encoding rejection, and the fault-injection
// pk-mismatch trap all live inside the WASM layer.
//
// TypeError for non-Uint8Array, RangeError for wrong-length. Matches
// the mldsa / mlkem validation conventions.

export function validateSeed(seed: Uint8Array): void {
	if (!(seed instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 seed must be a Uint8Array');
	if (seed.length !== 32)
		throw new RangeError(`leviathan-crypto: ed25519 seed must be 32 bytes (got ${seed.length})`);
}

export function validateSecretKey(sk: Uint8Array): void {
	// Ed25519 sk IS the seed per RFC 8032 §5.1.5.
	if (!(sk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 secret key must be a Uint8Array');
	if (sk.length !== 32)
		throw new RangeError(`leviathan-crypto: ed25519 secret key must be 32 bytes (got ${sk.length})`);
}

export function validatePublicKey(pk: Uint8Array): void {
	// Length-only at this layer; on-curve / canonical-y checks happen in
	// edPointDecompress (verify) or via the fault-injection pk-mismatch
	// trap (sign).
	if (!(pk instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 public key must be a Uint8Array');
	if (pk.length !== 32)
		throw new RangeError(`leviathan-crypto: ed25519 public key must be 32 bytes (got ${pk.length})`);
}

export function validateMessage(M: Uint8Array): void {
	if (!(M instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 message must be a Uint8Array');
	// RFC 8032 places no upper bound on the message length; the WASM
	// staging region imposes its own per-call ceiling enforced in the
	// caller (Ed25519.sign / verify).
}

export function validateSignature(sig: Uint8Array): void {
	if (!(sig instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 signature must be a Uint8Array');
	if (sig.length !== 64)
		throw new RangeError(`leviathan-crypto: ed25519 signature must be 64 bytes (got ${sig.length})`);
}

export function validateContext(ctx: Uint8Array): void {
	if (!(ctx instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 context must be a Uint8Array');
	// RFC 8032 §5.1 encodes |C| in a single octet, so 255 is the spec ceiling.
	if (ctx.length > 255)
		throw new RangeError(`leviathan-crypto: ed25519 context must be <= 255 bytes (got ${ctx.length})`);
}

export function validateDigest(digest: Uint8Array): void {
	if (!(digest instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ed25519 prehash digest must be a Uint8Array');
	if (digest.length !== 64)
		throw new RangeError(`leviathan-crypto: ed25519 prehash digest must be 64 bytes (got ${digest.length})`);
}
