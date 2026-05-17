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
// src/ts/sign/hasher.ts
//
// Internal running-hash abstraction over the prehash hasher classes,
// keyed on PrehashAlgorithm. Used by SignStream and VerifyStream so the
// dispatch logic is not duplicated. Not exported from the sign barrel.
//
// Wires `sha3-256`, `sha3-512`, and the SHAKE pair used by the SLH-DSA
// prehash suites, plus `sha-512` (buffered shim over the one-shot
// SHA512 class) used by the Ed25519 prehash suite. The `sha-256`
// variant still throws; it will land when ECDSA-P256 prehash is
// implemented.
//
// SHAKE outputs are fixed per suite: SHAKE128Stream(32) for cat-1, and
// SHAKE256Stream(64) for cat-3 / cat-5; the lengths track FIPS 204 §5.4.1
// (HashML-DSA) and FIPS 205 §10.2.2 (HashSLH-DSA) per-algorithm digest sizes.

import {
	SHA3_256Stream, SHA3_512Stream,
	SHAKE128Stream, SHAKE256Stream,
} from '../sha3/index.js';
import { SHA512 } from '../sha2/index.js';
import type { PrehashAlgorithm } from './types.js';

export interface RunningHash {
	update(chunk: Uint8Array): void;
	finalize(): Uint8Array;
	dispose(): void;
}

/**
 * One-shot SHA-512 over `msg`. Used by suite factories whose
 * `sign(sk, msg, ctx)` / `verify(pk, msg, sig, ctx)` paths must compute
 * SHA-512 at the TS layer (the Ed25519 prehash suite is the current
 * caller; ECDSA-P256 prehash will join when added). Kept here so the
 * sha2 module access point is centralised next to `createRunningHash`.
 */
export function sha512OneShot(msg: Uint8Array): Uint8Array {
	const h = new SHA512();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

/**
 * Buffered shim that exposes a `RunningHash` over the one-shot SHA512
 * class. Chunks are copied (so caller-owned buffers can be wiped under
 * us) and concatenated at `finalize()`, then fed to the sha2 module.
 * The output is byte-identical to `sha512OneShot(concat(...chunks))`,
 * which is the contract SignStream depends on.
 */
function sha512Buffered(): RunningHash {
	let chunks: Uint8Array[] = [];
	let total = 0;
	return {
		update(chunk: Uint8Array): void {
			const copy = new Uint8Array(chunk.length);
			copy.set(chunk);
			chunks.push(copy);
			total += copy.length;
		},
		finalize(): Uint8Array {
			const buf = new Uint8Array(total);
			let off = 0;
			for (const c of chunks) {
				buf.set(c, off); off += c.length;
			}
			try {
				return sha512OneShot(buf);
			} finally {
				buf.fill(0);
				for (const c of chunks) c.fill(0);
				chunks = [];
				total = 0;
			}
		},
		dispose(): void {
			for (const c of chunks) c.fill(0);
			chunks = [];
			total = 0;
		},
	};
}

export function createRunningHash(algo: PrehashAlgorithm): RunningHash {
	switch (algo) {
	case 'sha3-256':  return new SHA3_256Stream();
	case 'sha3-512':  return new SHA3_512Stream();
	case 'shake-128': return new SHAKE128Stream(32);
	case 'shake-256': return new SHAKE256Stream(64);
	case 'sha-512':   return sha512Buffered();
	case 'sha-256':
		throw new Error(
			`leviathan-crypto: prehash algorithm '${algo}' not implemented `
			+ 'yet; SHA-2/256 streaming arrives with ECDSA-P256 prehash',
		);
	default: {
		const _exhaustive: never = algo;
		throw new Error(
			`leviathan-crypto: unknown prehash algorithm ${_exhaustive as string}`,
		);
	}
	}
}
