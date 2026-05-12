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
// prehash suites. The two SHA-2 variants still throw — they will land when
// the sha2 module grows streaming wrappers (planned for Ed25519ph in
// Phase 4 and ECDSA-P256 prehash in Phase 5).
//
// SHAKE outputs are fixed per suite: SHAKE128Stream(32) for cat-1, and
// SHAKE256Stream(64) for cat-3 / cat-5; the lengths track FIPS 204 §5.4.1
// (HashML-DSA) and FIPS 205 §10.2.2 (HashSLH-DSA) per-algorithm digest sizes.

import {
	SHA3_256Stream, SHA3_512Stream,
	SHAKE128Stream, SHAKE256Stream,
} from '../sha3/index.js';
import type { PrehashAlgorithm } from './types.js';

export interface RunningHash {
	update(chunk: Uint8Array): void;
	finalize(): Uint8Array;
	dispose(): void;
}

export function createRunningHash(algo: PrehashAlgorithm): RunningHash {
	switch (algo) {
	case 'sha3-256':  return new SHA3_256Stream();
	case 'sha3-512':  return new SHA3_512Stream();
	case 'shake-128': return new SHAKE128Stream(32);
	case 'shake-256': return new SHAKE256Stream(64);
	case 'sha-256':
	case 'sha-512':
		throw new Error(
			`leviathan-crypto: prehash algorithm '${algo}' not implemented `
			+ 'yet; SHA-2 streaming lands in Phase 4 (Ed25519ph) / Phase 5 '
			+ '(ECDSA-P256 prehash)',
		);
	default: {
		const _exhaustive: never = algo;
		throw new Error(
			`leviathan-crypto: unknown prehash algorithm ${_exhaustive as string}`,
		);
	}
	}
}
