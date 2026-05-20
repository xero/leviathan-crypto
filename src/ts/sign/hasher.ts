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
// Internal running-hash abstraction keyed on PrehashAlgorithm, used by
// SignStream and VerifyStream. SHAKE output sizes track FIPS 204 §5.4.1
// (HashML-DSA) and FIPS 205 §10.2.2 (HashSLH-DSA).

import {
	SHA3_256Stream, SHA3_512Stream,
	SHAKE128Stream, SHAKE256Stream,
} from '../sha3/index.js';
import { SHA256, SHA512 } from '../sha2/index.js';
import type { PrehashAlgorithm } from './types.js';

export interface RunningHash {
	update(chunk: Uint8Array): void;
	finalize(): Uint8Array;
	dispose(): void;
}

export function sha256OneShot(msg: Uint8Array): Uint8Array {
	const h = new SHA256();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

export function sha512OneShot(msg: Uint8Array): Uint8Array {
	const h = new SHA512();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

function sha256Buffered(): RunningHash {
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
				return sha256OneShot(buf);
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
	case 'sha-256':   return sha256Buffered();
	default: {
		const _exhaustive: never = algo;
		throw new Error(
			`leviathan-crypto: unknown prehash algorithm ${_exhaustive as string}`,
		);
	}
	}
}
