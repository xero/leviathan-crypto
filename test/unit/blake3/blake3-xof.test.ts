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
/**
 * BLAKE3 XOF output reader tests, BLAKE3 §2.6 Extendable Output.
 *
 * The §2.6 XOF reads arbitrary-length output by incrementing the root
 * compress counter and re-firing the compress. v3 wires this through
 * `BLAKE3OutputReader`: the first read populates a WASM-side root-state
 * snapshot via the underlying hash entry, subsequent reads pump
 * `squeezeXofBlock` from the snapshot. The upstream KAT corpus carries
 * 131-byte XOF output per record (262 hex chars), specifically chosen
 * to cross the 64-byte root-block boundary on every case.
 *
 * Tests:
 *   1. Byte-at-a-time read of 131 bytes against `blake3Vectors[0].hashHex`
 *   2. 7-byte-chunk read of 131 bytes against the same vector
 *   3. 64-byte-chunk read of 131 bytes
 *   4. Read across the 64-byte block boundary (60, 8, 63 bytes)
 *   5. Full 131-byte single read across every blake3Vectors[i] for all
 *      three modes (hash / keyed_hash / derive_key)
 *   6. read after dispose throws
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	BLAKE3Stream, BLAKE3KeyedHashStream, BLAKE3DeriveKeyStream,
	blake3Init,
} from '../../../src/ts/blake3/index.js';
import { blake3Wasm } from '../../../src/ts/blake3/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import {
	blake3Vectors, blake3Key, blake3ContextString, expandBlake3Input,
} from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);
const XOF_LEN   = 131;

function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

beforeAll(async () => {
	_resetForTesting();
	await blake3Init(blake3Wasm);
});

// Each helper opens a fresh stream over the given input and returns the
// reader. Disposal is the caller's responsibility.
function readerForHash(input: Uint8Array) {
	const s = new BLAKE3Stream();
	if (input.length) s.update(input);
	return s.finalizeXof();
}

function readerForKeyed(input: Uint8Array) {
	const s = new BLAKE3KeyedHashStream(KEY_BYTES);
	if (input.length) s.update(input);
	return s.finalizeXof();
}

function readerForDerive(input: Uint8Array) {
	const s = new BLAKE3DeriveKeyStream(blake3ContextString);
	if (input.length) s.update(input);
	return s.finalizeXof();
}

describe('BLAKE3 XOF reader, §2.6', () => {
	// ─── byte-at-a-time / 7-byte / 64-byte chunkings over the empty-input
	//     XOF (vector record 0) — the simplest case exercising the
	//     squeeze loop across the 64-byte root-block boundary.
	it('read 1 byte at a time over 131-byte output, empty input', () => {
		const r   = readerForHash(new Uint8Array(0));
		const acc = new Uint8Array(XOF_LEN);
		try {
			for (let i = 0; i < XOF_LEN; i++) acc[i] = r.read(1)[0];
		} finally {
			r.dispose();
		}
		expect(toHex(acc)).toBe(blake3Vectors[0].hashHex);
	});

	it('read in 7-byte chunks over 131-byte output, empty input', () => {
		const r   = readerForHash(new Uint8Array(0));
		const acc = new Uint8Array(XOF_LEN);
		let off = 0;
		try {
			while (off < XOF_LEN) {
				const take  = Math.min(7, XOF_LEN - off);
				const block = r.read(take);
				acc.set(block, off);
				off += take;
			}
		} finally {
			r.dispose();
		}
		expect(toHex(acc)).toBe(blake3Vectors[0].hashHex);
	});

	it('read in 64-byte chunks over 131-byte output, empty input', () => {
		const r   = readerForHash(new Uint8Array(0));
		const acc = new Uint8Array(XOF_LEN);
		const a   = r.read(64);
		const b   = r.read(64);
		const c   = r.read(3);  // 131 - 128 = 3
		r.dispose();
		acc.set(a, 0); acc.set(b, 64); acc.set(c, 128);
		expect(toHex(acc)).toBe(blake3Vectors[0].hashHex);
	});

	it('read across the 64-byte boundary (60 + 8 + 63), empty input', () => {
		const r   = readerForHash(new Uint8Array(0));
		const a   = r.read(60);   // straddles boundary, stays in block 0
		const b   = r.read(8);    // crosses 64 → block 1
		const c   = r.read(63);   // crosses 128 → block 2
		r.dispose();
		const acc = new Uint8Array(XOF_LEN);
		acc.set(a, 0); acc.set(b, 60); acc.set(c, 68);
		expect(toHex(acc)).toBe(blake3Vectors[0].hashHex);
	});

	// ─── full 131-byte sweep across every vector × every mode.
	//     35 records × 3 modes = 105 cases.
	for (const v of blake3Vectors) {
		it(`hash: full 131-byte read, inputLen=${v.inputLen}`, () => {
			const input = expandBlake3Input(v.inputLen);
			const r     = readerForHash(input);
			const bytes = r.read(XOF_LEN);
			r.dispose();
			expect(toHex(bytes)).toBe(v.hashHex);
		});

		it(`keyed_hash: full 131-byte read, inputLen=${v.inputLen}`, () => {
			const input = expandBlake3Input(v.inputLen);
			const r     = readerForKeyed(input);
			const bytes = r.read(XOF_LEN);
			r.dispose();
			expect(toHex(bytes)).toBe(v.keyedHashHex);
		});

		it(`derive_key: full 131-byte read, inputLen=${v.inputLen}`, () => {
			const input = expandBlake3Input(v.inputLen);
			const r     = readerForDerive(input);
			const bytes = r.read(XOF_LEN);
			r.dispose();
			expect(toHex(bytes)).toBe(v.deriveKeyHex);
		});
	}

	it('read after dispose throws', () => {
		const r = readerForHash(new Uint8Array(0));
		r.dispose();
		expect(() => r.read(8)).toThrow();
	});
});
