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
 * BLAKE3 public surface smoke tests.
 *
 * Drives each of the six classes (one-shot + streaming × hash /
 * keyed_hash / derive_key), the BLAKE3OutputReader, the BLAKE3Hash
 * Fortuna HashFn const, and the streaming-lifecycle guards (update
 * after finalize, dispose idempotency). Sources expected values from
 * `test/vectors/blake3.ts` (the upstream BLAKE3 KAT corpus) per
 * AGENTS.md §Ground Rules #2.
 *
 * Coverage of the full KAT corpus past the empty-input record is
 * already exercised in `blake3-kat.test.ts` / `blake3-keyed-hash.test.ts`
 * / `blake3-derive-key.test.ts` at the WASM level; this file gates the
 * TS public surface and the API contract.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	BLAKE3, BLAKE3KeyedHash, BLAKE3DeriveKey,
	BLAKE3Stream, BLAKE3KeyedHashStream, BLAKE3DeriveKeyStream,
	BLAKE3OutputReader,
	BLAKE3Hash,
	blake3Init,
} from '../../../src/ts/blake3/index.js';
import { blake3Wasm } from '../../../src/ts/blake3/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import {
	blake3Vectors, blake3Key, blake3ContextString, expandBlake3Input,
} from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

beforeAll(async () => {
	_resetForTesting();
	await blake3Init(blake3Wasm);
});

describe('BLAKE3 public surface', () => {
	// GATE: BLAKE3 one-shot empty-input matches the upstream KAT record 0.
	it('BLAKE3.hash, empty-input KAT', () => {
		const h = new BLAKE3();
		try {
			const digest = h.hash(new Uint8Array(0));
			expect(toHex(digest)).toBe(blake3Vectors[0].hashHex.slice(0, 64));
		} finally {
			h.dispose();
		}
	});

	it('BLAKE3Stream chunked over arbitrary boundaries equals one-shot', () => {
		const input = expandBlake3Input(blake3Vectors[1].inputLen);  // 1 byte; covers the smallest nontrivial case
		// Compute the one-shot first, then dispose, before instantiating the
		// streaming class. Streaming holds module exclusivity so the two
		// instances cannot coexist.
		const h = new BLAKE3();
		let a: Uint8Array;
		try {
			a = h.hash(input);
		} finally {
			h.dispose();
		}
		const streamed = new BLAKE3Stream();
		streamed.update(input.subarray(0, 0));
		streamed.update(input);
		const b = streamed.finalize();
		expect(toHex(b)).toBe(toHex(a));
		expect(toHex(b)).toBe(blake3Vectors[1].hashHex.slice(0, 64));
	});

	it('BLAKE3KeyedHash empty-input matches keyed_hash KAT', () => {
		const h = new BLAKE3KeyedHash();
		try {
			const digest = h.hash(KEY_BYTES, new Uint8Array(0));
			expect(toHex(digest)).toBe(blake3Vectors[0].keyedHashHex.slice(0, 64));
		} finally {
			h.dispose();
		}
	});

	it('BLAKE3KeyedHashStream chunked equals one-shot keyed_hash', () => {
		const input = expandBlake3Input(blake3Vectors[1].inputLen);
		const h = new BLAKE3KeyedHash();
		let a: Uint8Array;
		try {
			a = h.hash(KEY_BYTES, input);
		} finally {
			h.dispose();
		}
		const streamed = new BLAKE3KeyedHashStream(KEY_BYTES);
		streamed.update(input.subarray(0, 0));
		streamed.update(input);
		const b = streamed.finalize();
		expect(toHex(b)).toBe(toHex(a));
		expect(toHex(b)).toBe(blake3Vectors[1].keyedHashHex.slice(0, 64));
	});

	it('BLAKE3DeriveKey empty-input matches derive_key KAT', () => {
		const dk = new BLAKE3DeriveKey();
		try {
			const out = dk.derive(blake3ContextString, new Uint8Array(0));
			expect(toHex(out)).toBe(blake3Vectors[0].deriveKeyHex.slice(0, 64));
		} finally {
			dk.dispose();
		}
	});

	it('BLAKE3DeriveKeyStream chunked equals one-shot derive_key', () => {
		const material = expandBlake3Input(blake3Vectors[1].inputLen);
		const dk = new BLAKE3DeriveKey();
		let a: Uint8Array;
		try {
			a = dk.derive(blake3ContextString, material);
		} finally {
			dk.dispose();
		}
		const streamed = new BLAKE3DeriveKeyStream(blake3ContextString);
		streamed.update(material.subarray(0, 0));
		streamed.update(material);
		const b = streamed.finalize();
		expect(toHex(b)).toBe(toHex(a));
		expect(toHex(b)).toBe(blake3Vectors[1].deriveKeyHex.slice(0, 64));
	});

	it('BLAKE3OutputReader read(32) on empty-input matches default-length KAT', () => {
		const stream = new BLAKE3Stream();
		// finalizeXof transfers module ownership to the reader.
		const reader: BLAKE3OutputReader = stream.finalizeXof();
		try {
			const bytes = reader.read(32);
			expect(toHex(bytes)).toBe(blake3Vectors[0].hashHex.slice(0, 64));
		} finally {
			reader.dispose();
		}
	});

	it('BLAKE3Hash HashFn const shape matches the Fortuna contract', () => {
		expect(BLAKE3Hash.outputSize).toBe(32);
		expect(BLAKE3Hash.wasmModules).toEqual(['blake3']);
		const digest = BLAKE3Hash.digest(new Uint8Array(0));
		expect(digest.length).toBe(32);
		expect(toHex(digest)).toBe(blake3Vectors[0].hashHex.slice(0, 64));
	});

	it('dispose is idempotent across all classes', () => {
		const a = new BLAKE3();           a.dispose(); a.dispose();
		const b = new BLAKE3KeyedHash();  b.dispose(); b.dispose();
		const c = new BLAKE3DeriveKey();  c.dispose(); c.dispose();
		const d = new BLAKE3Stream();     d.dispose(); d.dispose();
		const e = new BLAKE3KeyedHashStream(KEY_BYTES);                       e.dispose(); e.dispose();
		const f = new BLAKE3DeriveKeyStream(blake3ContextString);             f.dispose(); f.dispose();
		const g = new BLAKE3Stream();
		const reader = g.finalizeXof();   reader.dispose(); reader.dispose();
	});

	it('update after finalize throws (BLAKE3Stream)', () => {
		const s = new BLAKE3Stream();
		s.finalize();
		expect(() => s.update(new Uint8Array(1))).toThrow();
	});

	it('update after finalize throws (BLAKE3KeyedHashStream)', () => {
		const s = new BLAKE3KeyedHashStream(KEY_BYTES);
		s.finalize();
		expect(() => s.update(new Uint8Array(1))).toThrow();
	});

	it('update after finalize throws (BLAKE3DeriveKeyStream)', () => {
		const s = new BLAKE3DeriveKeyStream(blake3ContextString);
		s.finalize();
		expect(() => s.update(new Uint8Array(1))).toThrow();
	});

	it('update after finalizeXof throws (BLAKE3Stream)', () => {
		const s = new BLAKE3Stream();
		const r = s.finalizeXof();
		try {
			expect(() => s.update(new Uint8Array(1))).toThrow();
		} finally {
			r.dispose();
		}
	});

	it('read after dispose throws (BLAKE3OutputReader)', () => {
		const s = new BLAKE3Stream();
		const r = s.finalizeXof();
		r.dispose();
		expect(() => r.read(8)).toThrow();
	});

	it('validateKey: wrong key length throws RangeError', () => {
		const h = new BLAKE3KeyedHash();
		try {
			expect(() => h.hash(new Uint8Array(31), new Uint8Array(0))).toThrow(RangeError);
			expect(() => h.hash(new Uint8Array(33), new Uint8Array(0))).toThrow(RangeError);
		} finally {
			h.dispose();
		}
	});

	it('validateContext: empty derive_key context throws RangeError', () => {
		const dk = new BLAKE3DeriveKey();
		try {
			expect(() => dk.derive('',                  new Uint8Array(0))).toThrow(RangeError);
			expect(() => dk.derive(new Uint8Array(0),   new Uint8Array(0))).toThrow(RangeError);
		} finally {
			dk.dispose();
		}
	});
});
