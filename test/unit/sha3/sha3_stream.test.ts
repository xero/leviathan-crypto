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
// test/unit/sha3/sha3_stream.test.ts
//
// Incremental SHA3-256 / SHA3-512 streaming classes. The streaming path must
// produce digests byte-identical to the one-shot `hash()` for the same input,
// regardless of chunking.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	init, SHA3_256, SHA3_512, SHA3_256Stream, SHA3_512Stream,
} from '../../../src/ts/index.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { sha3_256Vectors, sha3_512Vectors } from '../../vectors/sha3.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++)
		bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

beforeAll(async () => {
	await init({ sha3: sha3Wasm });
});

// GATE: SHA3-256 streaming over empty input matches FIPS 202 §A.1.
describe('Gate, SHA3_256Stream empty input', () => {
	test('SHA3_256Stream over "" matches FIPS 202', () => {
		const h = new SHA3_256Stream();
		const digest = h.finalize();
		expect(toHex(digest)).toBe(sha3_256Vectors[0].expected);
	});
});

// GATE: SHA3-512 streaming over empty input matches FIPS 202 §A.4.
describe('Gate, SHA3_512Stream empty input', () => {
	test('SHA3_512Stream over "" matches FIPS 202', () => {
		const h = new SHA3_512Stream();
		const digest = h.finalize();
		expect(toHex(digest)).toBe(sha3_512Vectors[0].expected);
	});
});

describe('SHA3_256Stream equivalence with one-shot SHA3_256', () => {
	test('"abc" via single update matches one-shot', () => {
		const msg = fromHex('616263');
		const h = new SHA3_256Stream();
		const streamed = h.update(msg).finalize();
		expect(toHex(streamed)).toBe(sha3_256Vectors[1].expected);
	});

	test('1-byte chunks over a long message match one-shot', () => {
		const msg = new Uint8Array(500);
		for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;

		const oneShot = (() => {
			const h = new SHA3_256();
			try {
				return h.hash(msg);
			} finally {
				h.dispose();
			}
		})();

		const h = new SHA3_256Stream();
		for (let i = 0; i < msg.length; i++) h.update(msg.subarray(i, i + 1));
		const streamed = h.finalize();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('mixed chunk sizes across rate boundaries match one-shot', () => {
		const msg = new Uint8Array(400);
		for (let i = 0; i < msg.length; i++) msg[i] = (i * 31) & 0xff;

		const oneShot = (() => {
			const h = new SHA3_256();
			try {
				return h.hash(msg);
			} finally {
				h.dispose();
			}
		})();

		// chunk sizes that exercise non-block-aligned and boundary cases
		const sizes = [1, 135, 1, 136, 1, 126]; // sums to 400
		const h = new SHA3_256Stream();
		let off = 0;
		for (const n of sizes) {
			h.update(msg.subarray(off, off + n));
			off += n;
		}
		const streamed = h.finalize();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('exclusivity: a second SHA3_256Stream while one is live throws', () => {
		const a = new SHA3_256Stream();
		try {
			expect(() => new SHA3_256Stream()).toThrow();
		} finally {
			a.dispose();
		}
	});

	test('dispose is idempotent', () => {
		const h = new SHA3_256Stream();
		h.dispose();
		expect(() => h.dispose()).not.toThrow();
	});

	test('finalize disposes; subsequent update throws', () => {
		const h = new SHA3_256Stream();
		h.finalize();
		expect(() => h.update(new Uint8Array([1]))).toThrow();
	});

	test('finalize disposes; subsequent finalize throws', () => {
		const h = new SHA3_256Stream();
		h.finalize();
		expect(() => h.finalize()).toThrow();
	});
});

describe('SHA3_512Stream equivalence with one-shot SHA3_512', () => {
	test('"abc" via single update matches one-shot', () => {
		const msg = fromHex('616263');
		const h = new SHA3_512Stream();
		const streamed = h.update(msg).finalize();
		expect(toHex(streamed)).toBe(sha3_512Vectors[1].expected);
	});

	test('1-byte chunks over a long message match one-shot', () => {
		const msg = new Uint8Array(500);
		for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;

		const oneShot = (() => {
			const h = new SHA3_512();
			try {
				return h.hash(msg);
			} finally {
				h.dispose();
			}
		})();

		const h = new SHA3_512Stream();
		for (let i = 0; i < msg.length; i++) h.update(msg.subarray(i, i + 1));
		const streamed = h.finalize();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('mixed chunk sizes across rate boundaries match one-shot', () => {
		const msg = new Uint8Array(300);
		for (let i = 0; i < msg.length; i++) msg[i] = (i * 17) & 0xff;

		const oneShot = (() => {
			const h = new SHA3_512();
			try {
				return h.hash(msg);
			} finally {
				h.dispose();
			}
		})();

		// SHA3-512 rate is 72 bytes; exercise boundary crossings.
		const sizes = [1, 71, 1, 72, 1, 154]; // sums to 300
		const h = new SHA3_512Stream();
		let off = 0;
		for (const n of sizes) {
			h.update(msg.subarray(off, off + n));
			off += n;
		}
		const streamed = h.finalize();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('exclusivity: a second SHA3_512Stream while one is live throws', () => {
		const a = new SHA3_512Stream();
		try {
			expect(() => new SHA3_512Stream()).toThrow();
		} finally {
			a.dispose();
		}
	});

	test('dispose is idempotent', () => {
		const h = new SHA3_512Stream();
		h.dispose();
		expect(() => h.dispose()).not.toThrow();
	});

	test('finalize disposes; subsequent update throws', () => {
		const h = new SHA3_512Stream();
		h.finalize();
		expect(() => h.update(new Uint8Array([1]))).toThrow();
	});

	test('finalize disposes; subsequent finalize throws', () => {
		const h = new SHA3_512Stream();
		h.finalize();
		expect(() => h.finalize()).toThrow();
	});
});
