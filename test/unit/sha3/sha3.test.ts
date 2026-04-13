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
 * SHA3-224/256/384/512, SHAKE128, SHAKE256 Known-Answer Tests — FIPS 202
 *
 * Source: FIPS 202 (SHA-3 Standard)
 * Files:  vectors/sha3.ts (sha3_*Vectors, shake*Vectors, cross-check vectors)
 */
import { describe, test, expect, beforeAll } from 'vitest';
import { init, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import {
	sha3_256Vectors, sha3_512Vectors, sha3_384Vectors, sha3_224Vectors,
	shake128Vectors, shake256Vectors,
	sha3_256CrossCheck, sha3_512CrossCheck,
	sha3_384CrossCheck, sha3_224CrossCheck,
} from '../../vectors/sha3.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

beforeAll(async () => {
	await init({ sha3: sha3Wasm });
});

// GATE: SHA3-256 empty message: FIPS 202 §A.1
// Vector: sha3.ts[sha3_256Vectors[0]]
describe('Gate 7 — SHA3-256 empty message', () => {
	test('SHA3-256("") matches FIPS 202', () => {
		const h = new SHA3_256();
		const digest = h.hash(new Uint8Array(0));
		expect(toHex(digest)).toBe(sha3_256Vectors[0].expected);
		h.dispose();
	});
});

// ── SHA3-256 ────────────────────────────────────────────────────────────────

describe('SHA3-256', () => {
	for (const vec of sha3_256Vectors) {
		test(vec.description, () => {
			const h = new SHA3_256();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHA3-512 ────────────────────────────────────────────────────────────────

describe('SHA3-512', () => {
	for (const vec of sha3_512Vectors) {
		test(vec.description, () => {
			const h = new SHA3_512();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHA3-384 ────────────────────────────────────────────────────────────────

describe('SHA3-384', () => {
	for (const vec of sha3_384Vectors) {
		test(vec.description, () => {
			const h = new SHA3_384();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHA3-224 ────────────────────────────────────────────────────────────────

describe('SHA3-224', () => {
	for (const vec of sha3_224Vectors) {
		test(vec.description, () => {
			const h = new SHA3_224();
			const digest = h.hash(fromHex(vec.input));
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHAKE128 ────────────────────────────────────────────────────────────────

describe('SHAKE128', () => {
	for (const vec of shake128Vectors) {
		test(vec.description, () => {
			const h = new SHAKE128();
			const digest = h.hash(fromHex(vec.input), vec.outputLength);
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}

	test('throws for outputLength < 1', () => {
		const h = new SHAKE128();
		expect(() => h.hash(new Uint8Array(0), 0)).toThrow(RangeError);
		h.dispose();
	});
});

// ── SHAKE256 ────────────────────────────────────────────────────────────────

describe('SHAKE256', () => {
	for (const vec of shake256Vectors) {
		test(vec.description, () => {
			const h = new SHAKE256();
			const digest = h.hash(fromHex(vec.input), vec.outputLength);
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHAKE128 multi-block hash() ─────────────────────────────────────────────

describe('SHAKE128 multi-block hash()', () => {
	for (const vec of shake128Vectors.filter(v => v.outputLength > 168)) {
		test(vec.description, () => {
			const h = new SHAKE128();
			const digest = h.hash(fromHex(vec.input), vec.outputLength);
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHAKE256 multi-block hash() ─────────────────────────────────────────────

describe('SHAKE256 multi-block hash()', () => {
	for (const vec of shake256Vectors.filter(v => v.outputLength > 136)) {
		test(vec.description, () => {
			const h = new SHAKE256();
			const digest = h.hash(fromHex(vec.input), vec.outputLength);
			expect(toHex(digest)).toBe(vec.expected);
			h.dispose();
		});
	}
});

// ── SHAKE128 incremental absorb ─────────────────────────────────────────────

describe('SHAKE128 incremental absorb matches hash()', () => {
	test('split absorb produces same output as one-shot hash()', () => {
		const input = fromHex('616263');
		const half = input.length >>> 1;
		const h = new SHAKE128();

		const oneShot = h.hash(input, 32);

		h.reset();
		h.absorb(input.subarray(0, half));
		h.absorb(input.subarray(half));
		const incremental = h.squeeze(32);

		expect(toHex(incremental)).toBe(toHex(oneShot));
		h.dispose();
	});
});

// ── SHAKE256 incremental absorb ─────────────────────────────────────────────

describe('SHAKE256 incremental absorb matches hash()', () => {
	test('split absorb produces same output as one-shot hash()', () => {
		const input = fromHex('616263');
		const half = input.length >>> 1;
		const h = new SHAKE256();

		const oneShot = h.hash(input, 32);

		h.reset();
		h.absorb(input.subarray(0, half));
		h.absorb(input.subarray(half));
		const incremental = h.squeeze(32);

		expect(toHex(incremental)).toBe(toHex(oneShot));
		h.dispose();
	});
});

// ── SHAKE128 state machine guards ───────────────────────────────────────────

describe('SHAKE128 state machine guards', () => {
	test('absorb() after squeeze() throws with reset() hint', () => {
		const h = new SHAKE128();
		h.absorb(new Uint8Array(0));
		h.squeeze(1);
		expect(() => h.absorb(new Uint8Array([0x01]))).toThrow('reset()');
		h.dispose();
	});

	test('reset() allows absorb after squeeze', () => {
		const h = new SHAKE128();
		h.absorb(new Uint8Array([0x61]));
		h.squeeze(1);
		h.reset();
		expect(() => h.absorb(new Uint8Array([0x61]))).not.toThrow();
		h.dispose();
	});

	test('hash() is always safe regardless of prior state', () => {
		const h = new SHAKE128();
		h.absorb(new Uint8Array([0x61]));
		h.squeeze(16);
		expect(() => h.hash(new Uint8Array([0x61]), 32)).not.toThrow();
		h.dispose();
	});
});

// ── SHAKE256 state machine guards ───────────────────────────────────────────

describe('SHAKE256 state machine guards', () => {
	test('absorb() after squeeze() throws with reset() hint', () => {
		const h = new SHAKE256();
		h.absorb(new Uint8Array(0));
		h.squeeze(1);
		expect(() => h.absorb(new Uint8Array([0x01]))).toThrow('reset()');
		h.dispose();
	});

	test('reset() allows absorb after squeeze', () => {
		const h = new SHAKE256();
		h.absorb(new Uint8Array([0x61]));
		h.squeeze(1);
		h.reset();
		expect(() => h.absorb(new Uint8Array([0x61]))).not.toThrow();
		h.dispose();
	});

	test('hash() is always safe regardless of prior state', () => {
		const h = new SHAKE256();
		h.absorb(new Uint8Array([0x61]));
		h.squeeze(16);
		expect(() => h.hash(new Uint8Array([0x61]), 32)).not.toThrow();
		h.dispose();
	});
});

// ── SHAKE dispose zeroes TS-side buffer ─────────────────────────────────────

describe('SHAKE dispose zeroes TS-side block buffer', () => {
	test('SHAKE128 dispose() zeroes _block', () => {
		const h = new SHAKE128() as unknown as { _block: Uint8Array };
		(h as unknown as SHAKE128).hash(new Uint8Array([0x61, 0x62, 0x63]), 32);
		(h as unknown as SHAKE128).dispose();
		let nonZero = 0;
		for (const b of h._block) nonZero |= b;
		expect(nonZero).toBe(0);
	});

	test('SHAKE256 dispose() zeroes _block', () => {
		const h = new SHAKE256() as unknown as { _block: Uint8Array };
		(h as unknown as SHAKE256).hash(new Uint8Array([0x61, 0x62, 0x63]), 32);
		(h as unknown as SHAKE256).dispose();
		let nonZero = 0;
		for (const b of h._block) nonZero |= b;
		expect(nonZero).toBe(0);
	});
});

// ── wipeBuffers ─────────────────────────────────────────────────────────────

describe('wipeBuffers', () => {
	test('zeros state buffer after dispose', () => {
		const h = new SHA3_256();
		h.hash(new Uint8Array([0x61, 0x62, 0x63])); // hash "abc"
		h.dispose();

		const x = getInstance('sha3').exports as unknown as {
			memory: WebAssembly.Memory;
			getStateOffset: () => number;
		};
		const mem = new Uint8Array(x.memory.buffer);
		const stateOff = x.getStateOffset();
		let nonZero = 0;
		for (let i = 0; i < 200; i++) nonZero |= mem[stateOff + i];
		expect(nonZero).toBe(0);
	});
});

// ── leviathan cross-check ───────────────────────────────────────────────────

describe('leviathan cross-check', () => {
	test('SHA3-256 matches leviathan reference for 4 inputs', () => {
		const h = new SHA3_256();
		for (const vec of sha3_256CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});

	test('SHA3-512 matches leviathan reference for 4 inputs', () => {
		const h = new SHA3_512();
		for (const vec of sha3_512CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});

	test('SHA3-384 matches leviathan reference for 4 inputs', () => {
		const h = new SHA3_384();
		for (const vec of sha3_384CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});

	test('SHA3-224 matches Node.js crypto for 2 inputs', () => {
		const h = new SHA3_224();
		for (const vec of sha3_224CrossCheck) {
			expect(toHex(h.hash(fromHex(vec.input))), vec.description).toBe(vec.expected);
		}
		h.dispose();
	});
});
