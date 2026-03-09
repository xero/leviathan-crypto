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
import { describe, test, expect, beforeAll } from 'vitest';
import { init, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import {
	sha3_256Vectors, sha3_512Vectors, sha3_384Vectors, sha3_224Vectors,
	shake128Vectors, shake256Vectors,
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
	await init('sha3');
});

// ── Gate 7: SHA3-256 empty message ──────────────────────────────────────────
// GATE
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

	test('throws for outputLength > 168', () => {
		const h = new SHAKE128();
		expect(() => h.hash(new Uint8Array(0), 169)).toThrow(RangeError);
		h.dispose();
	});

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

	test('throws for outputLength > 136', () => {
		const h = new SHAKE256();
		expect(() => h.hash(new Uint8Array(0), 137)).toThrow(RangeError);
		h.dispose();
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
// Verified against leviathan/src/sha3.ts (TypeScript reference) — read AFTER Gate 7 passed.
// These values were computed with the leviathan reference using npx tsx.

describe('leviathan cross-check', () => {
	const crossInputs = [
		{ label: 'empty',     data: new Uint8Array(0) },
		{ label: '"abc"',     data: new Uint8Array([0x61, 0x62, 0x63]) },
		{ label: 'fox',       data: new TextEncoder().encode('The quick brown fox jumps over the lazy dog') },
		{ label: '"a"×200',   data: new Uint8Array(200).fill(0x61) },
	];

	const levSha3_256 = [
		'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
		'3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
		'69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04',
		'cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387',
	];

	const levSha3_512 = [
		'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
		'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
		'01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450',
		'eae6c85c6904f11075de9f9d5e1064371d000510fa3d2d79d40cf9be34892fb01859d0a0234e138bcb0ad5c84f6c0dca226a414b0c9a2897cb695f5185fe36ec',
	];

	const levSha3_384 = [
		'0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
		'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25',
		'7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41',
		'f97756776c1874724c94a8008f7f155553b4bf00fbf8fbeac246624ad59c258a3c0977d9f2543d7cbd75b9ac8fdc0d40',
	];

	test('SHA3-256 matches leviathan reference for 4 inputs', () => {
		const h = new SHA3_256();
		for (let i = 0; i < crossInputs.length; i++) {
			expect(toHex(h.hash(crossInputs[i].data)), crossInputs[i].label).toBe(levSha3_256[i]);
		}
		h.dispose();
	});

	test('SHA3-512 matches leviathan reference for 4 inputs', () => {
		const h = new SHA3_512();
		for (let i = 0; i < crossInputs.length; i++) {
			expect(toHex(h.hash(crossInputs[i].data)), crossInputs[i].label).toBe(levSha3_512[i]);
		}
		h.dispose();
	});

	test('SHA3-384 matches leviathan reference for 4 inputs', () => {
		const h = new SHA3_384();
		for (let i = 0; i < crossInputs.length; i++) {
			expect(toHex(h.hash(crossInputs[i].data)), crossInputs[i].label).toBe(levSha3_384[i]);
		}
		h.dispose();
	});

	test('SHA3-224 matches Node.js crypto for 2 inputs', () => {
		const h = new SHA3_224();
		expect(toHex(h.hash(crossInputs[0].data))).toBe('6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7');
		expect(toHex(h.hash(crossInputs[1].data))).toBe('e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf');
		h.dispose();
	});
});
