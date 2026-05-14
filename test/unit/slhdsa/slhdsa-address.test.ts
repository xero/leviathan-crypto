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
// test/unit/slhdsa/slhdsa-address.test.ts
//
// SLH-DSA ADRS encode/decode boundary tests, FIPS 205 §4.2 Figure 2 + Tables.
// Exhaustive checks for the 32-byte layout:
//   - all 7 ADRS types round-trip cleanly,
//   - big-endian byte order for layer/tree/type/keypair/chain/hash/height/
//     index fields,
//   - layer field is a 4-byte big-endian word (FIPS 205 §4.2 Figure 2),
//   - tree address is 12 bytes big-endian split across three u32 limbs,
//   - type-field setter zeroes type-specific slots per FIPS 205 §4.2
//     Algorithm 14.
//
// This file gates the ADRS encoding only; the algorithm-level entry points
// are exercised by slhdsa-acvp.test.ts and the sign/* integration suite.
// Each test allocates an ADRS scratch buffer in WASM memory, drives the
// setter, then asserts byte-by-byte against the raw memory image.

import { describe, test, expect, beforeAll } from 'vitest';
import { slhdsaInit, getSlhDsaExports } from '../../../src/ts/slhdsa/index.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';

let mem: Uint8Array;
let adrs: number;
let x: ReturnType<typeof getSlhDsaExports>;

// ADRS type constants from FIPS 205 §4.2 (must match src/asm/slhdsa/address.ts)
const ADRS_WOTS_HASH  = 0;
const ADRS_WOTS_PK    = 1;
const ADRS_TREE       = 2;
const ADRS_FORS_TREE  = 3;
const ADRS_FORS_ROOTS = 4;
const ADRS_WOTS_PRF   = 5;
const ADRS_FORS_PRF   = 6;
const ALL_TYPES = [
	ADRS_WOTS_HASH, ADRS_WOTS_PK, ADRS_TREE,
	ADRS_FORS_TREE, ADRS_FORS_ROOTS, ADRS_WOTS_PRF, ADRS_FORS_PRF,
];

function adrsBytes(): Uint8Array {
	return mem.subarray(adrs, adrs + 32);
}

beforeAll(async () => {
	await slhdsaInit(slhdsaWasm);
	x = getSlhDsaExports();
	mem  = new Uint8Array(x.memory.buffer);
	adrs = x.getAdrsOffset();
});

// ── adrsClear ───────────────────────────────────────────────────────────────

describe('adrsClear', () => {
	test('zeroes all 32 bytes', () => {
		mem.fill(0xaa, adrs, adrs + 32);
		x.adrsClear(adrs);
		expect(Array.from(adrsBytes())).toEqual(Array(32).fill(0));
	});
});

// ── Layer field, 4-byte big-endian word (FIPS 205 §4.2 Figure 2) ───────────

describe('adrsSetLayerAddress, 4-byte big-endian word', () => {
	test('layer=0x00 writes bytes 0..3 all zero', () => {
		mem.fill(0xff, adrs, adrs + 32);
		x.adrsClear(adrs);
		x.adrsSetLayerAddress(adrs, 0);
		const b = adrsBytes();
		expect(b[0]).toBe(0);
		expect(b[1]).toBe(0);
		expect(b[2]).toBe(0);
		expect(b[3]).toBe(0);
	});

	test('layer=0xff lands in byte 3 with bytes 0..2 zero (BE encoding)', () => {
		// Pre-poison the ADRS so a stale value at any byte 0..3 would be visible.
		mem.fill(0xaa, adrs, adrs + 32);
		x.adrsClear(adrs);
		x.adrsSetLayerAddress(adrs, 0xff);
		const b = adrsBytes();
		expect(b[0]).toBe(0);    // high byte of BE u32
		expect(b[1]).toBe(0);
		expect(b[2]).toBe(0);
		expect(b[3]).toBe(0xff); // low byte
	});

	test('layer=0x01020304 round-trips full 4-byte BE encoding', () => {
		x.adrsClear(adrs);
		x.adrsSetLayerAddress(adrs, 0x01020304);
		const b = adrsBytes();
		expect(b[0]).toBe(0x01);
		expect(b[1]).toBe(0x02);
		expect(b[2]).toBe(0x03);
		expect(b[3]).toBe(0x04);
		expect(x.adrsGetLayerAddress(adrs)).toBe(0x01020304);
	});

	test('round-trip for FIPS 205 approved layer values', () => {
		for (const layer of [0, 1, 16, 21, 22, 127, 200, 255]) {
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, layer);
			expect(x.adrsGetLayerAddress(adrs)).toBe(layer);
		}
	});

	test('setLayer keeps tree/type/keypair/chain/hash bytes untouched', () => {
		x.adrsClear(adrs);
		x.adrsSetTreeAddr(adrs, 0x01020304, 0x05060708, 0x090a0b0c);
		x.adrsSetType(adrs, ADRS_WOTS_HASH);
		x.adrsSetKeyPairAddress(adrs, 0xdeadbeef);
		x.adrsSetChainAddress(adrs, 0x12345678);
		x.adrsSetHashAddress(adrs, 0x9abcdef0);
		const before = Array.from(adrsBytes());

		x.adrsSetLayerAddress(adrs, 0x42);

		const after = Array.from(adrsBytes());
		expect(after[0]).toBe(0);
		expect(after[1]).toBe(0);
		expect(after[2]).toBe(0);
		expect(after[3]).toBe(0x42);
		// Bytes 4..31 must be unchanged.
		for (let i = 4; i < 32; i++) {
			expect(after[i]).toBe(before[i]);
		}
	});
});

// ── Tree address, 12 bytes big-endian (FIPS 205 §4.2 Tables 1-7) ───────────

describe('adrsSetTreeAddr, 12-byte big-endian across three u32 limbs', () => {
	test('byte-by-byte layout for (hi=0x01020304, mid=0x05060708, lo=0x090a0b0c)', () => {
		x.adrsClear(adrs);
		x.adrsSetTreeAddr(adrs, 0x01020304, 0x05060708, 0x090a0b0c);
		const expected = [
			0x00, 0x00, 0x00, 0x00,                  // bytes 0..3 = layer (BE u32, zero here)
			0x01, 0x02, 0x03, 0x04,                  // bytes 4..7  = treeHi  BE
			0x05, 0x06, 0x07, 0x08,                  // bytes 8..11 = treeMid BE
			0x09, 0x0a, 0x0b, 0x0c,                  // bytes 12..15 = treeLo BE
		];
		const got = Array.from(adrsBytes().slice(0, 16));
		expect(got).toEqual(expected);
	});

	test('round-trip getters return the original limbs', () => {
		const hi = 0xdeadbeef, mid = 0xfeedface, lo = 0xcafebabe;
		x.adrsClear(adrs);
		x.adrsSetTreeAddr(adrs, hi, mid, lo);
		expect(x.adrsGetTreeHi(adrs)  >>> 0).toBe(hi);
		expect(x.adrsGetTreeMid(adrs) >>> 0).toBe(mid);
		expect(x.adrsGetTreeLo(adrs)  >>> 0).toBe(lo);
	});

	test('setTreeAddr does not touch bytes 0..3 or 16..31', () => {
		x.adrsClear(adrs);
		x.adrsSetLayerAddress(adrs, 0xa1);
		x.adrsSetType(adrs, ADRS_TREE);
		x.adrsSetKeyPairAddress(adrs, 0xa2a2a2a2);
		x.adrsSetTreeHeight(adrs, 0xa3a3a3a3);
		x.adrsSetTreeIndex(adrs, 0xa4a4a4a4);

		const before = Array.from(adrsBytes());

		x.adrsSetTreeAddr(adrs, 0, 0, 0xffffffff);

		const after = Array.from(adrsBytes());
		// Bytes 0..3 (layer + reserved) and 16..31 (type + keypair + height +
		// index) must remain identical.
		for (const i of [0, 1, 2, 3, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]) {
			expect(after[i]).toBe(before[i]);
		}
		// Bytes 4..11 cleared (hi=mid=0); bytes 12..15 = 0xff,0xff,0xff,0xff.
		expect(after.slice(4, 12)).toEqual(Array(8).fill(0));
		expect(after.slice(12, 16)).toEqual([0xff, 0xff, 0xff, 0xff]);
	});
});

// ── Type field, 4 bytes big-endian, clears type-specific slots ─────────────

describe('adrsSetType, FIPS 205 §4.2 Algorithm 14', () => {
	test.each(ALL_TYPES)('type=%i round-trips and writes big-endian bytes 16..19', (t) => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, t);

		const b = adrsBytes();
		expect(b[16]).toBe(0);     // type fits in one byte for all 7 values
		expect(b[17]).toBe(0);
		expect(b[18]).toBe(0);
		expect(b[19]).toBe(t & 0xff);
		expect(x.adrsGetType(adrs)).toBe(t);
	});

	test('setType zeroes bytes 20..31 (type-specific slots) per Algorithm 14', () => {
		x.adrsClear(adrs);
		// Pre-fill the keypair/chain/hash slots
		x.adrsSetKeyPairAddress(adrs, 0xdeadbeef);
		x.adrsSetChainAddress(adrs, 0x12345678);
		x.adrsSetHashAddress(adrs, 0x9abcdef0);
		// Confirm the pre-fill landed.
		expect(adrsBytes().slice(20, 32).some(v => v !== 0)).toBe(true);

		x.adrsSetType(adrs, ADRS_WOTS_PK);

		expect(Array.from(adrsBytes().slice(20, 32))).toEqual(Array(12).fill(0));
	});

	test('setType keeps layer/reserved/tree bytes 0..15 untouched', () => {
		x.adrsClear(adrs);
		x.adrsSetLayerAddress(adrs, 0x42);
		x.adrsSetTreeAddr(adrs, 0x11, 0x22, 0x33);
		const beforeHead = Array.from(adrsBytes().slice(0, 16));

		x.adrsSetType(adrs, ADRS_FORS_TREE);

		const afterHead = Array.from(adrsBytes().slice(0, 16));
		expect(afterHead).toEqual(beforeHead);
	});
});

// ── Keypair / chain / hash address, 4 bytes big-endian each ────────────────

describe('adrsSetKeyPairAddress / Chain / Hash, big-endian u32', () => {
	test('keypair=0x01020304 writes bytes 20..23 big-endian', () => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, ADRS_WOTS_HASH);
		x.adrsSetKeyPairAddress(adrs, 0x01020304);
		expect(Array.from(adrsBytes().slice(20, 24))).toEqual([0x01, 0x02, 0x03, 0x04]);
	});

	test('chain=0x05060708 writes bytes 24..27 big-endian', () => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, ADRS_WOTS_HASH);
		x.adrsSetChainAddress(adrs, 0x05060708);
		expect(Array.from(adrsBytes().slice(24, 28))).toEqual([0x05, 0x06, 0x07, 0x08]);
	});

	test('hash=0x090a0b0c writes bytes 28..31 big-endian', () => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, ADRS_WOTS_HASH);
		x.adrsSetHashAddress(adrs, 0x090a0b0c);
		expect(Array.from(adrsBytes().slice(28, 32))).toEqual([0x09, 0x0a, 0x0b, 0x0c]);
	});

	test('keypair / chain / hash round-trip independently for WOTS_HASH', () => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, ADRS_WOTS_HASH);
		x.adrsSetKeyPairAddress(adrs, 0xdeadbeef);
		x.adrsSetChainAddress(adrs, 0x12345678);
		x.adrsSetHashAddress(adrs, 0x9abcdef0);
		expect(x.adrsGetKeyPairAddress(adrs) >>> 0).toBe(0xdeadbeef);
		expect(x.adrsGetChainAddress(adrs)   >>> 0).toBe(0x12345678);
		expect(x.adrsGetHashAddress(adrs)    >>> 0).toBe(0x9abcdef0);
	});
});

// ── Tree-height / tree-index aliases ───────────────────────────────────────

describe('adrsSetTreeHeight / TreeIndex, FIPS 205 §4.2 Tables 4-5', () => {
	test('tree height writes bytes 24..27 big-endian (alias of chain offset)', () => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, ADRS_TREE);
		x.adrsSetTreeHeight(adrs, 0x11223344);
		expect(Array.from(adrsBytes().slice(24, 28))).toEqual([0x11, 0x22, 0x33, 0x44]);
		expect(x.adrsGetTreeHeight(adrs) >>> 0).toBe(0x11223344);
	});

	test('tree index writes bytes 28..31 big-endian (alias of hash offset)', () => {
		x.adrsClear(adrs);
		x.adrsSetType(adrs, ADRS_FORS_TREE);
		x.adrsSetTreeIndex(adrs, 0xaabbccdd);
		expect(Array.from(adrsBytes().slice(28, 32))).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
		expect(x.adrsGetTreeIndex(adrs) >>> 0).toBe(0xaabbccdd);
	});
});

// ── adrsCopy ────────────────────────────────────────────────────────────────

describe('adrsCopy', () => {
	test('copies 32 bytes from src to dst, leaves src untouched', () => {
		// dst = ADRS_OFFSET; src = SCRATCH region for a scratch adrs.
		const src = x.getScratchOffset() + 1024;

		x.adrsClear(adrs);
		x.adrsSetLayerAddress(adrs, 0x07);
		x.adrsSetTreeAddr(adrs, 0xdeadbeef, 0xfeedface, 0xcafebabe);
		x.adrsSetType(adrs, ADRS_FORS_PRF);
		x.adrsSetKeyPairAddress(adrs, 0x10203040);
		x.adrsSetTreeIndex(adrs, 0x50607080);
		const original = Array.from(adrsBytes());

		x.adrsCopy(src, adrs);

		const copied = Array.from(mem.subarray(src, src + 32));
		expect(copied).toEqual(original);
		// src now matches dst, source is untouched at adrs.
		expect(Array.from(adrsBytes())).toEqual(original);
	});
});

// ── Round-trip walk: every type does not corrupt the others' fields ─────────

describe('field independence: setting one field does not corrupt others', () => {
	for (const t of ALL_TYPES) {
		test(`type=${t}: full round-trip writes/reads all fields without cross-talk`, () => {
			x.adrsClear(adrs);
			x.adrsSetLayerAddress(adrs, 0x21 ^ t);
			x.adrsSetTreeAddr(adrs, 0xa1a2a3a4, 0xb1b2b3b4, 0xc1c2c3c4);
			x.adrsSetType(adrs, t);
			x.adrsSetKeyPairAddress(adrs, 0xd1d2d3d4);
			x.adrsSetTreeHeight(adrs, 0xe1e2e3e4);
			x.adrsSetTreeIndex(adrs, 0xf1f2f3f4);

			expect(x.adrsGetLayerAddress(adrs)).toBe(0x21 ^ t);
			expect(x.adrsGetTreeHi(adrs)  >>> 0).toBe(0xa1a2a3a4);
			expect(x.adrsGetTreeMid(adrs) >>> 0).toBe(0xb1b2b3b4);
			expect(x.adrsGetTreeLo(adrs)  >>> 0).toBe(0xc1c2c3c4);
			expect(x.adrsGetType(adrs)).toBe(t);
			expect(x.adrsGetKeyPairAddress(adrs) >>> 0).toBe(0xd1d2d3d4);
			expect(x.adrsGetTreeHeight(adrs)     >>> 0).toBe(0xe1e2e3e4);
			expect(x.adrsGetTreeIndex(adrs)      >>> 0).toBe(0xf1f2f3f4);
		});
	}
});
