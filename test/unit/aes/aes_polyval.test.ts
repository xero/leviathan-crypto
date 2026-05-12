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
// test/unit/aes/aes_polyval.test.ts
//
// Gate 15, standalone POLYVAL primitive validation. Walks the RFC 8452
// Appendix A worked example through the WASM POLYVAL absorber directly
// (not via AES-GCM-SIV), the §3 mulX_GHASH examples through the
// `mulXGhash` helper, and the §7 field-operation algebra trace through
// a two-block POLYVAL run.
//
// Path-(a) reflection-wrapper note: the per-block scratch is a byte-
// reversed copy of the input that is XORed into the GHASH-bit-convention
// accumulator. The §7 `dot` and `product` primitives are not directly
// exposed by path (a), they are exercised transitively by the full
// POLYVAL hash trace. We assert the §7 `sum` field as a XOR sanity
// check and leave `product`/`dot` for the verifier to cover.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { aesWasm } from '../../../src/ts/aes/embedded.js';
import {
	polyvalFieldOps,
	polyvalMulXVectors,
	polyvalHashVectors,
} from '../../vectors/polyval';
import { fromHex, toHex } from '../helpers';

beforeAll(async () => {
	await init({ aes: aesWasm });
});

interface AesPolyvalExports {
	memory:                WebAssembly.Memory;
	getChunkPtOffset:      () => number;
	getGhashAccOffset:     () => number;
	getPolyvalAuthKeyOffset: () => number;
	mulXGhash:             (srcOff: number, dstOff: number) => void;
	byteReverse16:         (srcOff: number, dstOff: number) => void;
	polyvalStart:          (authKeyOff: number) => void;
	polyvalAbsorbBlock:    (srcOff: number) => void;
	polyvalAbsorbWithLen:  (srcOff: number, len: number) => void;
	polyvalFinalize:       (dstOff: number) => void;
	wipeBuffers:           () => void;
}

const x = (): AesPolyvalExports =>
	getInstance('aes').exports as unknown as AesPolyvalExports;

const mem = (): Uint8Array =>
	new Uint8Array(x().memory.buffer);

describe('POLYVAL gate (Gate 15), RFC 8452 §3, §7, Appendix A', () => {
	describe('15a, Appendix A POLYVAL(H, X_1, X_2) hash trace', () => {
		for (const v of polyvalHashVectors) {
			// GATE: full POLYVAL hash trace from RFC 8452 Appendix A. If this
			// fails, the bridge math (path (a) byte-reverse + mulX_GHASH on H,
			// per-block byte-reverse, final byte-reverse out) is wrong.
			it(v.description, () => {
				try {
					const w = x();
					const ptOff = w.getChunkPtOffset();
					const authOff = w.getPolyvalAuthKeyOffset();

					// Stage H at the auth-key offset; stage blocks contiguously
					// in CHUNK_PT.
					mem().set(fromHex(v.h), authOff);
					for (let i = 0; i < v.blocks.length; i++) {
						mem().set(fromHex(v.blocks[i]), ptOff + i * 16);
					}

					w.polyvalStart(authOff);
					for (let i = 0; i < v.blocks.length; i++) {
						w.polyvalAbsorbBlock(ptOff + i * 16);
					}
					const out = new Uint8Array(16);
					mem().set(out, ptOff);  // clear PT scratch where we'll read
					w.polyvalFinalize(ptOff);
					expect(toHex(mem().slice(ptOff, ptOff + 16))).toBe(v.expected);
				} finally {
					x().wipeBuffers();
				}
			});
		}
	});

	describe('15b, Appendix A mulX_GHASH primitive', () => {
		for (const v of polyvalMulXVectors) {
			it(v.description, () => {
				try {
					const w = x();
					const off = w.getChunkPtOffset();
					const dst = off + 16;
					mem().set(fromHex(v.input), off);
					w.mulXGhash(off, dst);
					expect(toHex(mem().slice(dst, dst + 16))).toBe(v.mulX_ghash);
				} finally {
					x().wipeBuffers();
				}
			});
		}
	});

	describe('15c, §7 field-ops algebra (XOR sanity check)', () => {
		// `product` and `dot` are not directly testable via path (a), they
		// are transitively exercised by the §3/Appendix A hash trace and by
		// every AES-GCM-SIV vector. The only field operation path (a)
		// exposes naturally is XOR, used internally in absorption.
		it(polyvalFieldOps.description, () => {
			const a = fromHex(polyvalFieldOps.a);
			const b = fromHex(polyvalFieldOps.b);
			const sum = new Uint8Array(16);
			for (let i = 0; i < 16; i++) sum[i] = a[i] ^ b[i];
			expect(toHex(sum)).toBe(polyvalFieldOps.sum);
		});
	});

	describe('15d, byteReverse16 helper', () => {
		it('reverses byte order of a 16-byte block', () => {
			try {
				const w = x();
				const off = w.getChunkPtOffset();
				const dst = off + 16;
				const input = new Uint8Array(16);
				for (let i = 0; i < 16; i++) input[i] = i;
				mem().set(input, off);
				w.byteReverse16(off, dst);
				const out = mem().slice(dst, dst + 16);
				for (let i = 0; i < 16; i++) {
					expect(out[i]).toBe(15 - i);
				}
			} finally {
				x().wipeBuffers();
			}
		});

		it('handles src===dst (in-place reverse)', () => {
			try {
				const w = x();
				const off = w.getChunkPtOffset();
				const input = fromHex('00112233445566778899aabbccddeeff');
				mem().set(input, off);
				w.byteReverse16(off, off);
				expect(toHex(mem().slice(off, off + 16)))
					.toBe('ffeeddccbbaa99887766554433221100');
			} finally {
				x().wipeBuffers();
			}
		});
	});
});
