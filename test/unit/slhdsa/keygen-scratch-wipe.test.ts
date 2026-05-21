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
//                           ▀█████▀▀▀
//
// test/unit/slhdsa/keygen-scratch-wipe.test.ts
//
// Verifies that wipeBuffers() zeroes the OUT, STATE, and SCRATCH regions
// after slhKeygenInternal leaves its working state behind. Mirrors the
// mldsa keygen-scratch-wipe discipline.
//
// FIPS 205 keygen drives xmss_node which exercises wots_pkGen at every leaf,
// leaving wots scratch (WOTS_TMP, WOTS_SK, SK_ADRS, WOTSPK_ADRS), xmss
// pair-stack scratch (XMSS_PAIR_BASE), and the embedded SHAKE256 sponge
// state behind in STATE / SCRATCH. The output buffer (OUT) holds SK || PK,
// which itself contains the secret seeds; wipeBuffers() must zero it after
// the TS layer reads the bytes out.

import { describe, it, expect, beforeAll } from 'vitest';
import { loadSlhdsa, exports_, mem } from './helpers.js';

beforeAll(async () => {
	await loadSlhdsa();
});

function regionIsZero(buf: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (buf[off + i] !== 0) return false;
	return true;
}

function regionHasNonZero(buf: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (buf[off + i] !== 0) return true;
	return false;
}

describe('slhKeygenInternal scratch-wipe (FIPS 205 §9.1)', () => {
	it('OUT region is non-zero after keygen, zero after wipeBuffers (128f)', () => {
		const x = exports_();
		const m = mem();
		x.slhSetParams128f();

		// Drive keygen with non-zero seeds so OUT picks up non-zero bytes.
		const inOff = x.getInputOffset();
		const outOff = x.getOutOffset();
		m.fill(0xA1, inOff,        inOff + 16);   // SK.seed
		m.fill(0xB2, inOff + 16,   inOff + 32);   // SK.prf
		m.fill(0xC3, inOff + 32,   inOff + 48);   // PK.seed
		x.slhKeygenInternal();

		// OUT holds SK || PK = 4n + 2n = 96 bytes for 128f. Should be non-zero.
		expect(regionHasNonZero(m, outOff, 96)).toBe(true);

		x.wipeBuffers();

		// OUT, STATE, SCRATCH must all be zero.
		expect(regionIsZero(m, outOff,                52 * 1024)).toBe(true);
		expect(regionIsZero(m, x.getStateOffset(),    4  * 1024)).toBe(true);
		expect(regionIsZero(m, x.getScratchOffset(),  8  * 1024)).toBe(true);
	});

	it('STATE region carries WOTS+/XMSS scratch after keygen, zero after wipe (192f)', () => {
		const x = exports_();
		const m = mem();
		x.slhSetParams192f();

		// Pre-dirty STATE so we can confirm both that keygen overwrites parts
		// of it AND that wipe zeros the entire region.
		const stateOff = x.getStateOffset();
		m.fill(0x5a, stateOff + 64, stateOff + 64 + 512);

		const inOff = x.getInputOffset();
		const n = 24;
		m.fill(0x11, inOff,         inOff + n);
		m.fill(0x22, inOff + n,     inOff + n * 2);
		m.fill(0x33, inOff + n * 2, inOff + n * 3);
		x.slhKeygenInternal();

		// STATE should have working scratch left over (WOTS_TMP, XMSS_PAIR_BASE
		// at minimum). Confirm SOME of the upper sub-region is non-zero.
		expect(regionHasNonZero(m, stateOff + 64, 1024)).toBe(true);

		x.wipeBuffers();
		expect(regionIsZero(m, stateOff, 4 * 1024)).toBe(true);
	});

	it('SCRATCH (Keccak sponge state) zeroed after wipe (256f)', () => {
		const x = exports_();
		const m = mem();
		x.slhSetParams256f();

		const inOff = x.getInputOffset();
		const n = 32;
		m.fill(0x99, inOff,         inOff + n);
		m.fill(0x88, inOff + n,     inOff + n * 2);
		m.fill(0x77, inOff + n * 2, inOff + n * 3);
		x.slhKeygenInternal();

		// Keccak permutation state lives at SCRATCH_OFFSET..+199 and after
		// the keygen flow runs many SHAKE256 invocations, the sponge state
		// will hold the residue of the last permutation.
		expect(regionHasNonZero(m, x.getScratchOffset(), 200)).toBe(true);

		x.wipeBuffers();
		expect(regionIsZero(m, x.getScratchOffset(), 8 * 1024)).toBe(true);
	});

	it('pre-dirtied OUT/STATE/SCRATCH are wiped to zero', () => {
		const x = exports_();
		const m = mem();

		const outOff     = x.getOutOffset();
		const stateOff   = x.getStateOffset();
		const scratchOff = x.getScratchOffset();

		// Stripe a poison pattern across all three regions before keygen.
		// Keep STATE poison clear of bytes 0..47 (ADRS scratch + PARAMS slot);
		// trampling those before the param selector runs would corrupt the
		// active n / m / paramSet readout and trigger OOB memory access.
		m.fill(0xa5, outOff,         outOff     + 96);
		m.fill(0xa5, stateOff + 48,  stateOff   + 256 + 48);
		m.fill(0xa5, scratchOff,     scratchOff + 256);

		x.slhSetParams128f();

		const inOff = x.getInputOffset();
		m.fill(0x44, inOff,        inOff + 48);
		x.slhKeygenInternal();
		x.wipeBuffers();

		expect(regionIsZero(m, outOff,     52 * 1024)).toBe(true);
		expect(regionIsZero(m, stateOff,   4  * 1024)).toBe(true);
		expect(regionIsZero(m, scratchOff, 8  * 1024)).toBe(true);
	});
});
