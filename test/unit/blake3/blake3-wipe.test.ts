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
 * BLAKE3 wipe coverage, AGENTS.md §Memory and Security.
 *
 * Each class disposes via `wipeBuffers()` (TS dispose() calls
 * x.wipeBuffers()); this test asserts the WASM-side mutable buffer
 * region is zero after dispose across every class:
 *
 *   BLAKE3 / BLAKE3Stream                  (hash mode)
 *   BLAKE3KeyedHash / BLAKE3KeyedHashStream (keyed_hash, 32-byte key)
 *   BLAKE3DeriveKey / BLAKE3DeriveKeyStream (derive_key, pass-1 CCV)
 *   BLAKE3OutputReader                     (post-finalizeXof XOF)
 *
 * The test reads WASM linear memory directly (not through the public
 * class API) per the pattern in
 * test/unit/slhdsa/keygen-scratch-wipe.test.ts. It additionally
 * pre-dirties the mutable region between MUTABLE_START and BUFFER_END
 * before the op so the assertion proves wipe definitively zeros, not
 * just initial-empty.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	BLAKE3, BLAKE3Stream,
	BLAKE3KeyedHash, BLAKE3KeyedHashStream,
	BLAKE3DeriveKey, BLAKE3DeriveKeyStream,
} from '../../../src/ts/blake3/index.js';
import { blake3Key, blake3ContextString } from '../../vectors/blake3.js';
import { loadBlake3, exports_, mem } from './helpers.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);

// Mutable buffer region (src/asm/blake3/buffers.ts). MUTABLE_START
// is the first byte after the AS data segment (SIGMA tables); BUFFER_END
// is the exclusive upper bound. wipeBuffers() zeros this entire region.
const MUTABLE_START = 4096;
const BUFFER_END    = 26328;

function regionIsZero(buf: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (buf[off + i] !== 0) return false;
	return true;
}

function regionHasNonZero(buf: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (buf[off + i] !== 0) return true;
	return false;
}

// Stripe a poison pattern across the mutable region so the post-dispose
// zero check proves wipe ran (not initial-empty). Stays clear of the
// data-segment region 0..MUTABLE_START-1 where SIGMA lives.
function poisonMutable(m: Uint8Array): void {
	m.fill(0xa5, MUTABLE_START, BUFFER_END);
}

function makeMaterial(len: number): Uint8Array {
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) out[i] = i % 251;
	return out;
}

beforeAll(async () => {
	await loadBlake3();
});

describe('BLAKE3 wipe coverage (AGENTS.md §Memory and Security)', () => {
	it('BLAKE3.hash + dispose zeroes the mutable region', () => {
		const input = makeMaterial(1234);
		const h     = new BLAKE3();
		const m     = mem();
		try        {
			h.hash(input);
		} finally    {
			h.dispose();
		}
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3Stream + finalize zeroes the mutable region (pre-poisoned)', () => {
		const input = makeMaterial(2048);
		const m     = mem();
		poisonMutable(m);
		expect(regionHasNonZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);

		const s = new BLAKE3Stream();
		s.update(input.subarray(0, 700));
		s.update(input.subarray(700));
		s.finalize();
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3Stream + dispose without finalize zeroes the mutable region', () => {
		const m = mem();
		poisonMutable(m);
		const s = new BLAKE3Stream();
		s.update(new Uint8Array(64));
		s.dispose();
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3KeyedHash + dispose zeroes the mutable region (including key bytes)', () => {
		const x = exports_();
		const m = mem();
		const input = makeMaterial(4096);
		const h = new BLAKE3KeyedHash();
		try        {
			h.hash(KEY_BYTES, input);
		} finally    {
			h.dispose();
		}
		// KEYED_KEY is inside the wiped region; also check the explicit
		// per-op key wipe in oneShotKeyedHash zeroed the staging slot.
		const keyOff = x.getKeyedKeyOffset();
		expect(regionIsZero(m, keyOff, 32)).toBe(true);
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3KeyedHashStream + finalize zeroes the mutable region', () => {
		const m = mem();
		poisonMutable(m);
		const input = makeMaterial(3000);
		const s = new BLAKE3KeyedHashStream(KEY_BYTES);
		s.update(input);
		s.finalize();
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3KeyedHashStream + dispose without finalize zeroes the mutable region', () => {
		const m = mem();
		poisonMutable(m);
		const s = new BLAKE3KeyedHashStream(KEY_BYTES);
		s.update(makeMaterial(128));
		s.dispose();
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3DeriveKey + dispose zeroes the mutable region (CONTEXT_CV included)', () => {
		const m = mem();
		const dk = new BLAKE3DeriveKey();
		try        {
			dk.derive(blake3ContextString, makeMaterial(1024));
		} finally    {
			dk.dispose();
		}
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3DeriveKeyStream + finalize zeroes the mutable region', () => {
		const m = mem();
		poisonMutable(m);
		const s = new BLAKE3DeriveKeyStream(blake3ContextString);
		s.update(makeMaterial(2049));
		s.finalize();
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3DeriveKeyStream + dispose without finalize zeroes the mutable region', () => {
		const m = mem();
		poisonMutable(m);
		const s = new BLAKE3DeriveKeyStream(blake3ContextString);
		s.update(makeMaterial(256));
		s.dispose();
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3OutputReader (hash) holds ROOT_STATE_* live, wipes on dispose', () => {
		const m = mem();
		const s = new BLAKE3Stream();
		s.update(makeMaterial(2048));
		const r = s.finalizeXof();
		// r.read(131) forces _populate + at least one squeezeXofBlock
		try        {
			r.read(131);
		} finally    {
			r.dispose();
		}
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3OutputReader (keyed) wipes key and mutable region on dispose', () => {
		const x = exports_();
		const m = mem();
		const s = new BLAKE3KeyedHashStream(KEY_BYTES);
		s.update(makeMaterial(1024));
		const r = s.finalizeXof();
		try        {
			r.read(200);
		} finally    {
			r.dispose();
		}
		const keyOff = x.getKeyedKeyOffset();
		expect(regionIsZero(m, keyOff, 32)).toBe(true);
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});

	it('BLAKE3OutputReader (derive) wipes context staging and mutable region on dispose', () => {
		const m = mem();
		const s = new BLAKE3DeriveKeyStream(blake3ContextString);
		s.update(makeMaterial(64));
		const r = s.finalizeXof();
		try        {
			r.read(200);
		} finally    {
			r.dispose();
		}
		expect(regionIsZero(m, MUTABLE_START, BUFFER_END - MUTABLE_START)).toBe(true);
	});
});
