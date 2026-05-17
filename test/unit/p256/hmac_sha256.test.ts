//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * Embedded HMAC-SHA-256 indirect-equivalence test. See sha256.test.ts
 * for the rationale: HMAC is not directly exposed by the p256 ABI;
 * its correctness is gated transitively by the RFC 6979 §A.2.5
 * derivation, which byte-matches the RFC's expected k values only if
 * every HMAC call in the chain produces the exact RFC-specified
 * output.
 *
 * RFC 6979 §3.2 step e is V = HMAC_K(V) starting from V = 0x01..01
 * and K = 0x00..00. The substrate's first observable HMAC output is
 * the result of step d's HMAC_K(V || 0x00 || int2octets(x) ||
 * bits2octets(h1)). The rfc6979.test.ts gate fails byte-for-byte if
 * HMAC has any bug.
 *
 * This file's role: exercise deriveKDeterministic on additional input
 * shapes beyond the §A.2.5 corpus, to catch HMAC-specific corner cases
 * (e.g. message length straddling SHA-256 block boundaries) that the
 * §A.2.5 inputs don't trigger.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { loadP256, testSlot, writeBytes, type P256Exports } from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 embedded HMAC-SHA-256 (indirect via RFC 6979)', () => {
	it('deriveK gives deterministic k for fixed (d, h1)', () => {
		wasm.wipeBuffers();
		const d = testSlot(0);
		const h = testSlot(32);
		const k1 = testSlot(64);
		const k2 = testSlot(96);

		writeBytes(wasm.memory, d, new Uint8Array(32).fill(0x42));
		const digest = createHash('sha256').update('hello').digest();
		writeBytes(wasm.memory, h, new Uint8Array(digest));

		wasm.deriveKDeterministic(d, h, k1);
		// Wipe and re-derive: same (d, h) must give same k.
		wasm.wipeBuffers();
		writeBytes(wasm.memory, d, new Uint8Array(32).fill(0x42));
		writeBytes(wasm.memory, h, new Uint8Array(digest));
		wasm.deriveKDeterministic(d, h, k2);

		const k1bytes = new Uint8Array(wasm.memory.buffer, k1, 32);
		const k2bytes = new Uint8Array(wasm.memory.buffer, k2, 32);
		for (let i = 0; i < 32; i++) {
			expect(k1bytes[i]).toBe(k2bytes[i]);
		}
	}, 30000);

	it('hedged deriveK with all-zero Z != deterministic deriveK', () => {
		// Per draft-irtf-cfrg-det-sigs-with-noise-05 §4, the hedged
		// construction zero-pads to a different HMAC input length
		// than RFC 6979 §3.2; even with Z = 0 the two derivations are
		// intentionally domain-separated and produce different k.
		wasm.wipeBuffers();
		const d = testSlot(0);
		const h = testSlot(32);
		const rnd = testSlot(64);
		const kDet = testSlot(96);
		const kHedged = testSlot(128);

		writeBytes(wasm.memory, d, new Uint8Array(32).fill(0x42));
		writeBytes(wasm.memory, h, new Uint8Array(32).fill(0x33));
		writeBytes(wasm.memory, rnd, new Uint8Array(32));  // all-zero Z

		wasm.deriveKDeterministic(d, h, kDet);
		wasm.deriveKHedged(d, h, rnd, kHedged);

		const kDetView = new Uint8Array(wasm.memory.buffer, kDet, 32);
		const kHedgedView = new Uint8Array(wasm.memory.buffer, kHedged, 32);
		let diff = 0;
		for (let i = 0; i < 32; i++) diff |= kDetView[i] ^ kHedgedView[i];
		expect(diff).not.toBe(0);
	}, 30000);
});
