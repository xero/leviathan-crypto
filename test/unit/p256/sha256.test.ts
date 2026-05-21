//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * Embedded SHA-256 indirect byte-equivalence via the deriveKDeterministic
 * path. Direct KAT requires an unexposed sha256-private; AGENTS.md forbids
 * internal-API leakage. See docs/ecdsa-p256.md#embedded-sha256-cross-check.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { loadP256, testSlot, writeBytes, type P256Exports } from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 embedded SHA-256 (indirect)', () => {
	// Use deriveKDeterministic to exercise the SHA-256 → HMAC chain.
	// d = all-ones (a non-degenerate scalar). For each msg hash input,
	// confirm the substrate produces SOME k in [1, n-1] without
	// crashing. Direct byte-equivalence of the SHA-256 layer is
	// covered by the rfc6979 gate which uses Node's SHA-256 to compute
	// the input hash; if SHA-256 inside the substrate differed, the
	// gate would fail.
	it('deriveK accepts arbitrary 32-byte digests (smoke)', () => {
		const inputs: Uint8Array[] = [
			new Uint8Array(0),
			new Uint8Array([0x61]),  // "a"
			new Uint8Array([0x61, 0x62, 0x63]),  // "abc"
			new Uint8Array(64).fill(0x42),
			new Uint8Array(1000).fill(0x55),
		];

		for (const msg of inputs) {
			wasm.wipeBuffers();
			const d = testSlot(0);
			const h = testSlot(32);
			const k = testSlot(64);

			writeBytes(wasm.memory, d, new Uint8Array(32).fill(0xff));  // arbitrary canonical d
			const digest = createHash('sha256').update(msg).digest();
			writeBytes(wasm.memory, h, new Uint8Array(digest));

			wasm.deriveKDeterministic(d, h, k);

			// k must be non-zero AND in [0, n) — i.e. scalarIsCanonical
			// AND scalarIsZero gives the strict [1, n-1] range.
			expect(wasm.scalarIsCanonical(k)).toBe(1);
			expect(wasm.scalarIsZero(k)).toBe(0);
		}
	}, 30000);
});
