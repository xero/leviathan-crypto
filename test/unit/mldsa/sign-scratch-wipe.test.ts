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
 * mldsaSignInternal — scratch-region wipes after sign.
 *
 * Verifies that after `MlDsa*.sign(...)` (or signDeterministic / signDerand)
 * returns, every mldsa WASM scratch region that held secret or
 * secret-derived bytes during signing is zeroed.
 *
 * Severity ranking of residuals to guard against:
 *   (a) ŝ₁ / ŝ₂ / t̂₀ in NTT/tomont form (slots 0/1/2) — full secret-key state
 *       in NTT representation; recovers s₁/s₂/t₀ via inverse NTT.
 *   (b) y / cs₁ / cs₂ / ct₀ / w − cs₂ (slots 3/4/5) — per-iteration
 *       secret-derived intermediates. y leak compromises the rejection-
 *       sampling state; cs₁/cs₂ leak relate to challenge × secret products.
 *   (c) POLY_SLOT_7 — accumulator scratch from polyvec_pointwise_acc
 *       (matrix-vector product); holds last partial product across y_ntt.
 *   (d) XOF/PRF region — last expandMask output (ρ''-derived) on a
 *       rejected iteration, or sample_in_ball position bytes (c̃-derived,
 *       public) on the accepted iteration; wipe regardless for hygiene.
 *
 * Public regions allowed to retain content: SIG_OFFSET (signature is
 * public; we wipe nothing here so the slice stays valid until copied
 * out), MATRIX_SLOT (Â — public).
 *
 * GATE: ML-DSA sign scratch-wipe.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlDsa44, MlDsa65, MlDsa87 } from '../../../src/ts/index.js';
import { _resetForTesting, getInstance } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/params.js';

beforeAll(async () => {
	_resetForTesting();
	// sha2 is loaded so the HashML-DSA SHA-2 prehash branch is reachable
	// from this scratch-wipe suite; pure-ML-DSA sign tests don't touch sha2.
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm });
});

interface MldsaMem {
	memory:             WebAssembly.Memory
	getPolySlotBase:    () => number
	getPolyvecSlotBase: () => number
	getPolyvecSlotSize: () => number
	getPolyvecSlot0:    () => number
	getPolyvecSlot1:    () => number
	getPolyvecSlot2:    () => number
	getPolyvecSlot3:    () => number
	getPolyvecSlot4:    () => number
	getPolyvecSlot5:    () => number
	getXofPrfOffset:    () => number
	getSeedOffset:      () => number
	getTrOffset:        () => number
	getSkOffset:        () => number
	getCTildeOffset:    () => number
	getMsgRepOffset:    () => number
}

function getExports(): MldsaMem {
	return getInstance('mldsa').exports as unknown as MldsaMem;
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

const POLY_BYTES = 1024;

const cases = [
	{ name: 'ML-DSA-44', make: () => new MlDsa44(), k: MLDSA44.k, l: MLDSA44.l, skBytes: MLDSA44.skBytes },
	{ name: 'ML-DSA-65', make: () => new MlDsa65(), k: MLDSA65.k, l: MLDSA65.l, skBytes: MLDSA65.skBytes },
	{ name: 'ML-DSA-87', make: () => new MlDsa87(), k: MLDSA87.k, l: MLDSA87.l, skBytes: MLDSA87.skBytes },
];

describe('mldsaSignInternal — scratch slots wiped after sign', () => {
	for (const { name, make, k, l, skBytes } of cases) {
		describe(name, () => {
			it('POLYVEC_SLOTS 0..5 fully zeroed (ŝ₁ ŝ₂ t̂₀ y/cs₂/h cs₁/z w/w-cs₂)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					// Wipe applies the full 6-slot region; verify all 6 × 8192 bytes zeroed.
					expect(regionIsZero(mem, x.getPolyvecSlot0(), 6 * x.getPolyvecSlotSize())).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('POLY_SLOTS 0..7 fully zeroed (signs / c / acc-scratch)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getPolySlotBase(), 8 * POLY_BYTES)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('XOF_PRF_OFFSET zero (last expandMask / sample_in_ball block)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('SEED_OFFSET zero (defensive)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getSeedOffset(), 128)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('TR_OFFSET zero (defensive)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getTrOffset(), 64)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('SK_OFFSET zero (defensive)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getSkOffset(), skBytes)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('C_TILDE_OFFSET / MSG_REP_OFFSET zero (defensive)', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getCTildeOffset(), 64)).toBe(true);
					expect(regionIsZero(mem, x.getMsgRepOffset(), 64)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			// Pre-dirty + sign confirms the wipe definitively zeros the regions,
			// not just that they happen to be empty after expandA / sign body.
			it('pre-dirtied slots are wiped after sign', () => {
				const dsa = make();
				try {
					const { signingKey } = dsa.keygen();
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					mem.fill(0xa5, x.getPolyvecSlot0(),  x.getPolyvecSlot0()  + l * POLY_BYTES);
					mem.fill(0xa5, x.getPolyvecSlot1(),  x.getPolyvecSlot1()  + k * POLY_BYTES);
					mem.fill(0xa5, x.getPolyvecSlot4(),  x.getPolyvecSlot4()  + l * POLY_BYTES);
					mem.fill(0xa5, x.getXofPrfOffset(),  x.getXofPrfOffset()  + 8192);
					dsa.sign(signingKey, new Uint8Array([4, 5, 6]));
					expect(regionIsZero(mem, x.getPolyvecSlot0(), l * POLY_BYTES)).toBe(true);
					expect(regionIsZero(mem, x.getPolyvecSlot1(), k * POLY_BYTES)).toBe(true);
					expect(regionIsZero(mem, x.getPolyvecSlot4(), l * POLY_BYTES)).toBe(true);
					expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});
		});
	}

	// One spot-check exercising signDeterministic and signDerand to confirm
	// the wipe path covers all three signing entry points (sign uses random
	// rnd; signDeterministic uses zero rnd; signDerand takes an injected rnd).
	it('signDeterministic wipes scratch (ML-DSA-44)', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			dsa.signDeterministic(signingKey, new Uint8Array([7, 8]));
			const x = getExports();
			const mem = new Uint8Array(x.memory.buffer);
			expect(regionIsZero(mem, x.getPolyvecSlot0(), 6 * x.getPolyvecSlotSize())).toBe(true);
			expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
		} finally {
			dsa.dispose();
		}
	});

	it('signDerand wipes scratch (ML-DSA-44)', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			const rnd = new Uint8Array(32).fill(0x77);
			dsa.signDerand(signingKey, new Uint8Array([7, 8]), new Uint8Array(0), rnd);
			const x = getExports();
			const mem = new Uint8Array(x.memory.buffer);
			expect(regionIsZero(mem, x.getPolyvecSlot0(), 6 * x.getPolyvecSlotSize())).toBe(true);
			expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
		} finally {
			dsa.dispose();
		}
	});

	// HashML-DSA wraps the same Sign_internal so the ml-dsa scratch wipe
	// already covers signHash. The new variable in the prehash path is the
	// sha2 / sha3 module residue: signHash drives those modules with PH_M's
	// input/state, then mldsaSignInternal drives sha3 again. Confirm that
	// the post-call mldsa scratch is still zeroed end-to-end.
	for (const ph of ['SHA2-256', 'SHA3-512', 'SHAKE128'] as const) {
		it(`signHash wipes scratch (ML-DSA-44, prehash=${ph})`, () => {
			const dsa = new MlDsa44();
			try {
				const { signingKey } = dsa.keygen();
				dsa.signHash(signingKey, new Uint8Array([0xAB, 0xCD]), ph);
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot0(), 6 * x.getPolyvecSlotSize())).toBe(true);
				expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
				expect(regionIsZero(mem, x.getCTildeOffset(), 64)).toBe(true);
				expect(regionIsZero(mem, x.getMsgRepOffset(), 64)).toBe(true);
			} finally {
				dsa.dispose();
			}
		});

		it(`signHashDeterministic wipes scratch (ML-DSA-44, prehash=${ph})`, () => {
			const dsa = new MlDsa44();
			try {
				const { signingKey } = dsa.keygen();
				dsa.signHashDeterministic(signingKey, new Uint8Array([0x01]), ph);
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot0(), 6 * x.getPolyvecSlotSize())).toBe(true);
				expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
			} finally {
				dsa.dispose();
			}
		});
	}

	it('signHashDerand wipes scratch (ML-DSA-44, SHA2-512)', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygen();
			const rnd = new Uint8Array(32).fill(0x77);
			dsa.signHashDerand(signingKey, new Uint8Array([7, 8]), 'SHA2-512', new Uint8Array(0), rnd);
			const x = getExports();
			const mem = new Uint8Array(x.memory.buffer);
			expect(regionIsZero(mem, x.getPolyvecSlot0(), 6 * x.getPolyvecSlotSize())).toBe(true);
			expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
		} finally {
			dsa.dispose();
		}
	});
});
