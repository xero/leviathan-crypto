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
 * mldsaKeygenInternal scratch-slot wipes.
 *
 * Verifies that after `MlDsa*.keygenDerand(xi)` returns, every mldsa WASM
 * scratch region that held secret or secret-derived bytes during keygen
 * is zeroed. Highest-severity residual is SEED_OFFSET — it briefly held
 * ρ′ (which expands to s₁/s₂) and K (per-message signing randomness):
 * disclosure recovers the entire signing key. The polyvec slots that
 * held s₁, s₂, ŝ₁ (NTT/Montgomery copy), t (intermediate), and t₀
 * (low-bits of t — secret-component of sk) all get wiped too. The
 * XOF/PRF buffer holds the last SHAKE256 squeeze block, which after
 * ExpandS contains ρ′-derived bytes.
 *
 * Public regions intentionally NOT wiped: PK_OFFSET (encoded pk),
 * MATRIX_SLOT (Â — public, derived from ρ which is published in pk),
 * POLYVEC_SLOT_3 (t₁ — published in pk).
 *
 * GATE: ML-DSA scratch-wipe — confirms no secret residue persists in
 * mldsa linear memory after `keygenDerand` returns.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlDsa44, MlDsa65, MlDsa87 } from '../../../src/ts/index.js';
import { _resetForTesting, getInstance } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { MLDSA44, MLDSA65, MLDSA87 } from '../../../src/ts/mldsa/params.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm });
});

interface MldsaMem {
	memory:             WebAssembly.Memory
	getSeedOffset:      () => number
	getTrOffset:        () => number
	getPolyvecSlot0:    () => number
	getPolyvecSlot1:    () => number
	getPolyvecSlot2:    () => number
	getPolyvecSlot4:    () => number
	getPolyvecSlot5:    () => number
	getXofPrfOffset:    () => number
	getSkOffset:        () => number
}

function getExports(): MldsaMem {
	return getInstance('mldsa').exports as unknown as MldsaMem;
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

const POLY_BYTES = 1024;

describe('mldsaKeygenInternal — scratch slots wiped after keygenDerand', () => {
	it('SEED_OFFSET zero (ρ ‖ ρ′ ‖ K — H output)', () => {
		const dsa = new MlDsa44();
		dsa.keygenDerand(new Uint8Array(32));
		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getSeedOffset(), 128)).toBe(true);
		dsa.dispose();
	});

	it('TR_OFFSET zero (key digest tr = H(pk, 64))', () => {
		const dsa = new MlDsa44();
		dsa.keygenDerand(new Uint8Array(32));
		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getTrOffset(), 64)).toBe(true);
		dsa.dispose();
	});

	it('XOF_PRF_OFFSET zero (last SHAKE squeeze block)', () => {
		const dsa = new MlDsa44();
		dsa.keygenDerand(new Uint8Array(32));
		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
		dsa.dispose();
	});

	// SK_OFFSET wipe size is parameter-set-dependent (skBytes). Running each
	// parameter set verifies the per-set range zeroes correctly — catches a
	// regression where a hard-coded length passes for one set but leaves
	// bytes resident on another.
	describe('polyvec scratch wipes across parameter sets', () => {
		const cases: {
			name:    string
			make:    () => MlDsa44 | MlDsa65 | MlDsa87
			k:       number
			l:       number
			skBytes: number
		}[] = [
			{ name: 'ML-DSA-44', make: () => new MlDsa44(), k: MLDSA44.k, l: MLDSA44.l, skBytes: MLDSA44.skBytes },
			{ name: 'ML-DSA-65', make: () => new MlDsa65(), k: MLDSA65.k, l: MLDSA65.l, skBytes: MLDSA65.skBytes },
			{ name: 'ML-DSA-87', make: () => new MlDsa87(), k: MLDSA87.k, l: MLDSA87.l, skBytes: MLDSA87.skBytes },
		];

		for (const { name, make, k, l, skBytes } of cases) {
			it(`${name}: POLYVEC_SLOT_0 (s₁ time-domain) zero`, () => {
				const dsa = make();
				dsa.keygenDerand(new Uint8Array(32));
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot0(), l * POLY_BYTES)).toBe(true);
				dsa.dispose();
			});

			it(`${name}: POLYVEC_SLOT_1 (s₂ time-domain) zero`, () => {
				const dsa = make();
				dsa.keygenDerand(new Uint8Array(32));
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot1(), k * POLY_BYTES)).toBe(true);
				dsa.dispose();
			});

			it(`${name}: POLYVEC_SLOT_2 (t intermediate) zero`, () => {
				const dsa = make();
				dsa.keygenDerand(new Uint8Array(32));
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot2(), k * POLY_BYTES)).toBe(true);
				dsa.dispose();
			});

			it(`${name}: POLYVEC_SLOT_4 (t₀ secret) zero`, () => {
				const dsa = make();
				dsa.keygenDerand(new Uint8Array(32));
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot4(), k * POLY_BYTES)).toBe(true);
				dsa.dispose();
			});

			it(`${name}: POLYVEC_SLOT_5 (ŝ₁ NTT/Montgomery) zero`, () => {
				const dsa = make();
				dsa.keygenDerand(new Uint8Array(32));
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot5(), l * POLY_BYTES)).toBe(true);
				dsa.dispose();
			});

			it(`${name}: SK_OFFSET zero (encoded sk, ${skBytes} bytes)`, () => {
				const dsa = make();
				dsa.keygenDerand(new Uint8Array(32));
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getSkOffset(), skBytes)).toBe(true);
				dsa.dispose();
			});
		}
	});

	// Pre-dirty + keygen confirms wipe definitively zeros the regions, not
	// just that they happen to be initial-empty. Mirrors the kyber gate
	// pattern.
	it('pre-dirtied scratch regions are wiped after keygen (ML-DSA-65)', () => {
		const dsa = new MlDsa65();
		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);

		mem.fill(0xa5, x.getSeedOffset(),    x.getSeedOffset()    + 128);
		mem.fill(0xa5, x.getXofPrfOffset(),  x.getXofPrfOffset()  + 8192);
		mem.fill(0xa5, x.getPolyvecSlot0(),  x.getPolyvecSlot0()  + MLDSA65.l * POLY_BYTES);
		mem.fill(0xa5, x.getPolyvecSlot4(),  x.getPolyvecSlot4()  + MLDSA65.k * POLY_BYTES);

		dsa.keygenDerand(new Uint8Array(32));

		expect(regionIsZero(mem, x.getSeedOffset(),   128)).toBe(true);
		expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
		expect(regionIsZero(mem, x.getPolyvecSlot0(), MLDSA65.l * POLY_BYTES)).toBe(true);
		expect(regionIsZero(mem, x.getPolyvecSlot4(), MLDSA65.k * POLY_BYTES)).toBe(true);

		dsa.dispose();
	});
});
