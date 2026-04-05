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
// test/unit/kyber/mlkem.test.ts
//
// ML-KEM ACVP validation suite — 10 gates: Gate 0 init system, Gates 1-9 ACVP vectors.
// Gates 1-9 load build/kyber.wasm and build/sha3.wasm directly (no init() system).
// Gate 0 validates the standard init() integration path.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import { loadKyber, loadSha3, fromHex, toHex } from './helpers.js';
import { indcpaKeypairDerand, sha3_256Hash } from '../../../src/ts/kyber/indcpa.js';
import { kemKeypairDerand, kemEncapsulateDerand, kemDecapsulate } from '../../../src/ts/kyber/kem.js';
import { checkEncapsulationKey, checkDecapsulationKey } from '../../../src/ts/kyber/validate.js';
import { MLKEM512, MLKEM768, MLKEM1024 } from '../../../src/ts/kyber/params.js';
import { init, MlKem768, isInitialized, _resetForTesting } from '../../../src/ts/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import {
	ml_kem_512_keygen,
	ml_kem_768_keygen,
	ml_kem_1024_keygen,
	ml_kem_512_encap,
	ml_kem_768_encap,
	ml_kem_1024_encap,
	ml_kem_512_decap_val,
	ml_kem_768_decap_val,
	ml_kem_1024_decap_val,
	ml_kem_512_decap_key_check,
	ml_kem_512_encap_key_check,
	ml_kem_768_decap_key_check,
	ml_kem_768_encap_key_check,
	ml_kem_1024_decap_key_check,
	ml_kem_1024_encap_key_check,
} from '../../vectors/kyber.js';
import type { KyberExports, Sha3Exports } from '../../../src/ts/kyber/types.js';
import type { KyberParams } from '../../../src/ts/kyber/params.js';

// ── Gate 0 — init system wiring ───────────────────────────────────────────────

describe('Gate 0 — init system wiring', () => {
	beforeAll(async () => {
		_resetForTesting();
		const kyberBytes = readFileSync(join(__dirname, '../../../build/kyber.wasm'));
		const sha3Bytes  = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
		await init({ kyber: kyberBytes, sha3: sha3Bytes });
	});

	it('kyber module initialized', () => {
		expect(isInitialized('kyber')).toBe(true);
	});

	it('sha3 module initialized', () => {
		expect(isInitialized('sha3')).toBe(true);
	});

	it('MlKem768 constructs without arguments', () => {
		const kem = new MlKem768();
		expect(kem).toBeDefined();
	});

	it('round-trip via init-backed classes', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const { ciphertext: c, sharedSecret: K1 } = kem.encapsulate(ek);
		const K2 = kem.decapsulate(dk, c);
		expect(toHex(K1)).toBe(toHex(K2));
	});
});

// ── Shared WASM instances (Gates 1-9) ────────────────────────────────────────

let kx: KyberExports;
let sx: Sha3Exports;

beforeAll(async () => {
	kx = await loadKyber();
	sx = await loadSha3();
});

// ── Gate 1 — IND-CPA keygen (ML-KEM-768 only, 25 vectors) ────────────────────

describe('Gate 1 — IND-CPA keygen ML-KEM-768', () => {
	it.each(ml_kem_768_keygen)('tcId=$tcId', ({ tcId: _tcId, d, z, ek, dk }) => {
		const dBytes = fromHex(d);
		const zBytes = fromHex(z);
		const expectedEk = fromHex(ek);
		const expectedDk = fromHex(dk);

		// IND-CPA keygen uses only d (not z)
		const { ekCpa, skCpa } = indcpaKeypairDerand(kx, sx, MLKEM768, dBytes);

		// Assemble full dk = skCpa || ek || H(ek) || z
		const h = sha3_256Hash(sx, ekCpa);
		const dkFull = new Uint8Array(MLKEM768.dkBytes);
		dkFull.set(skCpa, 0);
		dkFull.set(ekCpa, MLKEM768.skCpaBytes);
		dkFull.set(h, MLKEM768.skCpaBytes + MLKEM768.ekBytes);
		dkFull.set(zBytes, MLKEM768.skCpaBytes + MLKEM768.ekBytes + 32);

		expect(toHex(ekCpa)).toBe(toHex(expectedEk));
		expect(toHex(dkFull)).toBe(toHex(expectedDk));
	});
});

// ── Gate 2 — IND-CPA keygen all param sets (75 vectors) ──────────────────────

describe('Gate 2 — IND-CPA keygen all param sets', () => {
	function runKeygen(vectors: typeof ml_kem_512_keygen, params: KyberParams) {
		it.each(vectors)('tcId=$tcId', ({ tcId: _tcId, d, z, ek, dk }) => {
			const dBytes = fromHex(d);
			const zBytes = fromHex(z);
			const expectedEk = fromHex(ek);
			const expectedDk = fromHex(dk);

			const { ekCpa, skCpa } = indcpaKeypairDerand(kx, sx, params, dBytes);

			const h = sha3_256Hash(sx, ekCpa);
			const dkFull = new Uint8Array(params.dkBytes);
			dkFull.set(skCpa, 0);
			dkFull.set(ekCpa, params.skCpaBytes);
			dkFull.set(h, params.skCpaBytes + params.ekBytes);
			dkFull.set(zBytes, params.skCpaBytes + params.ekBytes + 32);

			expect(toHex(ekCpa)).toBe(toHex(expectedEk));
			expect(toHex(dkFull)).toBe(toHex(expectedDk));
		});
	}

	describe('ML-KEM-512', () => {
		runKeygen(ml_kem_512_keygen, MLKEM512);
	});
	describe('ML-KEM-768', () => {
		runKeygen(ml_kem_768_keygen, MLKEM768);
	});
	describe('ML-KEM-1024', () => {
		runKeygen(ml_kem_1024_keygen, MLKEM1024);
	});
});

// ── Gate 3 — Encapsulation all param sets (75 vectors) ───────────────────────

describe('Gate 3 — Encapsulation all param sets', () => {
	function runEncap(vectors: typeof ml_kem_512_encap, params: KyberParams) {
		it.each(vectors)('tcId=$tcId', ({ tcId: _tcId, ek, c, k, m }) => {
			const ekBytes = fromHex(ek);
			const mBytes  = fromHex(m);
			const expectedC = fromHex(c);
			const expectedK = fromHex(k);

			const { ciphertext, sharedSecret } = kemEncapsulateDerand(kx, sx, params, ekBytes, mBytes);

			expect(toHex(ciphertext)).toBe(toHex(expectedC));
			expect(toHex(sharedSecret)).toBe(toHex(expectedK));
		});
	}

	describe('ML-KEM-512',  () => {
		runEncap(ml_kem_512_encap,  MLKEM512);
	});
	describe('ML-KEM-768',  () => {
		runEncap(ml_kem_768_encap,  MLKEM768);
	});
	describe('ML-KEM-1024', () => {
		runEncap(ml_kem_1024_encap, MLKEM1024);
	});
});

// ── Gate 4 — Decapsulation valid (15 vectors) ─────────────────────────────────

describe('Gate 4 — Decapsulation valid', () => {
	function runDecapValid(vectors: typeof ml_kem_512_decap_val, params: KyberParams) {
		const valid = vectors.filter(v => v.reason === 'valid decapsulation');
		it.each(valid)('tcId=$tcId', ({ tcId: _tcId, dk, c, k }) => {
			const dkBytes = fromHex(dk);
			const cBytes  = fromHex(c);
			const expectedK = fromHex(k);

			const sharedSecret = kemDecapsulate(kx, sx, params, dkBytes, cBytes);

			expect(toHex(sharedSecret)).toBe(toHex(expectedK));
		});
	}

	describe('ML-KEM-512',  () => {
		runDecapValid(ml_kem_512_decap_val,  MLKEM512);
	});
	describe('ML-KEM-768',  () => {
		runDecapValid(ml_kem_768_decap_val,  MLKEM768);
	});
	describe('ML-KEM-1024', () => {
		runDecapValid(ml_kem_1024_decap_val, MLKEM1024);
	});
});

// ── Gate 5 — Decapsulation implicit rejection (15 vectors) ────────────────────
// CRITICAL: modified ciphertext must produce J(z||c) NOT the actual shared secret.

describe('Gate 5 — Decapsulation implicit rejection', () => {
	function runDecapReject(vectors: typeof ml_kem_512_decap_val, params: KyberParams) {
		const modified = vectors.filter(v => v.reason === 'modified ciphertext');
		it.each(modified)('tcId=$tcId', ({ tcId: _tcId, dk, c, k }) => {
			const dkBytes = fromHex(dk);
			const cBytes  = fromHex(c);
			const expectedK = fromHex(k);

			const sharedSecret = kemDecapsulate(kx, sx, params, dkBytes, cBytes);

			// Must return the implicit rejection value K̄ = J(z||c), not any secret
			expect(toHex(sharedSecret)).toBe(toHex(expectedK));
		});
	}

	describe('ML-KEM-512',  () => {
		runDecapReject(ml_kem_512_decap_val,  MLKEM512);
	});
	describe('ML-KEM-768',  () => {
		runDecapReject(ml_kem_768_decap_val,  MLKEM768);
	});
	describe('ML-KEM-1024', () => {
		runDecapReject(ml_kem_1024_decap_val, MLKEM1024);
	});
});

// ── Gate 6 — Encapsulation key validation (30 vectors) ───────────────────────

describe('Gate 6 — Encapsulation key validation', () => {
	function runEncapKeyCheck(vectors: typeof ml_kem_512_encap_key_check, params: KyberParams) {
		it.each(vectors)('tcId=$tcId testPassed=$testPassed', ({ tcId: _tcId, testPassed, ek }) => {
			const ekBytes = fromHex(ek);
			const result = checkEncapsulationKey(kx, params, ekBytes);
			expect(result).toBe(testPassed);
		});
	}

	describe('ML-KEM-512',  () => {
		runEncapKeyCheck(ml_kem_512_encap_key_check,  MLKEM512);
	});
	describe('ML-KEM-768',  () => {
		runEncapKeyCheck(ml_kem_768_encap_key_check,  MLKEM768);
	});
	describe('ML-KEM-1024', () => {
		runEncapKeyCheck(ml_kem_1024_encap_key_check, MLKEM1024);
	});
});

// ── Gate 7 — Decapsulation key validation (30 vectors) ───────────────────────

describe('Gate 7 — Decapsulation key validation', () => {
	function runDecapKeyCheck(vectors: typeof ml_kem_512_decap_key_check, params: KyberParams) {
		it.each(vectors)('tcId=$tcId testPassed=$testPassed', ({ tcId: _tcId, testPassed, dk }) => {
			const dkBytes = fromHex(dk);
			const result = checkDecapsulationKey(kx, sx, params, dkBytes);
			expect(result).toBe(testPassed);
		});
	}

	describe('ML-KEM-512',  () => {
		runDecapKeyCheck(ml_kem_512_decap_key_check,  MLKEM512);
	});
	describe('ML-KEM-768',  () => {
		runDecapKeyCheck(ml_kem_768_decap_key_check,  MLKEM768);
	});
	describe('ML-KEM-1024', () => {
		runDecapKeyCheck(ml_kem_1024_decap_key_check, MLKEM1024);
	});
});

// ── Gate 8 — Round-trip property test (10 iterations × 3 param sets) ─────────
// Random keygen → encap → decap. Shared secrets must match.

describe('Gate 8 — Round-trip property', () => {
	function runRoundTrip(params: KyberParams, label: string) {
		describe(label, () => {
			// Use deterministic seeds derived from iteration index
			for (let i = 0; i < 10; i++) {
				it(`iteration ${i}`, () => {
					// Deterministic seeds: fill with iteration index pattern
					const d = new Uint8Array(32).fill(i * 7 + 1);
					const z = new Uint8Array(32).fill(i * 13 + 3);
					const m = new Uint8Array(32).fill(i * 19 + 5);

					const { encapsulationKey: ek, decapsulationKey: dk } =
						kemKeypairDerand(kx, sx, params, d, z);

					const { ciphertext: c, sharedSecret: K1 } =
						kemEncapsulateDerand(kx, sx, params, ek, m);

					const K2 = kemDecapsulate(kx, sx, params, dk, c);

					expect(toHex(K1)).toBe(toHex(K2));
				});
			}
		});
	}

	runRoundTrip(MLKEM512,  'ML-KEM-512');
	runRoundTrip(MLKEM768,  'ML-KEM-768');
	runRoundTrip(MLKEM1024, 'ML-KEM-1024');
});

// ── Gate 9 — Implicit rejection property test ─────────────────────────────────
// Flip one ciphertext byte → decap must return something != the real shared secret.

describe('Gate 9 — Implicit rejection property', () => {
	function runRejection(params: KyberParams, label: string) {
		describe(label, () => {
			for (let i = 0; i < 5; i++) {
				it(`iteration ${i}`, () => {
					const d = new Uint8Array(32).fill(i * 11 + 2);
					const z = new Uint8Array(32).fill(i * 17 + 4);
					const m = new Uint8Array(32).fill(i * 23 + 6);

					const { encapsulationKey: ek, decapsulationKey: dk } =
						kemKeypairDerand(kx, sx, params, d, z);

					const { ciphertext: c, sharedSecret: K } =
						kemEncapsulateDerand(kx, sx, params, ek, m);

					// Corrupt the ciphertext
					const cBad = c.slice();
					cBad[0] ^= 0xFF;

					const KBad = kemDecapsulate(kx, sx, params, dk, cBad);

					// Implicit rejection: must differ from real shared secret
					expect(toHex(KBad)).not.toBe(toHex(K));
					// Must still be 32 bytes
					expect(KBad.length).toBe(32);
				});
			}
		});
	}

	runRejection(MLKEM512,  'ML-KEM-512');
	runRejection(MLKEM768,  'ML-KEM-768');
	runRejection(MLKEM1024, 'ML-KEM-1024');
});
