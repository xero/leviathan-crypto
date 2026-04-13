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
import { init, MlKem512, MlKem768, MlKem1024, isInitialized } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';

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

// GATE — ML-KEM init system: FIPS 203 ML-KEM-768

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

// GATE — ML-KEM-768 IND-CPA keygen: NIST ACVP ML-KEM-keyGen-FIPS203
// Vector: kyber_keygen.ts[ml_kem_768_keygen[0]]

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

// GATE — ML-KEM IND-CPA keygen all param sets: NIST ACVP ML-KEM-keyGen-FIPS203
// Vector: kyber_keygen.ts[ml_kem_512_keygen[0]]

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

// GATE — ML-KEM encapsulation all param sets: NIST ACVP ML-KEM-encapDecap-FIPS203
// Vector: kyber_encapdecap.ts[ml_kem_512_encap[0]]

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

// GATE — ML-KEM valid decapsulation: NIST ACVP ML-KEM-encapDecap-FIPS203
// Vector: kyber_encapdecap.ts[ml_kem_512_decap_val[0]]

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

// GATE — ML-KEM implicit rejection: NIST ACVP ML-KEM-encapDecap-FIPS203
// Vector: kyber_encapdecap.ts[ml_kem_512_decap_val[0]]

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

// GATE — ML-KEM encapsulation key validation: NIST ACVP ML-KEM-encapDecap-FIPS203
// Vector: kyber_encapdecap.ts[ml_kem_512_encap_key_check[0]]

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

// GATE — ML-KEM decapsulation key validation: NIST ACVP ML-KEM-encapDecap-FIPS203
// Vector: kyber_encapdecap.ts[ml_kem_512_decap_key_check[0]]

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

// GATE — ML-KEM round-trip property: deterministic keygen/encap/decap

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

// GATE — ML-KEM implicit rejection property: flip one ciphertext byte

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

// ── FIPS 203 §7.2 / §7.3 auto-validation in MlKemBase.encapsulate/decapsulate ──

/**
 * Return a copy of ek with coefficient 0 of the first polynomial set to `coeff`.
 * Preserves coefficient 1 (and the rest of the ek). The 12-bit value `coeff`
 * is packed as: byte0 = coeff & 0xFF; byte1 low nibble = (coeff >> 8) & 0x0F.
 * byte1 high nibble is coefficient 1's low 4 bits — left untouched.
 */
function patchCoeff0(ek: Uint8Array, coeff: number): Uint8Array {
	if (coeff < 0 || coeff > 0xFFF) throw new Error('coeff out of 12-bit range');
	const out = ek.slice();
	out[0] = coeff & 0xFF;
	out[1] = (out[1] & 0xF0) | ((coeff >> 8) & 0x0F);
	return out;
}

describe('FIPS 203 §7.2 — encapsulate auto-validates ek', () => {
	beforeAll(async () => {
		_resetForTesting();
		const kyberBytes = readFileSync(join(__dirname, '../../../build/kyber.wasm'));
		const sha3Bytes  = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
		await init({ kyber: kyberBytes, sha3: sha3Bytes });
	});

	it('patchCoeff0 round-trips through polyvec_frombytes (sanity)', () => {
		// Decode the patched ek's polyvec and assert coefficient 0 equals the
		// patched value. Catches accidental bit-twiddling in the patch helper.
		const kem = new MlKem768();
		const { encapsulationKey: ek } = kem.keygen();
		const patched = patchCoeff0(ek, 3329);

		const pvOff = kx.getPolyvecSlot0();
		const pkOff = kx.getPkOffset();
		const mem   = new Uint8Array(kx.memory.buffer);
		mem.set(patched.subarray(0, MLKEM768.k * 384), pkOff);
		kx.polyvec_frombytes(pvOff, pkOff, MLKEM768.k);
		const coeff0 = new DataView(kx.memory.buffer).getInt16(pvOff, true);
		expect(coeff0).toBe(3329);
	});

	it('valid ek → encapsulate succeeds through the new validation path', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const { ciphertext, sharedSecret: K1 } = kem.encapsulate(ek);
		const K2 = kem.decapsulate(dk, ciphertext);
		expect(toHex(K1)).toBe(toHex(K2));
	});

	it('ML-KEM-512 coeff=Q rejected → encapsulate throws §7.2', () => {
		const kem = new MlKem512();
		const { encapsulationKey: ek } = kem.keygen();
		const bad = patchCoeff0(ek, 3329);
		expect(kem.checkEncapsulationKey(bad)).toBe(false);
		expect(() => kem.encapsulate(bad)).toThrow(RangeError);
		expect(() => kem.encapsulate(bad)).toThrow(/FIPS 203 §7\.2/);
	});

	it('ML-KEM-768 coeff=Q rejected → encapsulate throws §7.2', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek } = kem.keygen();
		const bad = patchCoeff0(ek, 3329);
		expect(kem.checkEncapsulationKey(bad)).toBe(false);
		expect(() => kem.encapsulate(bad)).toThrow(RangeError);
		expect(() => kem.encapsulate(bad)).toThrow(/FIPS 203 §7\.2/);
	});

	it('ML-KEM-1024 coeff=Q rejected → encapsulate throws §7.2', () => {
		const kem = new MlKem1024();
		const { encapsulationKey: ek } = kem.keygen();
		const bad = patchCoeff0(ek, 3329);
		expect(kem.checkEncapsulationKey(bad)).toBe(false);
		expect(() => kem.encapsulate(bad)).toThrow(RangeError);
		expect(() => kem.encapsulate(bad)).toThrow(/FIPS 203 §7\.2/);
	});

	it('boundary: coeff=Q-1 (3328) accepted — strict < check', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const patched = patchCoeff0(ek, 3328);
		// The patched ek has a different coefficient 0 than keygen produced, so the
		// dk's embedded polyvec won't match for a full round-trip. But §7.2 only
		// validates the ek, and encapsulate must succeed without throwing.
		expect(kem.checkEncapsulationKey(patched)).toBe(true);
		expect(() => kem.encapsulate(patched)).not.toThrow();
		// unused variable silenced — dk is only needed for a round-trip which
		// this boundary test intentionally does not exercise.
		void dk;
	});

	it('boundary: coeff=4095 (max 12-bit) rejected — upper bound sanity', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek } = kem.keygen();
		const bad = patchCoeff0(ek, 4095);
		expect(kem.checkEncapsulationKey(bad)).toBe(false);
		expect(() => kem.encapsulate(bad)).toThrow(/FIPS 203 §7\.2/);
	});

	it('invalid ek (short length) → encapsulate throws RangeError', () => {
		const kem = new MlKem768();
		const shortEk = new Uint8Array(100);
		expect(() => kem.encapsulate(shortEk)).toThrow(RangeError);
		expect(() => kem.encapsulate(shortEk)).toThrow(/encapsulation key must be/);
	});

	it('ACVP wrong-length vector (ML-KEM-768) → encapsulate throws RangeError via length gate', () => {
		// ACVP §7.2 failure vectors carry the rejection reason "noisy linear system
		// values too large" encoded at 2× ekBytes length. The length gate catches
		// them; kept here as a regression on the length-validation path.
		const bad = ml_kem_768_encap_key_check.find(v => !v.testPassed);
		expect(bad).toBeDefined();
		const ek = fromHex(bad!.ek);

		const kem = new MlKem768();
		expect(kem.checkEncapsulationKey(ek)).toBe(false);
		expect(() => kem.encapsulate(ek)).toThrow(RangeError);
	});

	it('ACVP wrong-length vector (ML-KEM-512) → encapsulate throws', () => {
		const bad = ml_kem_512_encap_key_check.find(v => !v.testPassed);
		const ek = fromHex(bad!.ek);
		const kem = new MlKem512();
		expect(() => kem.encapsulate(ek)).toThrow(RangeError);
	});

	it('ACVP wrong-length vector (ML-KEM-1024) → encapsulate throws', () => {
		const bad = ml_kem_1024_encap_key_check.find(v => !v.testPassed);
		const ek = fromHex(bad!.ek);
		const kem = new MlKem1024();
		expect(() => kem.encapsulate(ek)).toThrow(RangeError);
	});

	it('checkEncapsulationKey(bad_ek) is side-effect-free (does not throw)', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek } = kem.keygen();
		const bad = patchCoeff0(ek, 3329);

		// probe API returns false without throwing
		expect(() => kem.checkEncapsulationKey(bad)).not.toThrow();
		expect(kem.checkEncapsulationKey(bad)).toBe(false);
	});
});

describe('FIPS 203 §7.3 — decapsulate auto-validates dk', () => {
	beforeAll(async () => {
		_resetForTesting();
		const kyberBytes = readFileSync(join(__dirname, '../../../build/kyber.wasm'));
		const sha3Bytes  = readFileSync(join(__dirname, '../../../build/sha3.wasm'));
		await init({ kyber: kyberBytes, sha3: sha3Bytes });
	});

	it('valid dk → decapsulate succeeds', () => {
		const kem = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const { ciphertext, sharedSecret: K1 } = kem.encapsulate(ek);
		const K2 = kem.decapsulate(dk, ciphertext);
		expect(toHex(K1)).toBe(toHex(K2));
	});

	it('invalid dk (ACVP §7.3 failure vector — modified H) → decapsulate throws with §7.3 message', () => {
		// "modified H" = embedded H(ek) no longer matches — §7.3 reject. dk length is correct.
		const bad = ml_kem_768_decap_key_check.find(
			v => !v.testPassed && v.dk.length / 2 === MLKEM768.dkBytes,
		);
		expect(bad).toBeDefined();
		const dk = fromHex(bad!.dk);

		const kem = new MlKem768();
		expect(kem.checkDecapsulationKey(dk)).toBe(false);

		// Use a ctBytes-length array to satisfy the length check; §7.3 validation fires after.
		const ct = new Uint8Array(MLKEM768.ctBytes);
		expect(() => kem.decapsulate(dk, ct)).toThrow(/FIPS 203 §7\.3/);
		expect(() => kem.decapsulate(dk, ct)).toThrow(RangeError);
	});

	it('invalid dk (short length) → decapsulate throws RangeError (length check fires first)', () => {
		const kem = new MlKem768();
		const shortDk = new Uint8Array(100);
		const ct = new Uint8Array(MLKEM768.ctBytes);
		expect(() => kem.decapsulate(shortDk, ct)).toThrow(RangeError);
		expect(() => kem.decapsulate(shortDk, ct)).toThrow(/decapsulation key must be/);
	});

	it('ML-KEM-512 invalid dk → decapsulate throws §7.3', () => {
		const bad = ml_kem_512_decap_key_check.find(
			v => !v.testPassed && v.dk.length / 2 === MLKEM512.dkBytes,
		);
		const dk = fromHex(bad!.dk);
		const ct = new Uint8Array(MLKEM512.ctBytes);
		const kem = new MlKem512();
		expect(() => kem.decapsulate(dk, ct)).toThrow(/FIPS 203 §7\.3/);
	});

	it('ML-KEM-1024 invalid dk → decapsulate throws §7.3', () => {
		const bad = ml_kem_1024_decap_key_check.find(
			v => !v.testPassed && v.dk.length / 2 === MLKEM1024.dkBytes,
		);
		const dk = fromHex(bad!.dk);
		const ct = new Uint8Array(MLKEM1024.ctBytes);
		const kem = new MlKem1024();
		expect(() => kem.decapsulate(dk, ct)).toThrow(/FIPS 203 §7\.3/);
	});

	it('dk with modulus-bad embedded ek (H recomputed) → decapsulate throws §7.3', () => {
		// Without a direct polyvec_modulus_check, this case would slip past §7.3:
		// the H-binding check passes on a length-valid ek, and the recursive
		// §7.2 check is inert against length-valid-but-modulus-bad inputs.
		// The direct modulus scan closes that gap.
		const kem = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const { ciphertext } = kem.encapsulate(ek);
		const { skCpaBytes, ekBytes } = MLKEM768;

		const embeddedBad = patchCoeff0(
			dk.slice(skCpaBytes, skCpaBytes + ekBytes),
			3329,
		);
		const hNew = sha3_256Hash(sx, embeddedBad);

		const dkBad = dk.slice();
		dkBad.set(embeddedBad, skCpaBytes);
		dkBad.set(hNew, skCpaBytes + ekBytes);

		expect(() => kem.decapsulate(dkBad, ciphertext)).toThrow(/FIPS 203 §7\.3/);
	});
});
