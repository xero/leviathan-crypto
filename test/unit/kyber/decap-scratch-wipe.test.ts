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
 * kemDecapsulate scratch-slot wipes.
 *
 * Verifies that after a successful decapsulate call, every kyber WASM
 * scratch region that held secret or secret-derived bytes during
 * indcpaDecrypt + indcpaEncrypt (re-encryption) is zeroed. Coverage:
 *
 *   - m' / K' / K̄ (32B head) / POLY_SLOT_2 / POLY_SLOT_3.
 *   - POLY_SLOT_1 full 512B (e₂ noise tail), POLYVEC_SLOT_1 (r noise
 *     polyvec, 2048B), POLYVEC_SLOT_2 (e₁ noise polyvec for u, 2048B),
 *     XOF_PRF_OFFSET (last PRF output block, 1024B).
 *   - SK_OFFSET (skCpa CPA secret key — highest-severity residual,
 *     long-lived key material; size varies per parameter set) and
 *     POLYVEC_SLOT_3 (uncompressed u polyvec from FO re-encryption,
 *     leaks coefficient low-order bits that Compress_du discards in
 *     the public ciphertext).
 *
 * Without these wipes the scratch bytes would persist in kyber linear
 * memory until the next kyber op or MlKem.dispose().
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlKem512, MlKem768, MlKem1024 } from '../../../src/ts/index.js';
import { MLKEM512, MLKEM768, MLKEM1024 } from '../../../src/ts/kyber/params.js';
import { getInstance } from '../../../src/ts/init.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';

beforeAll(async () => {
	await init({ kyber: kyberWasm, sha3: sha3Wasm });
});

interface KyberExports {
	memory: WebAssembly.Memory
	getMsgOffset:     () => number
	getPolySlot0:     () => number
	getPolySlot1:     () => number
	getPolySlot2:     () => number
	getPolySlot3:     () => number
	getPolyvecSlot1:  () => number
	getPolyvecSlot2:  () => number
	getPolyvecSlot3:  () => number
	getXofPrfOffset:  () => number
	getSkOffset:      () => number
}

function getExports(): KyberExports {
	return getInstance('kyber').exports as unknown as KyberExports;
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

function runDecap(): void {
	const kem = new MlKem768();
	const { encapsulationKey, decapsulationKey } = kem.keygen();
	const { ciphertext, sharedSecret } = kem.encapsulate(encapsulationKey);
	const recovered = kem.decapsulate(decapsulationKey, ciphertext);
	expect(recovered).toEqual(sharedSecret);
	kem.dispose();
}

describe('kemDecapsulate — scratch slots wiped after decaps', () => {
	it('MSG buffer, POLY_SLOT_0, POLY_SLOT_2, POLY_SLOT_3 are zero after decapsulate', () => {
		runDecap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);

		// MSG_OFFSET (32B) — held m' from indcpaDecrypt
		expect(regionIsZero(mem, x.getMsgOffset(), 32)).toBe(true);
		// POLY_SLOT_0 (32B of interest) — held K' after ct_cmov
		expect(regionIsZero(mem, x.getPolySlot0(), 32)).toBe(true);
		// POLY_SLOT_2 / SLOT_3 full-slot wipes: 512B each
		expect(regionIsZero(mem, x.getPolySlot2(), 512)).toBe(true);
		expect(regionIsZero(mem, x.getPolySlot3(), 512)).toBe(true);
	});

	it('POLY_SLOT_1 is fully zero — K̄ head + e₂ noise tail', () => {
		// The e₂ noise polynomial lives in POLY_SLOT_1[0..512] during
		// indcpaEncrypt; the whole 512-byte slot must be zeroed, not just
		// the K̄ head.
		runDecap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolySlot1(), 512)).toBe(true);
	});

	it('POLYVEC_SLOT_1 is zero — r noise polyvec residual', () => {
		runDecap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot1(), 2048)).toBe(true);
	});

	it('POLYVEC_SLOT_2 is zero — e₁ noise polyvec residual', () => {
		runDecap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot2(), 2048)).toBe(true);
	});

	it('XOF_PRF_OFFSET is zero — last PRF output block', () => {
		runDecap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getXofPrfOffset(), 1024)).toBe(true);
	});

	it('POLYVEC_SLOT_3 is zero — uncompressed u polyvec residual', () => {
		// indcpaEncrypt (the FO re-encryption step) writes invNTT(Â^T·r̂) + e₁
		// reduced into POLYVEC_SLOT_3 as the uncompressed u polyvec. The
		// ciphertext ships Compress_du(u) which is lossy for du ∈ {10, 11};
		// the uncompressed u retains low-order coefficient bits the public
		// ciphertext does not. Wiping closes that leakage channel.
		runDecap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot3(), 2048)).toBe(true);
	});

	// SK_OFFSET wipe size is parameter-set-dependent (skCpaBytes). Running
	// each parameter set verifies the correct per-set range gets zeroed and
	// catches a regression where e.g. a hard-coded 1152 (ML-KEM-768) would
	// pass for 768 but leave bytes resident on 1024.
	describe('SK_OFFSET (skCpa CPA secret key) wipe', () => {
		const cases: {
			name: string;
			make: () => MlKem512 | MlKem768 | MlKem1024;
			skBytes: number;
		}[] = [
			{ name: 'ML-KEM-512',  make: () => new MlKem512(),  skBytes: MLKEM512.skCpaBytes  },
			{ name: 'ML-KEM-768',  make: () => new MlKem768(),  skBytes: MLKEM768.skCpaBytes  },
			{ name: 'ML-KEM-1024', make: () => new MlKem1024(), skBytes: MLKEM1024.skCpaBytes },
		];

		for (const { name, make, skBytes } of cases) {
			it(`after successful decapsulate, SK_OFFSET is zero (${name}, ${skBytes} bytes)`, () => {
				const kem = make();
				const { encapsulationKey, decapsulationKey } = kem.keygen();
				const { ciphertext, sharedSecret } = kem.encapsulate(encapsulationKey);
				const recovered = kem.decapsulate(decapsulationKey, ciphertext);
				expect(recovered).toEqual(sharedSecret);

				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getSkOffset(), skBytes)).toBe(true);

				kem.dispose();
			});
		}
	});
});
