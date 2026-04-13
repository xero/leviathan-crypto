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
 * kemKeypairDerand scratch-slot wipes.
 *
 * Verifies that after `MlKem*.keygen()` returns, every kyber WASM scratch
 * region that held secret or secret-derived bytes during the IND-CPA
 * keygen is zeroed. SK_OFFSET is the highest-severity residual: it holds
 * skCpa (the CPA secret key) packed via polyvec_tobytes; disclosure
 * compromises every ciphertext under the corresponding ek. The size is
 * parameter-set-dependent, so SK_OFFSET is exercised across all three
 * parameter sets to confirm the correct per-set range gets zeroed.
 * POLYVEC_SLOT_1/2 hold ŝ/ê in NTT domain. XOF_PRF_OFFSET holds the last
 * PRF output block from CBD sampling. POLYVEC_SLOT_3 (t̂) and
 * POLYVEC_SLOT_0 (Â rows) are public and intentionally not wiped.
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
	getPolyvecSlot1: () => number
	getPolyvecSlot2: () => number
	getXofPrfOffset: () => number
	getSkOffset:     () => number
}

function getExports(): KyberExports {
	return getInstance('kyber').exports as unknown as KyberExports;
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

describe('kemKeypairDerand — scratch slots wiped after keygen', () => {
	it('POLYVEC_SLOT_1 is zero after keygen (ŝ in NTT domain)', () => {
		const kem = new MlKem768();
		kem.keygen();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot1(), 2048)).toBe(true);

		kem.dispose();
	});

	it('POLYVEC_SLOT_2 is zero after keygen (ê in NTT domain)', () => {
		const kem = new MlKem768();
		kem.keygen();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot2(), 2048)).toBe(true);

		kem.dispose();
	});

	it('XOF_PRF_OFFSET is zero after keygen (last PRF output block)', () => {
		const kem = new MlKem768();
		kem.keygen();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getXofPrfOffset(), 1024)).toBe(true);

		kem.dispose();
	});

	// SK_OFFSET wipe size is parameter-set-dependent (skCpaBytes). Running
	// each parameter set verifies the correct per-set range gets zeroed and
	// catches a regression where a hard-coded length would pass for one set
	// but leave bytes resident on another.
	describe('SK_OFFSET (skCpa CPA secret key) wipe across parameter sets', () => {
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
			it(`after keygen, SK_OFFSET is zero (${name}, ${skBytes} bytes)`, () => {
				const kem = make();
				kem.keygen();

				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getSkOffset(), skBytes)).toBe(true);

				kem.dispose();
			});
		}
	});
});
