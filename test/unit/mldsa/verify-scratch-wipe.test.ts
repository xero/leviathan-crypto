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
 * mldsaVerifyInternal, scratch-region wipes after verify.
 *
 * Verify operates entirely on public inputs (vk, sig, M, ctx all public);
 * t̂₁·2^d, ẑ, w'_approx, h are all public-derivable. So the wipe is a
 * discipline-not-secrecy thing, but the discipline matches the keygen
 * and sign paths so reviewers don't have to special-case verify when
 * auditing the zeroize surface.
 *
 * GATE: ML-DSA verify scratch-wipe.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlDsa44, MlDsa65, MlDsa87 } from '../../../src/ts/index.js';
import { _resetForTesting, getInstance } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	_resetForTesting();
	// sha2 loaded so the HashML-DSA SHA-2 prehash branch is reachable.
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm });
});

interface MldsaMem {
	memory:             WebAssembly.Memory
	getPolySlotBase:    () => number
	getPolyvecSlotBase: () => number
	getPolyvecSlotSize: () => number
	getPolyvecSlot0:    () => number
	getXofPrfOffset:    () => number
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
	{ name: 'ML-DSA-44', make: () => new MlDsa44() },
	{ name: 'ML-DSA-65', make: () => new MlDsa65() },
	{ name: 'ML-DSA-87', make: () => new MlDsa87() },
];

describe('mldsaVerifyInternal, scratch slots wiped after verify', () => {
	for (const { name, make } of cases) {
		describe(name, () => {
			it('POLYVEC slots 0..4 wiped after successful verify', () => {
				const dsa = make();
				try {
					const { verificationKey, signingKey } = dsa.keygen();
					const msg = new Uint8Array([1, 2, 3]);
					const sig = dsa.sign(signingKey, msg);
					const ok = dsa.verify(verificationKey, msg, sig);
					expect(ok).toBe(true);
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					// Verify uses 5 polyvec slots (0..4); wipe spans the full 5 slots.
					expect(regionIsZero(mem, x.getPolyvecSlot0(), 5 * x.getPolyvecSlotSize())).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('POLY_SLOTS 0..7 zero after verify', () => {
				const dsa = make();
				try {
					const { verificationKey, signingKey } = dsa.keygen();
					const msg = new Uint8Array([4, 5, 6]);
					const sig = dsa.sign(signingKey, msg);
					dsa.verify(verificationKey, msg, sig);
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getPolySlotBase(), 8 * POLY_BYTES)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('XOF_PRF_OFFSET zero after verify', () => {
				const dsa = make();
				try {
					const { verificationKey, signingKey } = dsa.keygen();
					const msg = new Uint8Array([7, 8]);
					const sig = dsa.sign(signingKey, msg);
					dsa.verify(verificationKey, msg, sig);
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('verify returning false also wipes (tampered signature)', () => {
				const dsa = make();
				try {
					const { verificationKey, signingKey } = dsa.keygen();
					const msg = new Uint8Array([9, 10]);
					const sig = dsa.sign(signingKey, msg);
					sig[0] ^= 0xFF;  // flip first byte of c̃
					expect(dsa.verify(verificationKey, msg, sig)).toBe(false);
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getPolyvecSlot0(), 5 * x.getPolyvecSlotSize())).toBe(true);
					expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});

			it('verify on malformed hint also wipes', () => {
				const dsa = make();
				try {
					const { verificationKey, signingKey } = dsa.keygen();
					const msg = new Uint8Array([11, 12]);
					const sig = dsa.sign(signingKey, msg);
					// Set a hint cumulative-count byte beyond ω → triggers Alg 21 line 4.
					// Hint region starts after c̃ + z bytes. We don't need to be precise
					// about position, the kernel returns -1 the moment it sees the
					// invalid byte, and the early-return path still hits the wipe.
					const hintTail = sig.length - 1;
					sig[hintTail] = 0xFF;
					expect(dsa.verify(verificationKey, msg, sig)).toBe(false);
					const x = getExports();
					const mem = new Uint8Array(x.memory.buffer);
					expect(regionIsZero(mem, x.getPolyvecSlot0(), 5 * x.getPolyvecSlotSize())).toBe(true);
					expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
				} finally {
					dsa.dispose();
				}
			});
		});
	}

	// HashML-DSA verify wraps Verify_internal, same wipe coverage applies.
	// Spot-check across SHA-2 / SHA-3 / SHAKE prehashes.
	for (const ph of ['SHA2-256', 'SHA3-512', 'SHAKE256'] as const) {
		it(`verifyHash wipes scratch (ML-DSA-44, prehash=${ph})`, () => {
			const dsa = new MlDsa44();
			try {
				const { verificationKey, signingKey } = dsa.keygen();
				const msg = new Uint8Array([0xAB, 0xCD]);
				const sig = dsa.signHash(signingKey, msg, ph);
				expect(dsa.verifyHash(verificationKey, msg, sig, ph)).toBe(true);
				const x = getExports();
				const mem = new Uint8Array(x.memory.buffer);
				expect(regionIsZero(mem, x.getPolyvecSlot0(), 5 * x.getPolyvecSlotSize())).toBe(true);
				expect(regionIsZero(mem, x.getXofPrfOffset(), 8192)).toBe(true);
			} finally {
				dsa.dispose();
			}
		});
	}
});
