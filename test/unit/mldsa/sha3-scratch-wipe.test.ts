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
 * sha3 scratch-region wipes across mldsa op boundaries.
 *
 * Every public ML-DSA op that performs sha3 work (phase 4: keygen and
 * keygenDerand; phase 5+: sign, verify, etc.) calls `sx.wipeBuffers()`
 * before returning, under the `_assertNotOwned('sha3')` guard held for
 * the op's duration. After any such op returns, the sha3 module's STATE
 * (200 B @ 0), INPUT (168 B @ 209), and OUT (168 B @ 377) are all zero.
 *
 * GATE: ML-DSA cross-module SHA3 wipe — confirms keygen does not leak
 * ρ′ / K / xi-derived bytes through the SHAKE state across op boundaries.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlDsa44, MlDsa65, MlDsa87 } from '../../../src/ts/index.js';
import { _resetForTesting, getInstance } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	_resetForTesting();
	// sha2 is required for HashML-DSA SHA-2-prehash variants exercised below.
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm });
});

// sha3 buffer layout — src/asm/sha3/buffers.ts
const SHA3_STATE_OFFSET = 0;
const SHA3_STATE_LEN    = 200;
const SHA3_INPUT_OFFSET = 209;
const SHA3_INPUT_LEN    = 168;
const SHA3_OUT_OFFSET   = 377;
const SHA3_OUT_LEN      = 168;

interface Sha3Mem { memory: WebAssembly.Memory }

function sha3Mem(): Uint8Array {
	const sx = getInstance('sha3').exports as unknown as Sha3Mem;
	return new Uint8Array(sx.memory.buffer);
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

function expectSha3ScratchZero(): void {
	const mem = sha3Mem();
	expect(regionIsZero(mem, SHA3_STATE_OFFSET, SHA3_STATE_LEN)).toBe(true);
	expect(regionIsZero(mem, SHA3_INPUT_OFFSET, SHA3_INPUT_LEN)).toBe(true);
	expect(regionIsZero(mem, SHA3_OUT_OFFSET,   SHA3_OUT_LEN)).toBe(true);
}

describe('sha3 scratch wiped after every public mldsa op', () => {
	it('MlDsa44.keygen() → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		dsa.keygen();
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.keygenDerand(xi) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		dsa.keygenDerand(new Uint8Array(32));
		expectSha3ScratchZero();
		dsa.dispose();
	});

	// The sha3 scratch region is parameter-set-independent. One pass at each
	// of the larger sets confirms the wipes fire regardless of which mldsa
	// params drove the op (different k, ℓ, η values mean different SHAKE128
	// / SHAKE256 absorb counts, but the same wipe path).
	it('MlDsa65.keygen() → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa65();
		dsa.keygen();
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa87.keygen() → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa87();
		dsa.keygen();
		expectSha3ScratchZero();
		dsa.dispose();
	});

	// ── Phase-5: sign / verify wipes too ────────────────────────────────
	// Sign drives multiple SHAKE256 invocations: μ, ρ'', expandMask (per
	// iteration), c̃ (per iteration), sample_in_ball (per iteration). The
	// sha3 STATE / INPUT / OUT regions hold residue from each — wipe must
	// fire before sign returns, regardless of how many iterations the
	// rejection-sample loop ran.

	it('MlDsa44.sign(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.sign(signingKey, new Uint8Array([1, 2, 3]));
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.signDeterministic(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.signDeterministic(signingKey, new Uint8Array([4, 5, 6]));
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.signDerand(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.signDerand(signingKey, new Uint8Array([7, 8]), new Uint8Array(0), new Uint8Array(32));
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa65.sign(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa65();
		const { signingKey } = dsa.keygen();
		dsa.sign(signingKey, new Uint8Array([9, 10, 11]));
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa87.sign(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa87();
		const { signingKey } = dsa.keygen();
		dsa.sign(signingKey, new Uint8Array([12, 13, 14]));
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.verify(...) → sha3 STATE/INPUT/OUT zero (success path)', () => {
		const dsa = new MlDsa44();
		const { verificationKey, signingKey } = dsa.keygen();
		const msg = new Uint8Array([15, 16]);
		const sig = dsa.sign(signingKey, msg);
		expect(dsa.verify(verificationKey, msg, sig)).toBe(true);
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.verify(...) → sha3 STATE/INPUT/OUT zero (failure path)', () => {
		const dsa = new MlDsa44();
		const { verificationKey, signingKey } = dsa.keygen();
		const msg = new Uint8Array([17, 18]);
		const sig = dsa.sign(signingKey, msg);
		sig[0] ^= 1;
		expect(dsa.verify(verificationKey, msg, sig)).toBe(false);
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa65.verify(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa65();
		const { verificationKey, signingKey } = dsa.keygen();
		const msg = new Uint8Array([19, 20]);
		const sig = dsa.sign(signingKey, msg);
		dsa.verify(verificationKey, msg, sig);
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa87.verify(...) → sha3 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa87();
		const { verificationKey, signingKey } = dsa.keygen();
		const msg = new Uint8Array([21, 22]);
		const sig = dsa.sign(signingKey, msg);
		dsa.verify(verificationKey, msg, sig);
		expectSha3ScratchZero();
		dsa.dispose();
	});

	// ── Phase-6: HashML-DSA cross-module wipes ──────────────────────────────
	// SHA-3 and SHAKE prehash directly drive the sha3 module before
	// mldsaSignInternal runs; sha3 STATE/INPUT/OUT must still be clean
	// after the public op returns. SHA-2 prehash leaves sha3 untouched
	// during the prehash phase, then mldsa drives sha3 normally.

	it('MlDsa44.signHash(... SHA3-256) → sha3 zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.signHash(signingKey, new Uint8Array([1, 2, 3]), 'SHA3-256');
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.signHash(... SHAKE128) → sha3 zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.signHash(signingKey, new Uint8Array([4, 5, 6]), 'SHAKE128');
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.signHash(... SHAKE256) → sha3 zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.signHash(signingKey, new Uint8Array([7, 8, 9]), 'SHAKE256');
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.signHash(... SHA2-256) → sha3 zero', () => {
		const dsa = new MlDsa44();
		const { signingKey } = dsa.keygen();
		dsa.signHash(signingKey, new Uint8Array([10, 11, 12]), 'SHA2-256');
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.verifyHash(... SHA3-512) success path → sha3 zero', () => {
		const dsa = new MlDsa44();
		const { verificationKey, signingKey } = dsa.keygen();
		const msg = new Uint8Array([13, 14]);
		const sig = dsa.signHash(signingKey, msg, 'SHA3-512');
		expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA3-512')).toBe(true);
		expectSha3ScratchZero();
		dsa.dispose();
	});

	it('MlDsa44.verifyHash(... SHA2-512) failure path → sha3 zero', () => {
		const dsa = new MlDsa44();
		const { verificationKey, signingKey } = dsa.keygen();
		const msg = new Uint8Array([15, 16]);
		const sig = dsa.signHash(signingKey, msg, 'SHA2-512');
		sig[0] ^= 1;
		expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA2-512')).toBe(false);
		expectSha3ScratchZero();
		dsa.dispose();
	});
});
