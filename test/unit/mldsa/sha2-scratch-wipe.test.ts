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
 * sha2 scratch-region wipes across HashML-DSA op boundaries.
 *
 * HashML-DSA's signHash / signHashDeterministic / signHashDerand /
 * verifyHash methods drive the sha2 module ONLY when `ph` is a SHA-2
 * family pre-hash. After the op returns, the sha2 module's
 * STATE / INPUT / OUT regions held the pre-hash digest of M (PH_M)
 * and the last block of M; the wrapper calls `sha2x.wipeBuffers()` in
 * its `finally` block so neither persists across the op boundary.
 *
 * PH_M itself is M-derived (M is public input), so the wipe is
 * discipline rather than secrecy — but the discipline is uniform across
 * modules: every public mldsa op that touches a module leaves that
 * module wiped, with a regression test gating the contract. This file
 * is the sha2-side counterpart of `sha3-scratch-wipe.test.ts`.
 *
 * GATE: ML-DSA cross-module SHA-2 wipe — confirms HashML-DSA SHA-2
 * pre-hash leaves no PH_M / message-block residue in the sha2 module.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlDsa44 } from '../../../src/ts/index.js';
import { _resetForTesting, getInstance } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }  from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }  from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm, sha2: sha2Wasm });
});

// sha2 buffer layout — src/asm/sha2/buffers.ts
const SHA2_BUFFER_END   = 1976;  // HMAC512_INNER_OFFSET (1912) + 64
const SHA256_H_OFFSET   = 0;
const SHA256_BLOCK_OFF  = 32;
const SHA256_OUT_OFF    = 352;
const SHA256_INPUT_OFF  = 384;
const SHA512_H_OFFSET   = 620;
const SHA512_BLOCK_OFF  = 684;
const SHA512_OUT_OFF    = 1452;
const SHA512_INPUT_OFF  = 1516;

interface Sha2Mem { memory: WebAssembly.Memory }

function sha2Mem(): Uint8Array {
	const sx = getInstance('sha2').exports as unknown as Sha2Mem;
	return new Uint8Array(sx.memory.buffer);
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

/** Confirm the sha2 module's full mutable surface (state + block + out + input
 *  + partial + total + HMAC pads + HMAC inner) is zero. */
function expectSha2ScratchZero(): void {
	const mem = sha2Mem();
	expect(regionIsZero(mem, 0, SHA2_BUFFER_END)).toBe(true);
}

const KEYGEN_SEED = new Uint8Array(32);

describe('sha2 scratch wiped after every HashML-DSA op with a SHA-2 prehash', () => {
	// One signHash test per SHA-2 prehash. The choice of paramSet is
	// independent — sha2 buffers are paramSet-invariant. Stick with
	// MlDsa44 to keep keygen fast.

	it('signHash(SHA2-224) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHash(signingKey, new Uint8Array([1, 2, 3]), 'SHA2-224');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	it('signHash(SHA2-256) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHash(signingKey, new Uint8Array([4, 5, 6]), 'SHA2-256');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	it('signHash(SHA2-384) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHash(signingKey, new Uint8Array([7, 8, 9]), 'SHA2-384');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	it('signHash(SHA2-512) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHash(signingKey, new Uint8Array([10, 11, 12]), 'SHA2-512');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	it('signHash(SHA2-512/224) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHash(signingKey, new Uint8Array([13, 14, 15]), 'SHA2-512/224');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	it('signHash(SHA2-512/256) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHash(signingKey, new Uint8Array([16, 17, 18]), 'SHA2-512/256');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	// verifyHash success path — the wipe must fire on the return-true branch.
	it('verifyHash(SHA2-512) success path → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey, signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			const msg = new Uint8Array([19, 20, 21]);
			const sig = dsa.signHash(signingKey, msg, 'SHA2-512');
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA2-512')).toBe(true);
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	// verifyHash failure path — wipe must fire on return-false too.
	// Tampered c̃ in σ → cTilde compare fails → verify returns false.
	it('verifyHash(SHA2-256) failure path → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { verificationKey, signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			const msg = new Uint8Array([22, 23]);
			const sig = dsa.signHash(signingKey, msg, 'SHA2-256');
			sig[0] ^= 0x01;  // tamper c̃
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA2-256')).toBe(false);
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	// signHashDeterministic + signHashDerand spot-checks. Logic is
	// the same finally-block as signHash; one each suffices.
	it('signHashDeterministic(SHA2-384) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			dsa.signHashDeterministic(signingKey, new Uint8Array([24, 25]), 'SHA2-384');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	it('signHashDerand(SHA2-512/256) → sha2 STATE/INPUT/OUT zero', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			const rnd = new Uint8Array(32).fill(0xa3);
			dsa.signHashDerand(signingKey, new Uint8Array([26, 27]), 'SHA2-512/256', new Uint8Array(0), rnd);
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	// Pre-dirty-then-op confirms the wipe definitively zeros the regions,
	// not just that they happen to be empty after the SHA-2 hash itself.
	it('pre-dirtied sha2 buffers are wiped after signHash(SHA2-256)', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			const mem = sha2Mem();
			mem.fill(0xbe, SHA256_H_OFFSET,  SHA256_H_OFFSET  + 32);
			mem.fill(0xef, SHA256_BLOCK_OFF, SHA256_BLOCK_OFF + 64);
			mem.fill(0xa5, SHA512_H_OFFSET,  SHA512_H_OFFSET  + 64);
			mem.fill(0x5a, SHA512_BLOCK_OFF, SHA512_BLOCK_OFF + 128);
			dsa.signHash(signingKey, new Uint8Array([28, 29]), 'SHA2-256');
			expectSha2ScratchZero();
		} finally {
			dsa.dispose();
		}
	});

	// Inverse-discipline check: signHash with a SHA-3 / SHAKE prehash MUST
	// NOT touch sha2 buffers. The optional-sha2 design says we only wipe
	// the modules we used — pre-existing sha2 state from an unrelated op
	// (a prior HMAC, say) is the caller's to manage, not ours to clobber.
	it('signHash(SHAKE128) does NOT touch sha2 buffers (sentinel preserved)', () => {
		const dsa = new MlDsa44();
		try {
			const { signingKey } = dsa.keygenDerand(KEYGEN_SEED);
			const mem = sha2Mem();
			const sentinel = 0x42;
			mem.fill(sentinel, SHA256_OUT_OFF,   SHA256_OUT_OFF   + 32);
			mem.fill(sentinel, SHA256_INPUT_OFF, SHA256_INPUT_OFF + 64);
			mem.fill(sentinel, SHA512_OUT_OFF,   SHA512_OUT_OFF   + 64);
			mem.fill(sentinel, SHA512_INPUT_OFF, SHA512_INPUT_OFF + 128);
			dsa.signHash(signingKey, new Uint8Array([30, 31]), 'SHAKE128');
			// Sentinel must be preserved — sha2 was not used, not wiped.
			for (let i = 0; i < 32;  i++) expect(mem[SHA256_OUT_OFF   + i]).toBe(sentinel);
			for (let i = 0; i < 64;  i++) expect(mem[SHA256_INPUT_OFF + i]).toBe(sentinel);
			for (let i = 0; i < 64;  i++) expect(mem[SHA512_OUT_OFF   + i]).toBe(sentinel);
			for (let i = 0; i < 128; i++) expect(mem[SHA512_INPUT_OFF + i]).toBe(sentinel);
		} finally {
			dsa.dispose();
		}
	});
});
