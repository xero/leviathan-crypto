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
 * sha3 scratch-region wipes across kyber op boundaries.
 *
 * Every public ML-KEM op that performs sha3 work
 * (`keygen`, `encapsulate`, `decapsulate`, `checkDecapsulationKey`) calls
 * `sx.wipeBuffers()` before returning, under the `_assertNotOwned('sha3')`
 * guard held for the op's duration. After any such op returns, the sha3
 * module's STATE (200 B @ 0), INPUT (168 B @ 209), and OUT (168 B @ 377)
 * are all zero.
 *
 * Historically the no-residue claim was behavioral — it relied on "the
 * last sha3 call in every kyber public path happens to be keyed on
 * public material." A future reordering or new post-hash step could
 * silently break that invariant. The explicit wipe makes the invariant
 * mechanical: no matter what sha3 work ran last, scratch is zero at the
 * op boundary.
 *
 * The one documented exception is `checkDecapsulationKey`'s length-gate
 * early return, which runs before any sha3 work and therefore has
 * nothing to wipe. The length-gate test pre-dirties sha3 memory and
 * confirms the early-return path leaves it untouched; the counter-test
 * feeds a valid-length-but-bad-hash dk and confirms the wipe fires on
 * every path that actually touched sha3.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlKem512, MlKem768, MlKem1024 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';

beforeAll(async () => {
	await init({ kyber: kyberWasm, sha3: sha3Wasm });
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

function dirtySha3Scratch(): void {
	const mem = sha3Mem();
	mem.fill(0xa5, SHA3_STATE_OFFSET, SHA3_STATE_OFFSET + SHA3_STATE_LEN);
	mem.fill(0xa5, SHA3_INPUT_OFFSET, SHA3_INPUT_OFFSET + SHA3_INPUT_LEN);
	mem.fill(0xa5, SHA3_OUT_OFFSET,   SHA3_OUT_OFFSET   + SHA3_OUT_LEN);
}

function expectSha3ScratchDirty(): void {
	const mem = sha3Mem();
	expect(mem[SHA3_STATE_OFFSET]).toBe(0xa5);
	expect(mem[SHA3_INPUT_OFFSET]).toBe(0xa5);
	expect(mem[SHA3_OUT_OFFSET]).toBe(0xa5);
}

describe('sha3 scratch wiped after every public kyber op', () => {
	it('MlKem512.keygen() → sha3 STATE/INPUT/OUT zero', () => {
		const kem = new MlKem512();
		kem.keygen();
		expectSha3ScratchZero();
		kem.dispose();
	});

	it('MlKem512.encapsulate(ek) → sha3 STATE/INPUT/OUT zero', () => {
		const kem = new MlKem512();
		const { encapsulationKey } = kem.keygen();
		kem.encapsulate(encapsulationKey);
		expectSha3ScratchZero();
		kem.dispose();
	});

	it('MlKem512.decapsulate(dk, c) → sha3 STATE/INPUT/OUT zero', () => {
		const kem = new MlKem512();
		const { encapsulationKey, decapsulationKey } = kem.keygen();
		const { ciphertext, sharedSecret } = kem.encapsulate(encapsulationKey);
		const recovered = kem.decapsulate(decapsulationKey, ciphertext);
		expect(recovered).toEqual(sharedSecret);
		expectSha3ScratchZero();
		kem.dispose();
	});

	it('MlKem512.decapsulate(dk, tamperedC) → sha3 STATE/INPUT/OUT zero (implicit rejection still runs FO re-encryption)', () => {
		const kem = new MlKem512();
		const { encapsulationKey, decapsulationKey } = kem.keygen();
		const { ciphertext } = kem.encapsulate(encapsulationKey);
		const tampered = ciphertext.slice();
		tampered[0] ^= 0xff;
		kem.decapsulate(decapsulationKey, tampered);
		expectSha3ScratchZero();
		kem.dispose();
	});

	it('MlKem512.checkDecapsulationKey(dk) on valid dk → sha3 STATE/INPUT/OUT zero', () => {
		const kem = new MlKem512();
		const { decapsulationKey } = kem.keygen();
		expect(kem.checkDecapsulationKey(decapsulationKey)).toBe(true);
		expectSha3ScratchZero();
		kem.dispose();
	});
});

describe('checkDecapsulationKey — length-gate early return does NOT reach the sha3 wipe', () => {
	it('length-mismatched dk returns before any sha3 work; pre-existing sha3 bytes persist', () => {
		// Pre-populate sha3 scratch with a recognizable non-zero pattern,
		// verify it's there, then call checkDecapsulationKey with a dk whose
		// length is wrong. The function must return at the length gate before
		// any sha3 hashing — so the wipe does not fire and the pattern stays.
		const kem = new MlKem512();
		dirtySha3Scratch();
		expectSha3ScratchDirty();

		const badDk = new Uint8Array(kem.params.dkBytes - 1);
		expect(kem.checkDecapsulationKey(badDk)).toBe(false);

		expectSha3ScratchDirty();
		kem.dispose();
	});

	it('valid-length dk that fails the H(ek) check → wipe fires, sha3 STATE/INPUT/OUT zero', () => {
		// Same pre-dirty setup, but give a dk whose length matches so the
		// function actually runs sha3_256Hash(ek) before discovering the hash
		// mismatch. The try/finally must wipe on this failure path.
		const kem = new MlKem512();
		const { decapsulationKey } = kem.keygen();

		// Flip a byte in the stored H(ek) portion so the SHA3-256(ek) check
		// fails. dk layout: skCpa || ek || H(ek) || z.
		const corrupted = decapsulationKey.slice();
		const hIdx = kem.params.skCpaBytes + kem.params.ekBytes;
		corrupted[hIdx] ^= 0x01;

		dirtySha3Scratch();
		expect(kem.checkDecapsulationKey(corrupted)).toBe(false);

		expectSha3ScratchZero();
		kem.dispose();
	});
});

describe('sha3 scratch wipe — belt-and-suspenders across parameter sets', () => {
	// The sha3 scratch region is parameter-set-independent, so one pass at
	// each larger set for keygen + encap + decap gives us confidence that
	// the wipes fire identically regardless of which kyber params drove
	// the op.
	const cases: { name: string; make: () => MlKem768 | MlKem1024 }[] = [
		{ name: 'ML-KEM-768',  make: () => new MlKem768()  },
		{ name: 'ML-KEM-1024', make: () => new MlKem1024() },
	];

	for (const { name, make } of cases) {
		it(`${name} keygen + encap + decap all leave sha3 scratch zero`, () => {
			const kem = make();
			const { encapsulationKey, decapsulationKey } = kem.keygen();
			expectSha3ScratchZero();
			const { ciphertext } = kem.encapsulate(encapsulationKey);
			expectSha3ScratchZero();
			kem.decapsulate(decapsulationKey, ciphertext);
			expectSha3ScratchZero();
			kem.dispose();
		});
	}
});
