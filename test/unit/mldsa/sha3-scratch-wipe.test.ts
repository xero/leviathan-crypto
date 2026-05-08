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

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm });
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
});
