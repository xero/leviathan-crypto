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
 * kemEncapsulateDerand scratch-slot wipes.
 *
 * Verifies that after `MlKem*.encapsulate(ek)` returns, every kyber WASM
 * scratch region that held secret or secret-derived bytes during the
 * IND-CPA re-encryption is zeroed. MSG_OFFSET holds the raw message m —
 * reading it alongside the public ek reproduces the shared secret K =
 * G(m ‖ H(ek))[0..32], so it's the highest-severity encap residual. The
 * poly/polyvec slot sizes are k-independent (fixed at the k=4 maximum),
 * so one parameter set suffices for the non-skCpa regions. PK_OFFSET,
 * CT_OFFSET, and POLYVEC_SLOT_0/4 hold public material and are
 * intentionally not wiped.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, MlKem768 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';

beforeAll(async () => {
	await init({ kyber: kyberWasm, sha3: sha3Wasm });
});

interface KyberExports {
	memory: WebAssembly.Memory
	getMsgOffset:    () => number
	getPolySlot1:    () => number
	getPolySlot2:    () => number
	getPolySlot3:    () => number
	getPolyvecSlot1: () => number
	getPolyvecSlot2: () => number
	getPolyvecSlot3: () => number
	getXofPrfOffset: () => number
}

function getExports(): KyberExports {
	return getInstance('kyber').exports as unknown as KyberExports;
}

function regionIsZero(mem: Uint8Array, off: number, len: number): boolean {
	for (let i = 0; i < len; i++) if (mem[off + i] !== 0) return false;
	return true;
}

function freshEncap(): MlKem768 {
	const kem = new MlKem768();
	const { encapsulationKey } = kem.keygen();
	kem.encapsulate(encapsulationKey);
	return kem;
}

describe('kemEncapsulateDerand — scratch slots wiped after encap', () => {
	it('MSG_OFFSET is zero after encap (raw m — reproduces K with public ek)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getMsgOffset(), 32)).toBe(true);

		kem.dispose();
	});

	it('POLYVEC_SLOT_1 is zero after encap (r in NTT domain)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot1(), 2048)).toBe(true);

		kem.dispose();
	});

	it('POLYVEC_SLOT_2 is zero after encap (e₁ noise polyvec)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot2(), 2048)).toBe(true);

		kem.dispose();
	});

	it('POLYVEC_SLOT_3 is zero after encap (uncompressed u polyvec)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolyvecSlot3(), 2048)).toBe(true);

		kem.dispose();
	});

	it('POLY_SLOT_1 is zero after encap (e₂ noise, full 512 B)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolySlot1(), 512)).toBe(true);

		kem.dispose();
	});

	it('POLY_SLOT_2 is zero after encap (v uncompressed)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolySlot2(), 512)).toBe(true);

		kem.dispose();
	});

	it('POLY_SLOT_3 is zero after encap (m-polynomial)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getPolySlot3(), 512)).toBe(true);

		kem.dispose();
	});

	it('XOF_PRF_OFFSET is zero after encap (last PRF output block)', () => {
		const kem = freshEncap();

		const x = getExports();
		const mem = new Uint8Array(x.memory.buffer);
		expect(regionIsZero(mem, x.getXofPrfOffset(), 1024)).toBe(true);

		kem.dispose();
	});
});
