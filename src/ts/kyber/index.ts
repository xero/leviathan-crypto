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
// src/ts/kyber/index.ts
//
// ML-KEM public API — MlKem512, MlKem768, MlKem1024 classes.
// Uses the init() module cache — call init({ kyber: ..., sha3: ... }) before constructing.

import { getInstance, initModule, isInitialized } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import type { KyberExports, Sha3Exports, KyberKeyPair, KyberEncapsulation } from './types.js';
import { KyberParams, MLKEM512, MLKEM768, MLKEM1024 } from './params.js';
import { kemKeypairDerand, kemEncapsulateDerand, kemDecapsulate } from './kem.js';
import { checkEncapsulationKey, checkDecapsulationKey } from './validate.js';

export async function kyberInit(source: WasmSource): Promise<void> {
	return initModule('kyber', source);
}

export function _kyberReady(): boolean {
	try {
		getInstance('kyber');
		getInstance('sha3');
		return true;
	} catch {
		return false;
	}
}

export type { WasmSource };
export type { KyberKeyPair, KyberEncapsulation, KyberExports, Sha3Exports };
export { MLKEM512, MLKEM768, MLKEM1024 };
export type { KyberParams };
export { isInitialized };
export { KyberSuite } from './suite.js';

// ── Layout assertion ──────────────────────────────────────────────────────────

function assertLayout(kx: KyberExports, p: KyberParams): void {
	const pk      = kx.getPkOffset();
	const sk      = kx.getSkOffset();
	const ct      = kx.getCtOffset();
	const ctPrime = kx.getCtPrimeOffset();
	const xof     = kx.getXofPrfOffset();
	if (pk + p.ekBytes > sk)
		throw new Error('leviathan-crypto: kyber buffer overflow — ek overflows into SK region');
	if (sk + p.skCpaBytes > ct)
		throw new Error('leviathan-crypto: kyber buffer overflow — sk overflows into CT region');
	if (ct + p.ctBytes > ctPrime)
		throw new Error('leviathan-crypto: kyber buffer overflow — ct overflows into CT_PRIME region');
	if (ctPrime + p.ctBytes > xof)
		throw new Error('leviathan-crypto: kyber buffer overflow — ct_prime overflows into XOF region');
}

// ── Base class ────────────────────────────────────────────────────────────────

export class MlKemBase {
	readonly params: KyberParams;

	constructor(params: KyberParams) {
		if (!isInitialized('kyber'))
			throw new Error('leviathan-crypto: call init({ kyber: ... }) before using MlKem classes');
		if (!isInitialized('sha3'))
			throw new Error('leviathan-crypto: call init({ sha3: ... }) before using MlKem classes');
		this.params = params;
		assertLayout(this.kx, params);
	}

	private get kx(): KyberExports {
		return getInstance('kyber').exports as unknown as KyberExports;
	}

	private get sx(): Sha3Exports {
		return getInstance('sha3').exports as unknown as Sha3Exports;
	}

	keygenDerand(d: Uint8Array, z: Uint8Array): KyberKeyPair {
		if (d.length !== 32)
			throw new RangeError(`d seed must be 32 bytes (got ${d.length})`);
		if (z.length !== 32)
			throw new RangeError(`z seed must be 32 bytes (got ${z.length})`);
		return kemKeypairDerand(this.kx, this.sx, this.params, d, z);
	}

	keygen(): KyberKeyPair {
		const d = randomBytes(32);
		const z = randomBytes(32);
		try {
			return this.keygenDerand(d, z);
		} finally {
			wipe(d);
			wipe(z);
		}
	}

	encapsulateDerand(ek: Uint8Array, m: Uint8Array): KyberEncapsulation {
		if (ek.length !== this.params.ekBytes)
			throw new RangeError(`encapsulation key must be ${this.params.ekBytes} bytes (got ${ek.length})`);
		if (m.length !== 32)
			throw new RangeError(`randomness m must be 32 bytes (got ${m.length})`);
		return kemEncapsulateDerand(this.kx, this.sx, this.params, ek, m);
	}

	encapsulate(ek: Uint8Array): KyberEncapsulation {
		const m = randomBytes(32);
		try {
			return this.encapsulateDerand(ek, m);
		} finally {
			wipe(m);
		}
	}

	decapsulate(dk: Uint8Array, c: Uint8Array): Uint8Array {
		if (dk.length !== this.params.dkBytes)
			throw new RangeError(`decapsulation key must be ${this.params.dkBytes} bytes (got ${dk.length})`);
		if (c.length !== this.params.ctBytes)
			throw new RangeError(`ciphertext must be ${this.params.ctBytes} bytes (got ${c.length})`);
		return kemDecapsulate(this.kx, this.sx, this.params, dk, c);
	}

	checkEncapsulationKey(ek: Uint8Array): boolean {
		return checkEncapsulationKey(this.kx, this.params, ek);
	}

	checkDecapsulationKey(dk: Uint8Array): boolean {
		return checkDecapsulationKey(this.kx, this.sx, this.params, dk);
	}

	dispose(): void {
		this.kx.wipeBuffers();
		this.sx.wipeBuffers();
	}
}

// ── Public classes ────────────────────────────────────────────────────────────

/** ML-KEM-512 — k=2, η₁=3, η₂=2, dᵤ=10, dᵥ=4. */
export class MlKem512 extends MlKemBase {
	constructor() {
		super(MLKEM512);
	}
}

/** ML-KEM-768 — k=3, η₁=2, η₂=2, dᵤ=10, dᵥ=4. */
export class MlKem768 extends MlKemBase {
	constructor() {
		super(MLKEM768);
	}
}

/** ML-KEM-1024 — k=4, η₁=2, η₂=2, dᵤ=11, dᵥ=5. */
export class MlKem1024 extends MlKemBase {
	constructor() {
		super(MLKEM1024);
	}
}
