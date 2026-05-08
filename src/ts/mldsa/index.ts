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
// src/ts/mldsa/index.ts
//
// ML-DSA public API — MlDsa44, MlDsa65, MlDsa87 classes.
// FIPS 204 — Module-Lattice-Based Digital Signature Standard.
//
// Phase-4 surface: keygen / keygenDerand only. sign / verify land in
// phase 5; HashML-DSA in phase 6. Use init({ mldsa, sha3 }) before
// constructing any class — both modules are required.

import { getInstance, initModule, isInitialized, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import type { MlDsaExports, Sha3Exports, MlDsaKeyPair } from './types.js';
import { MlDsaParams, MLDSA44, MLDSA65, MLDSA87 } from './params.js';
import { mldsaKeygenInternal } from './keygen.js';

export async function mldsaInit(source: WasmSource): Promise<void> {
	return initModule('mldsa', source);
}

export type { WasmSource };
export type { MlDsaKeyPair, MlDsaExports, Sha3Exports } from './types.js';
export { MLDSA44, MLDSA65, MLDSA87 };
export type { MlDsaParams };
export { isInitialized };

// ── Layout assertion ────────────────────────────────────────────────────────

function assertLayout(mx: MlDsaExports, p: MlDsaParams): void {
	const matrix    = mx.getMatrixSlot();
	const matrixEnd = matrix + mx.getMatrixSlotSize();
	const pvBase    = mx.getPolyvecSlotBase();
	const pkOff     = mx.getPkOffset();
	const skOff     = mx.getSkOffset();
	const sigOff    = mx.getSigOffset();
	const xofOff    = mx.getXofPrfOffset();

	if (matrixEnd > pvBase)
		throw new Error('leviathan-crypto: mldsa MATRIX_SLOT overflows POLYVEC region');
	const polyBytes = 1024;
	if (p.k * p.l * polyBytes > mx.getMatrixSlotSize())
		throw new Error(
			`leviathan-crypto: mldsa MATRIX_SLOT too small for ${p.paramSet} `
			+ `(needs ${p.k * p.l * polyBytes}, have ${mx.getMatrixSlotSize()})`,
		);
	if (pkOff + p.pkBytes > skOff)
		throw new Error('leviathan-crypto: mldsa pk buffer overflows into sk region');
	if (skOff + p.skBytes > sigOff)
		throw new Error('leviathan-crypto: mldsa sk buffer overflows into sig region');
	if (sigOff + p.sigBytes > xofOff)
		throw new Error('leviathan-crypto: mldsa sig buffer overflows into XOF region');
}

// ── Base class ──────────────────────────────────────────────────────────────

export class MlDsaBase {
	readonly params: MlDsaParams;

	constructor(params: MlDsaParams) {
		if (!isInitialized('mldsa'))
			throw new Error('leviathan-crypto: call init({ mldsa: ... }) before using MlDsa classes');
		if (!isInitialized('sha3'))
			throw new Error('leviathan-crypto: call init({ sha3: ... }) before using MlDsa classes');
		this.params = params;
		assertLayout(this.mx, params);
	}

	private get mx(): MlDsaExports {
		return getInstance('mldsa').exports as unknown as MlDsaExports;
	}

	private get sx(): Sha3Exports {
		return getInstance('sha3').exports as unknown as Sha3Exports;
	}

	/**
	 * Deterministic key generation — FIPS 204 §6.1 Algorithm 6.
	 * @param xi 32-byte seed. The sole input; ml-dsa keygen has no
	 *           additional rejection-tied randomness.
	 */
	keygenDerand(xi: Uint8Array): MlDsaKeyPair {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		if (xi.length !== 32)
			throw new RangeError(`xi seed must be 32 bytes (got ${xi.length})`);
		return mldsaKeygenInternal(this.mx, this.sx, this.params, xi);
	}

	/** Random key generation — wraps `keygenDerand` with `randomBytes(32)`. */
	keygen(): MlDsaKeyPair {
		const xi = randomBytes(32);
		try {
			return this.keygenDerand(xi);
		} finally {
			wipe(xi);
		}
	}

	dispose(): void {
		this.mx.wipeBuffers();
		// MlDsaBase does not own the sha3 module — wiping sha3 here would
		// clobber any SHAKE128/SHAKE256 instance live at the time of
		// dispose(). The wipe is not needed: every public mldsa op (only
		// keygen* in phase 4; sign/verify in subsequent phases) calls
		// sx.wipeBuffers() before returning, under the
		// _assertNotOwned('sha3') guard it holds. sha3 scratch carries no
		// residue across an mldsa op boundary.
	}
}

// ── Public classes ──────────────────────────────────────────────────────────

/** ML-DSA-44 — FIPS 204 §4 Table 1 (NIST security category 2). */
export class MlDsa44 extends MlDsaBase {
	constructor() {
		super(MLDSA44);
	}
}

/** ML-DSA-65 — FIPS 204 §4 Table 1 (NIST security category 3). */
export class MlDsa65 extends MlDsaBase {
	constructor() {
		super(MLDSA65);
	}
}

/** ML-DSA-87 — FIPS 204 §4 Table 1 (NIST security category 5). */
export class MlDsa87 extends MlDsaBase {
	constructor() {
		super(MLDSA87);
	}
}
