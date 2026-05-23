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
// src/ts/mlkem/kem.ts
//
// ML-KEM KEM layer, Fujisaki-Okamoto transform.
// FIPS 203 Algorithms 15, 16, 17 (ML-KEM internal).

import type { MlKemExports, Sha3Exports, MlKemKeyPair, MlKemEncapsulation } from './types.js';
import type { MlKemParams } from './params.js';
import {
	indcpaKeypairDerand,
	indcpaEncrypt,
	indcpaDecrypt,
	sha3_256Hash,
	sha3_512Hash,
	shake256Hash,
} from './indcpa.js';
import { wipe } from '../utils.js';

/**
 * ML-KEM.KeyGen_internal (FIPS 203 Algorithm 15).
 *
 * dk = skCpa || ek || H(ek) || z
 */
export function kemKeypairDerand(
	kx: MlKemExports,
	sx: Sha3Exports,
	params: MlKemParams,
	d: Uint8Array,
	z: Uint8Array,
): MlKemKeyPair {
	// indcpaKeypairDerand handles its own sigma wipe
	const { ekCpa, skCpa } = indcpaKeypairDerand(kx, sx, params, d);

	// Wipe CPA sk + keygen noise + PRF scratch. See
	// docs/mlkem.md#wipe-discipline.
	const mlkemMem = new Uint8Array(kx.memory.buffer);
	mlkemMem.fill(0, kx.getSkOffset(),      kx.getSkOffset()     + params.skCpaBytes);
	mlkemMem.fill(0, kx.getPolyvecSlot1(),  kx.getPolyvecSlot1() + 2048);
	mlkemMem.fill(0, kx.getPolyvecSlot2(),  kx.getPolyvecSlot2() + 2048);
	mlkemMem.fill(0, kx.getXofPrfOffset(),  kx.getXofPrfOffset() + 1024);

	const h = sha3_256Hash(sx, ekCpa);

	try {
		const dk = new Uint8Array(params.dkBytes);
		dk.set(skCpa, 0);
		dk.set(ekCpa, params.skCpaBytes);
		dk.set(h, params.skCpaBytes + params.ekBytes);
		dk.set(z, params.skCpaBytes + params.ekBytes + 32);

		sx.wipeBuffers();

		return {
			encapsulationKey: ekCpa,
			decapsulationKey: dk,
		};
	} finally {
		wipe(skCpa);
		wipe(h);
	}
}

/**
 * ML-KEM.Encaps_internal (FIPS 203 Algorithm 16).
 *
 * (K, r) = G(m || H(ek)), c = K-PKE.Encrypt(ek, m, r)
 */
export function kemEncapsulateDerand(
	kx: MlKemExports,
	sx: Sha3Exports,
	params: MlKemParams,
	ek: Uint8Array,
	m: Uint8Array,
): MlKemEncapsulation {
	const h = sha3_256Hash(sx, ek);

	let gInput: Uint8Array | undefined;
	let gOut: Uint8Array | undefined;
	let r: Uint8Array | undefined;
	try {
		gInput = new Uint8Array(64);
		gInput.set(m, 0);
		gInput.set(h, 32);
		gOut = sha3_512Hash(sx, gInput);

		const K = gOut.slice(0, 32);
		r = gOut.slice(32, 64);

		const c = indcpaEncrypt(kx, sx, params, ek, m, r);

		// Wipe m + r + e1/e2/u/v + m-poly + PRF scratch. See
		// docs/mlkem.md#wipe-discipline.
		const mlkemMem = new Uint8Array(kx.memory.buffer);
		mlkemMem.fill(0, kx.getMsgOffset(),     kx.getMsgOffset()    + 32);
		mlkemMem.fill(0, kx.getPolyvecSlot1(),  kx.getPolyvecSlot1() + 2048);
		mlkemMem.fill(0, kx.getPolyvecSlot2(),  kx.getPolyvecSlot2() + 2048);
		mlkemMem.fill(0, kx.getPolyvecSlot3(),  kx.getPolyvecSlot3() + 2048);
		mlkemMem.fill(0, kx.getPolySlot1(),     kx.getPolySlot1()    + 512);
		mlkemMem.fill(0, kx.getPolySlot2(),     kx.getPolySlot2()    + 512);
		mlkemMem.fill(0, kx.getPolySlot3(),     kx.getPolySlot3()    + 512);
		mlkemMem.fill(0, kx.getXofPrfOffset(),  kx.getXofPrfOffset() + 1024);

		sx.wipeBuffers();

		return { ciphertext: c, sharedSecret: K };
	} finally {
		if (gInput) wipe(gInput);
		if (gOut)   wipe(gOut);
		if (r)      wipe(r);
	}
}

/**
 * ML-KEM.Decaps_internal (FIPS 203 Algorithm 17).
 *
 * Constant-time: uses ct_verify and ct_cmov from mlkem WASM.
 * MUST NOT branch on secret data in JS, all comparison via WASM primitives.
 */
export function kemDecapsulate(
	kx: MlKemExports,
	sx: Sha3Exports,
	params: MlKemParams,
	dk: Uint8Array,
	c: Uint8Array,
): Uint8Array {
	const { skCpaBytes, ekBytes, ctBytes } = params;

	// Parse dk: skCpa || ek || H(ek) || z
	const skCpa = dk.slice(0, skCpaBytes);
	const ek    = dk.slice(skCpaBytes, skCpaBytes + ekBytes);
	const h     = dk.slice(skCpaBytes + ekBytes, skCpaBytes + ekBytes + 32);
	const z     = dk.slice(skCpaBytes + ekBytes + 32, skCpaBytes + ekBytes + 64);

	let mPrime: Uint8Array | undefined;
	let gInput: Uint8Array | undefined;
	let gOut: Uint8Array | undefined;
	let kPrime: Uint8Array | undefined;
	let rPrime: Uint8Array | undefined;
	let jInput: Uint8Array | undefined;
	let kBar: Uint8Array | undefined;
	let cPrime: Uint8Array | undefined;

	try {
		// Decrypt
		mPrime = indcpaDecrypt(kx, params, skCpa, c);

		// G(m' || H(ek)) → (K', r')
		gInput = new Uint8Array(64);
		gInput.set(mPrime, 0);
		gInput.set(h, 32);
		gOut = sha3_512Hash(sx, gInput);
		kPrime = gOut.slice(0, 32);
		rPrime = gOut.slice(32, 64);

		// J(z || c) → K̄  [implicit rejection value]
		jInput = new Uint8Array(32 + ctBytes);
		jInput.set(z, 0);
		jInput.set(c, 32);
		kBar = shake256Hash(sx, jInput, 32);

		// Re-encrypt c' = K-PKE.Encrypt(ek, m', r'), indcpaEncrypt handles its own prfInput wipe
		cPrime = indcpaEncrypt(kx, sx, params, ek, mPrime, rPrime);

		// Constant-time comparison and conditional select via mlkem WASM
		const mlkemMem = new Uint8Array(kx.memory.buffer);
		const ctOff      = kx.getCtOffset();
		const ctPrimeOff = kx.getCtPrimeOffset();

		// Write c and c' into named mlkem memory regions
		mlkemMem.set(c, ctOff);
		mlkemMem.set(cPrime, ctPrimeOff);

		// Write K' and K̄ into poly slots (512B each, 32B needed)
		const kPrimeOff = kx.getPolySlot0();
		const kBarOff   = kx.getPolySlot1();
		mlkemMem.set(kPrime, kPrimeOff);
		mlkemMem.set(kBar,   kBarOff);

		// fail = 0 if c == c', non-zero if different
		const fail = kx.ct_verify(ctOff, ctPrimeOff, ctBytes);

		// If fail != 0 (mismatch): K' ← K̄
		kx.ct_cmov(kPrimeOff, kBarOff, 32, fail);

		const sharedSecret = mlkemMem.slice(kPrimeOff, kPrimeOff + 32);

		// Wipe CPA sk + m' + K'/K_bar + noise + PRF scratch. skCpa is the
		// highest-severity residual (compromises every ciphertext under the
		// corresponding ek). See docs/mlkem.md#wipe-discipline.
		mlkemMem.fill(0, kx.getMsgOffset(),     kx.getMsgOffset() + 32);       // m' (bytes)
		mlkemMem.fill(0, kPrimeOff,             kPrimeOff + 32);               // K' (final shared secret)
		mlkemMem.fill(0, kBarOff,               kBarOff + 512);                // K̄ (first 32B) + e₂ poly tail
		mlkemMem.fill(0, kx.getPolySlot2(),     kx.getPolySlot2() + 512);      // m'-poly / v residual
		mlkemMem.fill(0, kx.getPolySlot3(),     kx.getPolySlot3() + 512);      // indcpa message poly
		mlkemMem.fill(0, kx.getPolyvecSlot1(),  kx.getPolyvecSlot1() + 2048);  // r (NTT-domain noise polyvec)
		mlkemMem.fill(0, kx.getPolyvecSlot2(),  kx.getPolyvecSlot2() + 2048);  // e₁ (noise polyvec for u)
		mlkemMem.fill(0, kx.getPolyvecSlot3(),  kx.getPolyvecSlot3() + 2048);  // uncompressed u polyvec from FO re-encryption
		mlkemMem.fill(0, kx.getXofPrfOffset(),  kx.getXofPrfOffset() + 1024);  // last PRF output block
		mlkemMem.fill(0, kx.getSkOffset(),      kx.getSkOffset() + skCpaBytes); // CPA secret key (long-lived, highest severity residual)

		sx.wipeBuffers();

		return sharedSecret;
	} finally {
		if (mPrime) wipe(mPrime);
		if (gInput) wipe(gInput);
		if (gOut)   wipe(gOut);
		if (kPrime) wipe(kPrime);
		if (rPrime) wipe(rPrime);
		if (jInput) wipe(jInput);
		if (kBar)   wipe(kBar);
		if (cPrime) wipe(cPrime);
		wipe(skCpa);
		wipe(ek);
		wipe(h);
		wipe(z);
	}
}
