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
// src/ts/kyber/kem.ts
//
// ML-KEM KEM layer — Fujisaki-Okamoto transform.
// FIPS 203 Algorithms 15, 16, 17 (ML-KEM internal).

import type { KyberExports, Sha3Exports, KyberKeyPair, KyberEncapsulation } from './types.js';
import type { KyberParams } from './params.js';
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
	kx: KyberExports,
	sx: Sha3Exports,
	params: KyberParams,
	d: Uint8Array,
	z: Uint8Array,
): KyberKeyPair {
	// indcpaKeypairDerand handles its own sigma wipe
	const { ekCpa, skCpa } = indcpaKeypairDerand(kx, sx, params, d);

	// Wipe kyber WASM scratch regions that held the CPA secret key and the
	// keygen noise. After kemKeypairDerand returns, no secret or secret-
	// derived data persists in kyber linear memory until the next kyber op
	// or MlKem.dispose(). SK_OFFSET holds skCpa packed via polyvec_tobytes
	// — same severity class as the decap-side SK_OFFSET residual (R-028):
	// long-lived key material whose disclosure compromises every ciphertext
	// under the corresponding ek. POLYVEC_SLOT_1/2 hold ŝ and ê in NTT
	// domain. XOF_PRF_OFFSET holds the last PRF output block. POLYVEC_SLOT_3
	// (t̂) and POLYVEC_SLOT_0 (Â rows) are public and intentionally skipped.
	const kyberMem = new Uint8Array(kx.memory.buffer);
	kyberMem.fill(0, kx.getSkOffset(),      kx.getSkOffset()     + params.skCpaBytes);
	kyberMem.fill(0, kx.getPolyvecSlot1(),  kx.getPolyvecSlot1() + 2048);
	kyberMem.fill(0, kx.getPolyvecSlot2(),  kx.getPolyvecSlot2() + 2048);
	kyberMem.fill(0, kx.getXofPrfOffset(),  kx.getXofPrfOffset() + 1024);

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
	kx: KyberExports,
	sx: Sha3Exports,
	params: KyberParams,
	ek: Uint8Array,
	m: Uint8Array,
): KyberEncapsulation {
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

		// Wipe kyber WASM scratch regions that held m / r / e₁ / e₂ / u / v /
		// m-poly / PRF output. After kemEncapsulateDerand returns, no secret
		// or secret-derived data persists in kyber linear memory until the
		// next kyber op or MlKem.dispose(). MSG_OFFSET holds raw m —
		// reproducing the shared secret K = G(m ‖ H(ek))[0..32] only needs m
		// plus the public ek, so this is the highest-severity encap residual.
		// POLYVEC_SLOT_1/2/3 hold r, e₁, and uncompressed u (u compression is
		// lossy for du ∈ {10,11} — uncompressed u reveals low-order bits the
		// public ciphertext hides). POLY_SLOT_1/2/3 hold e₂ (full 512B), v,
		// and the m-polynomial. XOF_PRF_OFFSET holds the last PRF block.
		// PK_OFFSET, CT_OFFSET, POLYVEC_SLOT_0/4 are public — skipped.
		const kyberMem = new Uint8Array(kx.memory.buffer);
		kyberMem.fill(0, kx.getMsgOffset(),     kx.getMsgOffset()    + 32);
		kyberMem.fill(0, kx.getPolyvecSlot1(),  kx.getPolyvecSlot1() + 2048);
		kyberMem.fill(0, kx.getPolyvecSlot2(),  kx.getPolyvecSlot2() + 2048);
		kyberMem.fill(0, kx.getPolyvecSlot3(),  kx.getPolyvecSlot3() + 2048);
		kyberMem.fill(0, kx.getPolySlot1(),     kx.getPolySlot1()    + 512);
		kyberMem.fill(0, kx.getPolySlot2(),     kx.getPolySlot2()    + 512);
		kyberMem.fill(0, kx.getPolySlot3(),     kx.getPolySlot3()    + 512);
		kyberMem.fill(0, kx.getXofPrfOffset(),  kx.getXofPrfOffset() + 1024);

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
 * Constant-time: uses ct_verify and ct_cmov from kyber WASM.
 * MUST NOT branch on secret data in JS — all comparison via WASM primitives.
 */
export function kemDecapsulate(
	kx: KyberExports,
	sx: Sha3Exports,
	params: KyberParams,
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

		// Re-encrypt c' = K-PKE.Encrypt(ek, m', r') — indcpaEncrypt handles its own prfInput wipe
		cPrime = indcpaEncrypt(kx, sx, params, ek, mPrime, rPrime);

		// Constant-time comparison and conditional select via kyber WASM
		const kyberMem = new Uint8Array(kx.memory.buffer);
		const ctOff      = kx.getCtOffset();
		const ctPrimeOff = kx.getCtPrimeOffset();

		// Write c and c' into named kyber memory regions
		kyberMem.set(c, ctOff);
		kyberMem.set(cPrime, ctPrimeOff);

		// Write K' and K̄ into poly slots (512B each, 32B needed)
		const kPrimeOff = kx.getPolySlot0();
		const kBarOff   = kx.getPolySlot1();
		kyberMem.set(kPrime, kPrimeOff);
		kyberMem.set(kBar,   kBarOff);

		// fail = 0 if c == c', non-zero if different
		const fail = kx.ct_verify(ctOff, ctPrimeOff, ctBytes);

		// If fail != 0 (mismatch): K' ← K̄
		kx.ct_cmov(kPrimeOff, kBarOff, 32, fail);

		const sharedSecret = kyberMem.slice(kPrimeOff, kPrimeOff + 32);

		// Wipe kyber WASM scratch regions that held the CPA secret key (skCpa),
		// m' / K' / K̄ / e₂ / r / e₁ / u, and the PRF output buffer. Without
		// this, residual secret and secret-derived bytes persist in linear
		// memory until the next kyber op or MlKem.dispose() — a window during
		// which any other code with a handle to the kyber exports could read
		// them. skCpa is the highest-severity residual: it compromises every
		// ciphertext under the corresponding ek, not just this message.
		kyberMem.fill(0, kx.getMsgOffset(),     kx.getMsgOffset() + 32);       // m' (bytes)
		kyberMem.fill(0, kPrimeOff,             kPrimeOff + 32);               // K' (final shared secret)
		kyberMem.fill(0, kBarOff,               kBarOff + 512);                // K̄ (first 32B) + e₂ poly tail
		kyberMem.fill(0, kx.getPolySlot2(),     kx.getPolySlot2() + 512);      // m'-poly / v residual
		kyberMem.fill(0, kx.getPolySlot3(),     kx.getPolySlot3() + 512);      // indcpa message poly
		kyberMem.fill(0, kx.getPolyvecSlot1(),  kx.getPolyvecSlot1() + 2048);  // r (NTT-domain noise polyvec)
		kyberMem.fill(0, kx.getPolyvecSlot2(),  kx.getPolyvecSlot2() + 2048);  // e₁ (noise polyvec for u)
		kyberMem.fill(0, kx.getPolyvecSlot3(),  kx.getPolyvecSlot3() + 2048);  // uncompressed u polyvec from FO re-encryption
		kyberMem.fill(0, kx.getXofPrfOffset(),  kx.getXofPrfOffset() + 1024);  // last PRF output block
		kyberMem.fill(0, kx.getSkOffset(),      kx.getSkOffset() + skCpaBytes); // CPA secret key (long-lived — highest severity residual)

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
