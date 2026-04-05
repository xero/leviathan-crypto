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
// src/ts/kyber/indcpa.ts
//
// ML-KEM IND-CPA PKE scheme — FIPS 203 Algorithms 12, 13, 14 (K-PKE).
// Orchestrates kyber WASM (polynomial math) and sha3 WASM (Keccak sponge).

import type { KyberExports, Sha3Exports } from './types.js';
import type { KyberParams } from './params.js';
import { wipe } from '../utils.js';

// ── SHA3 helpers ──────────────────────────────────────────────────────────────
// All operate directly on raw Sha3Exports, no init() system involved.

/** Absorb msg into the sha3 sponge in 168-byte chunks (max rate). */
function sha3Absorb(sx: Sha3Exports, msg: Uint8Array): void {
	const mem = new Uint8Array(sx.memory.buffer);
	const inOff = sx.getInputOffset();
	let pos = 0;
	while (pos < msg.length) {
		const chunk = Math.min(msg.length - pos, 168);
		mem.set(msg.subarray(pos, pos + chunk), inOff);
		sx.keccakAbsorb(chunk);
		pos += chunk;
	}
}

/** SHA3-512(msg) → 64 bytes. Resets sha3 state. */
export function sha3_512Hash(sx: Sha3Exports, msg: Uint8Array): Uint8Array {
	sx.sha3_512Init();
	sha3Absorb(sx, msg);
	sx.sha3_512Final();
	const mem = new Uint8Array(sx.memory.buffer);
	const off = sx.getOutOffset();
	return mem.slice(off, off + 64);
}

/** SHA3-256(msg) → 32 bytes. Resets sha3 state. */
export function sha3_256Hash(sx: Sha3Exports, msg: Uint8Array): Uint8Array {
	sx.sha3_256Init();
	sha3Absorb(sx, msg);
	sx.sha3_256Final();
	const mem = new Uint8Array(sx.memory.buffer);
	const off = sx.getOutOffset();
	return mem.slice(off, off + 32);
}

/**
 * SHAKE256(msg, n) → n bytes. Resets sha3 state.
 * Used for J function (z || c) and PRF seeding in kem.ts.
 */
export function shake256Hash(sx: Sha3Exports, msg: Uint8Array, n: number): Uint8Array {
	const rate = 136;
	sx.shake256Init();
	sha3Absorb(sx, msg);
	sx.shakePad();
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	const out = new Uint8Array(n);
	let pos = 0;
	while (pos < n) {
		sx.shakeSqueezeBlock();
		const take = Math.min(n - pos, rate);
		out.set(sha3Mem.subarray(outOff, outOff + take), pos);
		pos += take;
	}
	return out;
}

// ── Matrix generation ─────────────────────────────────────────────────────────

/**
 * Generate row `rowI` of matrix Â (or Â^T) into polyvec slot `pvecSlot`.
 *
 * FIPS 203 Algorithm 6 (SampleNTT): each entry Â[i][j] = XOF(ρ, j, i).
 * The matrix entries are already in NTT domain by construction — no separate
 * NTT call is needed after rej_uniform.
 *
 * transposed=false (keygen):  XOF input = ρ || j || i  → Â[i][j]
 * transposed=true  (encrypt): XOF input = ρ || i || j  → Â^T[i][j] = Â[j][i]
 */
function genMatrixRow(
	kx: KyberExports,
	sx: Sha3Exports,
	k: number,
	rho: Uint8Array,
	transposed: boolean,
	pvecSlot: number,
	rowI: number,
): void {
	const xofPrfOff = kx.getXofPrfOffset();
	const kyberMem = new Uint8Array(kx.memory.buffer);
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();

	// XOF seed buffer: ρ(32) || byte0 || byte1
	const xofSeed = new Uint8Array(34);
	xofSeed.set(rho, 0);

	for (let j = 0; j < k; j++) {
		// Build XOF seed before the squeeze loop (no branch inside)
		if (!transposed) {
			xofSeed[32] = j;      // ρ || j || i → Â[rowI][j]
			xofSeed[33] = rowI;
		} else {
			xofSeed[32] = rowI;   // ρ || i || j → Â^T[rowI][j] = Â[j][rowI]
			xofSeed[33] = j;
		}

		// Init SHAKE128 and absorb seed
		sx.shake128Init();
		sha3Absorb(sx, xofSeed);
		sx.shakePad();

		// Reject-sample until 256 NTT coefficients accepted
		const polyOff = pvecSlot + j * 512;
		let ctr = 0;
		while (ctr < 256) {
			sx.shakeSqueezeBlock();  // 168 bytes at sha3 OUT_OFFSET
			kyberMem.set(sha3Mem.subarray(outOff, outOff + 168), xofPrfOff);
			ctr += kx.rej_uniform(polyOff, ctr, xofPrfOff, 168);
		}
	}
}

// ── Noise generation ──────────────────────────────────────────────────────────

/**
 * CBD noise polyvec: SHAKE256(σ || nonce) for each entry.
 * FIPS 203 Algorithm 7: PRF_η(σ, N) = SHAKE256(σ || N)[0..64η-1].
 */
function noisePolyvec(
	kx: KyberExports,
	sx: Sha3Exports,
	pvSlot: number,
	k: number,
	sigma: Uint8Array,
	nonceStart: number,
	eta: number,
): void {
	const xofPrfOff = kx.getXofPrfOffset();
	const kyberMem = new Uint8Array(kx.memory.buffer);
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	const prfLen = eta * 64;    // 128 for η=2, 192 for η=3
	const rate = 136;            // SHAKE256 rate

	// PRF input buffer: σ(32) || nonce(1)
	const prfInput = new Uint8Array(33);
	prfInput.set(sigma, 0);

	try {
		for (let i = 0; i < k; i++) {
			prfInput[32] = nonceStart + i;

			sx.shake256Init();
			sha3Absorb(sx, prfInput);
			sx.shakePad();

			let pos = 0;
			while (pos < prfLen) {
				sx.shakeSqueezeBlock();
				const take = Math.min(prfLen - pos, rate);
				kyberMem.set(sha3Mem.subarray(outOff, outOff + take), xofPrfOff + pos);
				pos += take;
			}

			kx.poly_getnoise(pvSlot + i * 512, xofPrfOff, eta);
		}
	} finally {
		wipe(prfInput);
	}
}

/**
 * CBD noise single polynomial: SHAKE256(σ || nonce).
 */
function noisePoly(
	kx: KyberExports,
	sx: Sha3Exports,
	polyOff: number,
	sigma: Uint8Array,
	nonce: number,
	eta: number,
): void {
	const xofPrfOff = kx.getXofPrfOffset();
	const kyberMem = new Uint8Array(kx.memory.buffer);
	const sha3Mem = new Uint8Array(sx.memory.buffer);
	const outOff = sx.getOutOffset();
	const prfLen = eta * 64;
	const rate = 136;

	const prfInput = new Uint8Array(33);
	prfInput.set(sigma, 0);
	prfInput[32] = nonce;

	try {
		sx.shake256Init();
		sha3Absorb(sx, prfInput);
		sx.shakePad();

		let pos = 0;
		while (pos < prfLen) {
			sx.shakeSqueezeBlock();
			const take = Math.min(prfLen - pos, rate);
			kyberMem.set(sha3Mem.subarray(outOff, outOff + take), xofPrfOff + pos);
			pos += take;
		}

		kx.poly_getnoise(polyOff, xofPrfOff, eta);
	} finally {
		wipe(prfInput);
	}
}

// ── IND-CPA functions ─────────────────────────────────────────────────────────

/**
 * K-PKE.KeyGen (FIPS 203 Algorithm 12) — deterministic.
 *
 * Slot map:
 *   pvec0 — current row of Â (overwritten per row)
 *   pvec1 — ŝ (noise, persistent through dot products)
 *   pvec2 — ê (noise)
 *   pvec3 — t̂ = Â·ŝ + ê (output)
 */
export function indcpaKeypairDerand(
	kx: KyberExports,
	sx: Sha3Exports,
	params: KyberParams,
	d: Uint8Array,
): { ekCpa: Uint8Array; skCpa: Uint8Array } {
	const { k, eta1 } = params;

	// Step 1: G(d || k) → (ρ, σ)  [FIPS 203 §5.1 G = SHA3-512]
	const gInput = new Uint8Array(33);
	gInput.set(d, 0);
	gInput[32] = k;
	const gOut = sha3_512Hash(sx, gInput);
	const rho = gOut.slice(0, 32);
	const sigma = gOut.slice(32, 64);

	// Slot addresses
	const pvec0 = kx.getPolyvecSlot0();
	const pvec1 = kx.getPolyvecSlot1();
	const pvec2 = kx.getPolyvecSlot2();
	const pvec3 = kx.getPolyvecSlot3();
	const pkOff = kx.getPkOffset();
	const skOff = kx.getSkOffset();

	try {
		// Steps 2-3: Generate ŝ and ê BEFORE matrix (so ŝ is stable during dot products)
		noisePolyvec(kx, sx, pvec1, k, sigma, 0, eta1);   // ŝ ← CBD(σ, 0..k-1)
		noisePolyvec(kx, sx, pvec2, k, sigma, k, eta1);   // ê ← CBD(σ, k..2k-1)

		// Step 4: NTT(ŝ), NTT(ê)
		kx.polyvec_ntt(pvec1, k);
		kx.polyvec_ntt(pvec2, k);

		// Step 5: For each row i, t̂[i] = Â[i] · ŝ
		const kyberMem = new Uint8Array(kx.memory.buffer);
		for (let i = 0; i < k; i++) {
			genMatrixRow(kx, sx, k, rho, false, pvec0, i);
			kx.polyvec_basemul_acc_montgomery(pvec3 + i * 512, pvec0, pvec1, k);
			kx.poly_tomont(pvec3 + i * 512);
		}

		// Step 6-7: t̂ = t̂ + ê, reduce
		kx.polyvec_add(pvec3, pvec3, pvec2, k);
		kx.polyvec_reduce(pvec3, k);

		// Step 8: ek = polyvec_tobytes(t̂) || ρ
		kx.polyvec_tobytes(pkOff, pvec3, k);
		kyberMem.set(rho, pkOff + k * 384);

		// Step 9: sk = polyvec_tobytes(ŝ)
		kx.polyvec_tobytes(skOff, pvec1, k);

		return {
			ekCpa: kyberMem.slice(pkOff, pkOff + params.ekBytes),
			skCpa: kyberMem.slice(skOff, skOff + params.skCpaBytes),
		};
	} finally {
		wipe(sigma);
		wipe(gOut);
	}
}

/**
 * K-PKE.Encrypt (FIPS 203 Algorithm 13) — deterministic.
 *
 * Slot map:
 *   pvec0 — current row of Â^T (transposed, overwritten per row)
 *   pvec1 — r̂ = NTT(r)
 *   pvec2 — e₁ (noise)
 *   pvec3 — u = invNTT(Â^T · r̂) + e₁
 *   pvec4 — t̂ (unpacked from ek)
 *   poly1  — e₂ (noise)
 *   poly2  — v = invNTT(t̂^T · r̂) + e₂ + msg
 *   poly3  — message polynomial
 */
export function indcpaEncrypt(
	kx: KyberExports,
	sx: Sha3Exports,
	params: KyberParams,
	ek: Uint8Array,
	m: Uint8Array,
	coins: Uint8Array,
): Uint8Array {
	const { k, eta1, eta2, du, dv } = params;
	const kyberMem = new Uint8Array(kx.memory.buffer);

	const pvec0 = kx.getPolyvecSlot0();
	const pvec1 = kx.getPolyvecSlot1();
	const pvec2 = kx.getPolyvecSlot2();
	const pvec3 = kx.getPolyvecSlot3();
	const pvec4 = kx.getPolyvecSlot4();
	const poly1 = kx.getPolySlot1();
	const poly2 = kx.getPolySlot2();
	const poly3 = kx.getPolySlot3();
	const pkOff = kx.getPkOffset();
	const ctOff = kx.getCtOffset();
	const msgOff = kx.getMsgOffset();

	// Step 1: Unpack ek — t̂ → pvec4, ρ from ek tail
	kyberMem.set(ek, pkOff);
	kx.polyvec_frombytes(pvec4, pkOff, k);
	const rho = ek.slice(k * 384, k * 384 + 32);

	// Steps 2-4: Generate noise r, e₁, e₂ from coins
	noisePolyvec(kx, sx, pvec1, k, coins, 0, eta1);    // r  → pvec1
	noisePolyvec(kx, sx, pvec2, k, coins, k, eta2);    // e₁ → pvec2
	noisePoly(kx, sx, poly1, coins, 2 * k, eta2);      // e₂ → poly1

	// Step 5: r̂ = NTT(r)
	kx.polyvec_ntt(pvec1, k);

	// Step 6: For each row i, u[i] = Â^T[i] · r̂
	// basemul_acc produces (A·r)/R; invntt_tomont cancels the /R: INTT(A·r)
	for (let i = 0; i < k; i++) {
		genMatrixRow(kx, sx, k, rho, true, pvec0, i);
		kx.polyvec_basemul_acc_montgomery(pvec3 + i * 512, pvec0, pvec1, k);
	}

	// Steps 7-9: u = invNTT(Â^T · r̂) + e₁, reduce
	// invntt acts as invntt_tomont: input=(A·r)/R → output=INTT(A·r) in time domain
	// Add e₁ AFTER invntt (both in time domain)
	kx.polyvec_invntt(pvec3, k);
	kx.polyvec_add(pvec3, pvec3, pvec2, k);
	kx.polyvec_reduce(pvec3, k);

	// Steps 10-11: v = invNTT(t̂^T · r̂)
	kx.polyvec_basemul_acc_montgomery(poly2, pvec4, pvec1, k);
	kx.poly_invntt(poly2);

	// Step 12: decode message
	kyberMem.set(m, msgOff);
	kx.poly_frommsg(poly3, msgOff);

	// Steps 13-15: v = v + e₂ + msg, reduce
	kx.poly_add(poly2, poly2, poly1);
	kx.poly_add(poly2, poly2, poly3);
	kx.poly_reduce(poly2);

	// Step 16: pack ciphertext — Compress_du(u) || Compress_dv(v)
	const pvecCompBytes = k * du * 32;
	kx.polyvec_compress(ctOff, pvec3, k, du);
	kx.poly_compress(ctOff + pvecCompBytes, poly2, dv);

	return kyberMem.slice(ctOff, ctOff + params.ctBytes);
}

/**
 * K-PKE.Decrypt (FIPS 203 Algorithm 14).
 *
 * Slot map:
 *   pvec0 — û (decompressed from ct)
 *   pvec1 — ŝ (from sk)
 *   poly0  — v (decompressed from ct)
 *   poly1  — w = invNTT(ŝ^T · NTT(û))
 *   poly2  — m' = v - w
 */
export function indcpaDecrypt(
	kx: KyberExports,
	params: KyberParams,
	skCpa: Uint8Array,
	ct: Uint8Array,
): Uint8Array {
	const { k, du, dv } = params;
	const kyberMem = new Uint8Array(kx.memory.buffer);

	const pvec0 = kx.getPolyvecSlot0();
	const pvec1 = kx.getPolyvecSlot1();
	const poly0 = kx.getPolySlot0();
	const poly1 = kx.getPolySlot1();
	const poly2 = kx.getPolySlot2();
	const ctOff = kx.getCtOffset();
	const skOff = kx.getSkOffset();
	const msgOff = kx.getMsgOffset();

	// Load ct and sk into kyber memory
	kyberMem.set(ct, ctOff);
	kyberMem.set(skCpa, skOff);

	// Steps 1-2: Decompress û and v
	const pvecCompBytes = k * du * 32;
	kx.polyvec_decompress(pvec0, ctOff, k, du);
	kx.poly_decompress(poly0, ctOff + pvecCompBytes, dv);

	// Step 3: Unpack ŝ
	kx.polyvec_frombytes(pvec1, skOff, k);

	// Steps 4-6: w = invNTT(ŝ^T · NTT(û))
	// basemul_acc produces (ŝ·û)/R; invntt cancels it: INTT(ŝ·û) in time domain
	kx.polyvec_ntt(pvec0, k);
	kx.polyvec_basemul_acc_montgomery(poly1, pvec1, pvec0, k);
	kx.poly_invntt(poly1);

	// Steps 7-8: m' = v - w, reduce
	kx.poly_sub(poly2, poly0, poly1);
	kx.poly_reduce(poly2);

	// Step 9-10: poly_tomsg → 32-byte message
	kx.poly_tomsg(msgOff, poly2);
	return kyberMem.slice(msgOff, msgOff + 32);
}
