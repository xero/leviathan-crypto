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
// src/ts/slhdsa/index.ts
//
// SLH-DSA public API, SlhDsa128f / SlhDsa192f / SlhDsa256f classes.
// FIPS 205, Stateless Hash-Based Digital Signature Standard.
//
// Phase 2 surface: keygen / sign / verify, plus the HashSLH-DSA family
// (signHash / verifyHash) and prehashed variants (signHashPrehashed /
// verifyHashPrehashed). Use init({ slhdsa, ... }) before constructing
// any class. Pure-mode usage needs only the slhdsa module; HashSLH-DSA
// with SHA-2 pre-hash adds sha2, with SHA-3 / SHAKE pre-hash adds sha3.

import { initModule, getInstance, isInitialized, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import type { SlhDsaExports, SlhDsaKeyPair } from './types.js';
import type { Sha3Exports } from '../mldsa/types.js';
import type { Sha2Exports } from '../sha2/types.js';
import { type SlhDsaParams, SLHDSA128F, SLHDSA192F, SLHDSA256F } from './params.js';
import { slhSignInternalTs, signWithPrehash } from './sign.js';
import { slhVerifyInternalTs, verifyWithPrehash } from './verify.js';
import { constructMPrimePure } from './prehash.js';
import {
	validateContext,
	validateSigningKey,
	validateRnd,
	validateMessage,
	validateDigest,
} from './validate.js';
import {
	type PreHashAlgorithm,
	algoNeedsSha2,
	algoNeedsSha3,
	digestSize,
	preHashMessage,
} from './prehash.js';

export async function slhdsaInit(source: WasmSource): Promise<void> {
	return initModule('slhdsa', source);
}

export type { WasmSource };
export type { SlhDsaExports, SlhDsaKeyPair } from './types.js';
export { SLHDSA128F, SLHDSA192F, SLHDSA256F };
export type { SlhDsaParams };
export type { PreHashAlgorithm } from './prehash.js';
export { isInitialized };

/** Return the slhdsa WASM instance exports. Internal helper for tests that
 *  need raw access to the ADRS / hash / sponge primitives; consumers use
 *  the SlhDsa* classes below. */
export function getSlhDsaExports(): SlhDsaExports {
	return getInstance('slhdsa').exports as unknown as SlhDsaExports;
}

// ── Base class ──────────────────────────────────────────────────────────────

export class SlhDsaBase {
	readonly params: SlhDsaParams;

	constructor(params: SlhDsaParams) {
		if (!isInitialized('slhdsa'))
			throw new Error('leviathan-crypto: call init({ slhdsa: ... }) before using SlhDsa classes');
		this.params = params;
	}

	private get x(): SlhDsaExports {
		return getInstance('slhdsa').exports as unknown as SlhDsaExports;
	}

	private get sx(): Sha3Exports {
		return getInstance('sha3').exports as unknown as Sha3Exports;
	}

	private get sha2x(): Sha2Exports {
		return getInstance('sha2').exports as unknown as Sha2Exports;
	}

	/**
	 * Deterministic key generation, FIPS 205 §9.1 Algorithm 18.
	 * @param seed 3n bytes laid out as `SK.seed ‖ SK.prf ‖ PK.seed`. Each
	 *             component is `n` bytes (16 for 128f, 24 for 192f, 32 for
	 *             256f). The slh_keygen_internal entry consumes this layout
	 *             directly.
	 */
	keygenDerand(seed: Uint8Array): SlhDsaKeyPair {
		_assertNotOwned('slhdsa');
		const n = this.params.n;
		if (!(seed instanceof Uint8Array))
			throw new TypeError('leviathan-crypto: keygen seed must be a Uint8Array');
		if (seed.length !== 3 * n)
			throw new RangeError(
				`leviathan-crypto: keygen seed must be ${3 * n} bytes (SK.seed||SK.prf||PK.seed) for `
				+ `${this.params.paramSet} (got ${seed.length})`,
			);
		const x = this.x;
		const mem = new Uint8Array(x.memory.buffer);
		const inOff  = x.getInputOffset();
		const outOff = x.getOutOffset();
		try {
			this.params.wasmSelector();
			mem.set(seed, inOff);
			x.slhKeygenInternal();
			const sk = mem.slice(outOff,                     outOff + this.params.skBytes);
			const pk = mem.slice(outOff + this.params.skBytes, outOff + this.params.skBytes + this.params.pkBytes);
			return { verificationKey: pk, signingKey: sk };
		} finally {
			// INPUT held SK.seed ‖ SK.prf ‖ PK.seed; SK.seed and SK.prf are
			// secret. Wipe the lib's staging copy unconditionally.
			mem.fill(0, inOff, inOff + 3 * n);
			x.wipeBuffers();
		}
	}

	/** Random key generation, wraps `keygenDerand` with `randomBytes(3n)`. */
	keygen(): SlhDsaKeyPair {
		const seed = randomBytes(3 * this.params.n);
		try {
			return this.keygenDerand(seed);
		} finally {
			wipe(seed);
		}
	}

	/**
	 * Hedged signing, FIPS 205 §3.4 / §10.2.1 Algorithm 22.
	 * Generates a fresh n-byte addrnd (opt_rand) per signature; two
	 * signatures over the same (sk, M, ctx) produce different bytes.
	 * Hedged signing is recommended over deterministic because hedged
	 * signatures remain unforgeable under fault attacks that bias the
	 * rejection-sampling stream (FIPS 205 §3.4 / §9.2).
	 */
	sign(sk: Uint8Array, M: Uint8Array, ctx: Uint8Array = new Uint8Array(0)): Uint8Array {
		_assertNotOwned('slhdsa');
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const MPrime = constructMPrimePure(M, ctx);
		const optRand = randomBytes(this.params.n);
		try {
			return slhSignInternalTs(this.x, this.params, sk, MPrime, optRand);
		} finally {
			wipe(optRand);
			wipe(MPrime);
		}
	}

	/**
	 * Deterministic signing, FIPS 205 §3.4. Sets opt_rand ← PK.seed so two
	 * signatures over the same (sk, M, ctx) produce identical bytes.
	 * Caller accepts the §3.4 caveat: deterministic signatures are
	 * vulnerable to fault attacks that bias secret-derived intermediates;
	 * use only when no entropy is available or determinism is a hard
	 * protocol requirement. PK.seed lives at sk[2n..3n] inside the
	 * `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` encoding (FIPS 205 §9.1).
	 */
	signDeterministic(sk: Uint8Array, M: Uint8Array, ctx: Uint8Array = new Uint8Array(0)): Uint8Array {
		_assertNotOwned('slhdsa');
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const n = this.params.n;
		// PK.seed slice is sk-derived (not lib-allocated), so we do NOT
		// wipe it in finally; the caller's sk lifecycle owns it. Using a
		// subarray view rather than a slice would also work and would
		// share memory with sk; slice is cheap and keeps the optRand
		// buffer self-contained for the WASM driver's INPUT staging.
		const optRand = sk.slice(2 * n, 3 * n);
		const MPrime = constructMPrimePure(M, ctx);
		try {
			return slhSignInternalTs(this.x, this.params, sk, MPrime, optRand);
		} finally {
			wipe(MPrime);
			// optRand is a copy of PK.seed (which is part of sk and thus
			// already known to the caller); the slice itself is library
			// scratch though, so wipe it for hygiene.
			wipe(optRand);
		}
	}

	/**
	 * Externally-randomised signing, testing / CAVP API. Caller supplies
	 * the n-byte opt_rand; library does not mix in additional entropy.
	 * Hard contract on the caller: opt_rand MUST come from an approved
	 * RBG and MUST NOT be reused across signatures. ACVP SLH-DSA sigGen
	 * vectors (with a supplied additionalRandomness) drive this path.
	 */
	signDerand(
		sk:      Uint8Array,
		M:       Uint8Array,
		optRand: Uint8Array,
		ctx:     Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		validateRnd(optRand, this.params);
		const MPrime = constructMPrimePure(M, ctx);
		try {
			return slhSignInternalTs(this.x, this.params, sk, MPrime, optRand);
		} finally {
			wipe(MPrime);
		}
	}

	/**
	 * Pure SLH-DSA verify, FIPS 205 §10.3 Algorithm 24 / §9.3 Algorithm 20.
	 *
	 * Returns boolean. Wrong-length pk / sig return false (FIPS 205 §3.6.2
	 * structural mismatch; same posture as ML-DSA verify). Throws
	 * `SigningError('sig-ctx-too-long')` only on the caller-side contract
	 * violation `ctx.length > 255`.
	 */
	verify(
		pk:  Uint8Array,
		M:   Uint8Array,
		sig: Uint8Array,
		ctx: Uint8Array = new Uint8Array(0),
	): boolean {
		_assertNotOwned('slhdsa');
		validateMessage(M);
		// FIPS 205 §3.6.2 / §10.3 Algorithm 24 line 5, wrong-length pk or σ
		// is not a caller bug; it is a structural mismatch that cannot
		// verify. Return false rather than throw.
		if (!(pk  instanceof Uint8Array) || pk.length  !== this.params.pkBytes)  return false;
		if (!(sig instanceof Uint8Array) || sig.length !== this.params.sigBytes) return false;
		validateContext(ctx);
		const MPrime = constructMPrimePure(M, ctx);
		try {
			return slhVerifyInternalTs(this.x, this.params, pk, MPrime, sig);
		} finally {
			wipe(MPrime);
		}
	}

	// ── HashSLH-DSA, FIPS 205 §10.2.2 / §10.3 (pre-hash variant) ─────────
	//
	// HashSLH-DSA wraps the same Sign_internal / Verify_internal primitives
	// pure SLH-DSA uses, but pre-hashes M and builds M' with domain-sep
	// byte 0x01 plus the hash function's OID DER bytes; signatures
	// produced by sign / signHash on the same key are NOT interchangeable
	// per FIPS 205 §10.2 narrative.
	//
	// `ph` is the LAST positional parameter on every HashSLH-DSA method
	// (mirrors HashML-DSA's choice). There is no sensible default; callers
	// must select one explicitly.
	//
	// `init({ sha2: ... })` is required only when `ph` is a SHA-2 family
	// algorithm. `init({ sha3: ... })` is required when `ph` is a SHA-3
	// or SHAKE algorithm. Pure-SLH-DSA usage needs neither (slhdsa-wasm
	// has its own embedded Keccak permutation).

	private _assertHashPrereqs(ph: PreHashAlgorithm): void {
		// Validate ph before any other dispatch so widened-type callers
		// (e.g. parsing a vector file via `as PreHashAlgorithm`) hit the
		// canonical "unsupported HashSLH-DSA pre-hash" RangeError rather
		// than a downstream sha2-not-initialized error.
		digestSize(ph);

		// FIPS 205 §10.2.2: "SHA-256 and SHAKE128 are only appropriate
		// for use with SLH-DSA parameter sets that are claimed to be in
		// security category 1." Enforce this at the public surface: a
		// category-3 or category-5 key may not be used with SHA-256 or
		// SHAKE128 prehash.
		if ((ph === 'SHA2-256' || ph === 'SHAKE128') && this.params.securityCategory !== 1)
			throw new RangeError(
				`leviathan-crypto: HashSLH-DSA pre-hash '${ph}' is only appropriate for security category 1 `
				+ `(see FIPS 205 §10.2.2); ${this.params.paramSet} is security category ${this.params.securityCategory}`,
			);

		if (algoNeedsSha2(ph)) {
			if (!isInitialized('sha2'))
				throw new Error(
					'leviathan-crypto: call init({ sha2: ... }) before HashSLH-DSA with SHA-2 pre-hash',
				);
			_assertNotOwned('sha2');
		}
		if (algoNeedsSha3(ph)) {
			if (!isInitialized('sha3'))
				throw new Error(
					'leviathan-crypto: call init({ sha3: ... }) before HashSLH-DSA with SHA-3 / SHAKE pre-hash',
				);
			_assertNotOwned('sha3');
		}
	}

	/**
	 * Hedged HashSLH-DSA sign, FIPS 205 §10.2.2 Algorithm 23.
	 *
	 * Pre-hashes `M` with the chosen approved function `ph`, builds
	 * M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(ph) ‖ PH_M, then drives
	 * slh_sign_internal with a fresh n-byte opt_rand (FIPS 205 §3.4
	 * recommended default; see {@link sign} for the rationale).
	 */
	signHash(
		sk:  Uint8Array,
		M:   Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const sha3x = algoNeedsSha3(ph) ? this.sx    : undefined;
		const PH_M  = preHashMessage(sha3x, sha2x, ph, M);
		const optRand = randomBytes(this.params.n);
		try {
			return signWithPrehash(this.x, this.params, sk, PH_M, ph, ctx, optRand);
		} finally {
			wipe(optRand);
			wipe(PH_M);
			if (sha2x) sha2x.wipeBuffers();
			if (sha3x) sha3x.wipeBuffers();
		}
	}

	/**
	 * Deterministic HashSLH-DSA sign, FIPS 205 §10.2.2 Algorithm 23 with
	 * opt_rand ← PK.seed (the deterministic substitute per FIPS 205 §3.4).
	 * Same fault-attack caveat as {@link signDeterministic}.
	 */
	signHashDeterministic(
		sk:  Uint8Array,
		M:   Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const n = this.params.n;
		const optRand = sk.slice(2 * n, 3 * n);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const sha3x = algoNeedsSha3(ph) ? this.sx    : undefined;
		const PH_M  = preHashMessage(sha3x, sha2x, ph, M);
		try {
			return signWithPrehash(this.x, this.params, sk, PH_M, ph, ctx, optRand);
		} finally {
			wipe(PH_M);
			wipe(optRand);
			if (sha2x) sha2x.wipeBuffers();
			if (sha3x) sha3x.wipeBuffers();
		}
	}

	/**
	 * Externally-randomised HashSLH-DSA sign, testing / CAVP API. Caller
	 * supplies the n-byte opt_rand (same contract as {@link signDerand}).
	 * Used to oracle ACVP HashSLH-DSA sigGen vectors with byte-identical
	 * output.
	 */
	signHashDerand(
		sk:      Uint8Array,
		M:       Uint8Array,
		ph:      PreHashAlgorithm,
		optRand: Uint8Array,
		ctx:     Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		validateRnd(optRand, this.params);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const sha3x = algoNeedsSha3(ph) ? this.sx    : undefined;
		const PH_M  = preHashMessage(sha3x, sha2x, ph, M);
		try {
			return signWithPrehash(this.x, this.params, sk, PH_M, ph, ctx, optRand);
		} finally {
			wipe(PH_M);
			if (sha2x) sha2x.wipeBuffers();
			if (sha3x) sha3x.wipeBuffers();
		}
	}

	/**
	 * HashSLH-DSA verify, FIPS 205 §10.3 Algorithm 25.
	 *
	 * Same return / throw posture as {@link verify}: returns boolean for
	 * every signature outcome (including malformed-σ → false), throws
	 * `SigningError` only on caller-side contract violations
	 * (`ctx.length > 255`) or `RangeError` on category violations and
	 * unsupported `ph`.
	 */
	verifyHash(
		pk:  Uint8Array,
		M:   Uint8Array,
		sig: Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array = new Uint8Array(0),
	): boolean {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateMessage(M);
		if (!(pk  instanceof Uint8Array) || pk.length  !== this.params.pkBytes)  return false;
		if (!(sig instanceof Uint8Array) || sig.length !== this.params.sigBytes) return false;
		validateContext(ctx);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const sha3x = algoNeedsSha3(ph) ? this.sx    : undefined;
		const PH_M  = preHashMessage(sha3x, sha2x, ph, M);
		try {
			return verifyWithPrehash(this.x, this.params, pk, PH_M, sig, ph, ctx);
		} finally {
			wipe(PH_M);
			if (sha2x) sha2x.wipeBuffers();
			if (sha3x) sha3x.wipeBuffers();
		}
	}

	// ── HashSLH-DSA prehashed variants, FIPS 205 §10.2.2 ──────────────────
	//
	// The "caller already computed PH" surface. signHash family above runs
	// PH ← Hash(M, ph) internally; the prehashed family skips that step
	// and accepts PH directly. Use them when M is not buffered in one
	// place (streaming signers, protocols that already produced a digest
	// as part of a transcript) or when a verifier prescribes a specific
	// prehash and hands you the bytes.
	//
	// Wrong-size digest is a contract violation on the sign side (throws
	// `SigningError('sig-malformed-input')`) and a structural verdict on
	// the verify side (returns false, no throw), mirroring §3.6.2 for
	// wrong-size pk / σ.

	/**
	 * Hedged HashSLH-DSA sign with a caller-supplied prehash. FIPS 205
	 * §10.2.2 Algorithm 23 lines 18-25 (the post-PH path).
	 *
	 * `digest` must be exactly `digestSize(ph)` bytes; a mismatch throws
	 * `SigningError('sig-malformed-input')`. The caller owns `digest`
	 * and is responsible for wiping it; this method never mutates the
	 * buffer. Hedged variant generates a fresh n-byte opt_rand per call.
	 */
	signHashPrehashed(
		sk:     Uint8Array,
		digest: Uint8Array,
		ph:     PreHashAlgorithm,
		ctx:    Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateContext(ctx);
		validateDigest(digest, ph);
		const optRand = randomBytes(this.params.n);
		try {
			return signWithPrehash(this.x, this.params, sk, digest, ph, ctx, optRand);
		} finally {
			wipe(optRand);
		}
	}

	/**
	 * Deterministic HashSLH-DSA sign with a caller-supplied prehash,
	 * opt_rand ← PK.seed per FIPS 205 §3.4. Same fault-attack caveat as
	 * {@link signDeterministic}.
	 */
	signHashPrehashedDeterministic(
		sk:     Uint8Array,
		digest: Uint8Array,
		ph:     PreHashAlgorithm,
		ctx:    Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateContext(ctx);
		validateDigest(digest, ph);
		const n = this.params.n;
		const optRand = sk.slice(2 * n, 3 * n);
		try {
			return signWithPrehash(this.x, this.params, sk, digest, ph, ctx, optRand);
		} finally {
			wipe(optRand);
		}
	}

	/**
	 * Externally-randomised HashSLH-DSA sign with a caller-supplied
	 * prehash, testing / CAVP API. Caller supplies the n-byte opt_rand:
	 * MUST come from an approved RBG and MUST NOT be reused across
	 * signatures.
	 */
	signHashPrehashedDerand(
		sk:      Uint8Array,
		digest:  Uint8Array,
		ph:      PreHashAlgorithm,
		optRand: Uint8Array,
		ctx:     Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateContext(ctx);
		validateRnd(optRand, this.params);
		validateDigest(digest, ph);
		return signWithPrehash(this.x, this.params, sk, digest, ph, ctx, optRand);
	}

	/**
	 * HashSLH-DSA verify with a caller-supplied prehash. FIPS 205 §10.3
	 * Algorithm 25 lines 16-19 (the post-PH path).
	 *
	 * Returns boolean for every signature outcome. Wrong-length pk / σ
	 * and wrong-size `digest` all return `false` (FIPS 205 §3.6.2 /
	 * §10.3 structural mismatch). Throws on caller-side contract
	 * violations only (`ctx.length > 255`, unsupported `ph`, category
	 * mismatch).
	 */
	verifyHashPrehashed(
		pk:     Uint8Array,
		digest: Uint8Array,
		sig:    Uint8Array,
		ph:     PreHashAlgorithm,
		ctx:    Uint8Array = new Uint8Array(0),
	): boolean {
		_assertNotOwned('slhdsa');
		this._assertHashPrereqs(ph);
		if (!(pk  instanceof Uint8Array) || pk.length  !== this.params.pkBytes)  return false;
		if (!(sig instanceof Uint8Array) || sig.length !== this.params.sigBytes) return false;
		if (!(digest instanceof Uint8Array) || digest.length !== digestSize(ph)) return false;
		validateContext(ctx);
		return verifyWithPrehash(this.x, this.params, pk, digest, sig, ph, ctx);
	}

	dispose(): void {
		// SlhDsaBase is atomic-only (no per-instance state beyond the
		// readonly params). Every public method already runs
		// wipeBuffers() in its own finally, so this dispose is just a
		// final hygiene pass for defence-in-depth.
		try {
			this.x.wipeBuffers();
		} catch {
			// dispose() is idempotent and must not throw even if the
			// module was somehow torn down before the user finished.
		}
	}
}

// ── Public classes ──────────────────────────────────────────────────────────

/** SLH-DSA-SHAKE-128f, FIPS 205 §11.1 Table 2 (NIST security category 1). */
export class SlhDsa128f extends SlhDsaBase {
	constructor() {
		super(SLHDSA128F);
	}
}

/** SLH-DSA-SHAKE-192f, FIPS 205 §11.1 Table 2 (NIST security category 3). */
export class SlhDsa192f extends SlhDsaBase {
	constructor() {
		super(SLHDSA192F);
	}
}

/** SLH-DSA-SHAKE-256f, FIPS 205 §11.1 Table 2 (NIST security category 5). */
export class SlhDsa256f extends SlhDsaBase {
	constructor() {
		super(SLHDSA256F);
	}
}
