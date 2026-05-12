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
// ML-DSA public API, MlDsa44, MlDsa65, MlDsa87 classes.
// FIPS 204, Module-Lattice-Based Digital Signature Standard.
//
// Phase-4 surface: keygen / keygenDerand only. sign / verify land in
// phase 5; HashML-DSA in phase 6. Use init({ mldsa, sha3 }) before
// constructing any class, both modules are required.

import { getInstance, initModule, isInitialized, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import type { MlDsaExports, Sha3Exports, MlDsaKeyPair } from './types.js';
import type { Sha2Exports } from '../sha2/types.js';
import { MlDsaParams, MLDSA44, MLDSA65, MLDSA87 } from './params.js';
import { mldsaKeygenInternal } from './keygen.js';
import { mldsaSignInternal, signWithPrehash } from './sign.js';
import { mldsaVerifyInternal, verifyWithPrehash } from './verify.js';
import { constructMPrime } from './format.js';
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
	digestSize,
	preHashMessage,
} from './hashvariant.js';

export async function mldsaInit(source: WasmSource): Promise<void> {
	return initModule('mldsa', source);
}

export type { WasmSource };
export type { MlDsaKeyPair, MlDsaExports, Sha3Exports } from './types.js';
export { MLDSA44, MLDSA65, MLDSA87 };
export type { MlDsaParams };
export type { PreHashAlgorithm } from './hashvariant.js';
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

	private get sha2x(): Sha2Exports {
		return getInstance('sha2').exports as unknown as Sha2Exports;
	}

	/**
	 * Deterministic key generation, FIPS 204 §6.1 Algorithm 6.
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

	/** Random key generation, wraps `keygenDerand` with `randomBytes(32)`. */
	keygen(): MlDsaKeyPair {
		const xi = randomBytes(32);
		try {
			return this.keygenDerand(xi);
		} finally {
			wipe(xi);
		}
	}

	/**
	 * Hedged signing, FIPS 204 §3.4 (recommended default).
	 * Generates a fresh 32-byte rnd via `randomBytes()` per signature; the
	 * rnd is mixed into ρ'' so two signatures over the same (sk, M) produce
	 * different bytes. Hedged signatures are recommended over deterministic
	 * because they remain unforgeable under fault attacks that bias the
	 * rejection-sampling stream (FIPS 204 §3.4 / §3.6.1).
	 */
	sign(sk: Uint8Array, M: Uint8Array, ctx: Uint8Array = new Uint8Array(0)): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		// FIPS 204 §5.2 Algorithm 2 line 10, M' = 0x00 ‖ |ctx| ‖ ctx ‖ M.
		const MPrime = constructMPrime(0x00, ctx, M);
		const rnd = randomBytes(32);
		try {
			return mldsaSignInternal(this.mx, this.sx, this.params, sk, MPrime, rnd);
		} finally {
			wipe(rnd);
			wipe(MPrime);
		}
	}

	/**
	 * Deterministic signing, FIPS 204 §3.4. Sets rnd ← 0³² so two
	 * signatures over the same (sk, M) produce identical bytes. Caller
	 * accepts the §3.4 caveat: deterministic signatures are vulnerable to
	 * fault attacks that bias the SampleInBall stream, use only when no
	 * entropy is available or determinism is a hard protocol requirement.
	 */
	signDeterministic(sk: Uint8Array, M: Uint8Array, ctx: Uint8Array = new Uint8Array(0)): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const MPrime = constructMPrime(0x00, ctx, M);
		const rnd = new Uint8Array(32);   // already zeros
		try {
			return mldsaSignInternal(this.mx, this.sx, this.params, sk, MPrime, rnd);
		} finally {
			wipe(MPrime);
		}
	}

	/**
	 * Externally-randomised signing, testing / CAVP API. Caller supplies
	 * the 32-byte rnd; library does not mix in additional entropy. Hard
	 * contract on the caller: rnd MUST come from an approved RBG and MUST
	 * NOT be reused across signatures. ACVP `sigGen` test vectors (with a
	 * supplied rnd) drive this path.
	 */
	signDerand(
		sk:  Uint8Array,
		M:   Uint8Array,
		ctx: Uint8Array,
		rnd: Uint8Array,
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		validateRnd(rnd);
		const MPrime = constructMPrime(0x00, ctx, M);
		try {
			return mldsaSignInternal(this.mx, this.sx, this.params, sk, MPrime, rnd);
		} finally {
			wipe(MPrime);
		}
	}

	/**
	 * Pure ML-DSA verify, FIPS 204 §5.3 Algorithm 3 / §6.3 Algorithm 8.
	 *
	 * Returns boolean, `true` only if (a) the FIPS 204 norm bound on z
	 * holds and (b) the constant-time comparison of c̃ to the recomputed
	 * c̃' succeeds. Throws RangeError only on caller-side contract
	 * violations (`ctx.length > 255`). Wrong-length pk/sig and malformed
	 * hint encodings are NOT contract violations: they cause `verify` to
	 * return false (FIPS 204 §3.6.2 / §D.3).
	 */
	verify(
		vk:  Uint8Array,
		M:   Uint8Array,
		sig: Uint8Array,
		ctx: Uint8Array = new Uint8Array(0),
	): boolean {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		validateMessage(M);
		// FIPS 204 §3.6.2, wrong-length pk or σ is not a caller bug; it
		// is a structural mismatch that cannot verify. Return false rather
		// than throw, matching how Algorithm 3 returns ⊥ on length mismatch.
		if (!(vk  instanceof Uint8Array) || vk.length  !== this.params.pkBytes)  return false;
		if (!(sig instanceof Uint8Array) || sig.length !== this.params.sigBytes) return false;
		// ctx oversize is a caller-side contract violation per Alg 3 line 1.
		validateContext(ctx);
		const MPrime = constructMPrime(0x00, ctx, M);
		try {
			return mldsaVerifyInternal(this.mx, this.sx, this.params, vk, MPrime, sig);
		} finally {
			wipe(MPrime);
		}
	}

	// ── HashML-DSA, FIPS 204 §5.4 (pre-hash variant) ──────────────────────
	//
	// HashML-DSA wraps the same Sign_internal / Verify_internal primitives
	// pure ML-DSA uses, but pre-hashes M and builds M' with domain-sep byte
	// 0x01 plus the hash function's OID DER bytes, so signatures produced
	// by sign / signHash on the same key are NOT interchangeable. See
	// FIPS 204 §3.6.4 for the cross-protocol attack rationale.
	//
	// `ph` is the LAST positional parameter on every HashML-DSA method.
	// There is no sensible default, the spec lists 12 approved choices and
	// none has cryptographic priority. Callers must select one explicitly.
	//
	// `init({ sha2: ... })` is required only when `ph` is a SHA-2 family
	// algorithm. Using SHA3-* / SHAKE pre-hash needs no additional modules
	// beyond the `mldsa` + `sha3` pair pure ML-DSA already requires.

	private _assertHashPrereqs(ph: PreHashAlgorithm): void {
		// Validate ph before any other dispatch so widened-type callers
		// (e.g. parsing a vector file via `as PreHashAlgorithm`) hit the
		// canonical "unsupported HashML-DSA pre-hash" RangeError rather
		// than a downstream sha2-not-initialized error or a fallthrough.
		digestSize(ph);
		if (algoNeedsSha2(ph)) {
			if (!isInitialized('sha2'))
				throw new Error(
					'leviathan-crypto: call init({ sha2: ... }) before HashML-DSA with SHA-2 pre-hash',
				);
			_assertNotOwned('sha2');
		}
	}

	/**
	 * Hedged HashML-DSA sign, FIPS 204 §5.4 Algorithm 4.
	 *
	 * Pre-hashes `M` with the chosen approved function `ph`, builds
	 * M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(ph) ‖ PH_M, then drives
	 * ML-DSA.Sign_internal with a fresh 32-byte rnd (FIPS 204 §3.4
	 * recommended default; see {@link sign} for the rationale).
	 */
	signHash(
		sk:  Uint8Array,
		M:   Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const PH_M  = preHashMessage(this.sx, sha2x, ph, M);
		const rnd   = randomBytes(32);
		try {
			return signWithPrehash(this.mx, this.sx, this.params, sk, PH_M, ph, ctx, rnd);
		} finally {
			wipe(rnd);
			// PH_M is M-derived (M is public input) so leakage is benign,
			// but discipline matters, wipe it on every path.
			wipe(PH_M);
			// SHA-2 module's INPUT/OUT/H regions held the last block of M
			// and the digest. Wipe them so secret material from any prior
			// sha2 op (e.g. an HMAC) plus this PH_M digest don't linger.
			if (sha2x) sha2x.wipeBuffers();
		}
	}

	/**
	 * Deterministic HashML-DSA sign, FIPS 204 §5.4 Algorithm 4 with
	 * rnd ← 0³². Same fault-attack caveat as {@link signDeterministic}.
	 */
	signHashDeterministic(
		sk:  Uint8Array,
		M:   Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const PH_M  = preHashMessage(this.sx, sha2x, ph, M);
		const rnd   = new Uint8Array(32);   // already zeros
		try {
			return signWithPrehash(this.mx, this.sx, this.params, sk, PH_M, ph, ctx, rnd);
		} finally {
			wipe(PH_M);
			if (sha2x) sha2x.wipeBuffers();
		}
	}

	/**
	 * Externally-randomised HashML-DSA sign, testing / CAVP API. Caller
	 * supplies the 32-byte rnd (same contract as {@link signDerand}). Used
	 * to oracle ACVP HashML-DSA sigGen vectors with byte-identical output.
	 */
	signHashDerand(
		sk:  Uint8Array,
		M:   Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array,
		rnd: Uint8Array,
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateMessage(M);
		validateContext(ctx);
		validateRnd(rnd);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const PH_M  = preHashMessage(this.sx, sha2x, ph, M);
		try {
			return signWithPrehash(this.mx, this.sx, this.params, sk, PH_M, ph, ctx, rnd);
		} finally {
			wipe(PH_M);
			if (sha2x) sha2x.wipeBuffers();
		}
	}

	/**
	 * HashML-DSA verify, FIPS 204 §5.4 Algorithm 5.
	 *
	 * Same return / throw posture as {@link verify}: returns boolean for
	 * every signature outcome (including malformed-σ → false), throws
	 * RangeError only on caller-side contract violations such as
	 * `ctx.length > 255` or unsupported `ph`.
	 */
	verifyHash(
		vk:  Uint8Array,
		M:   Uint8Array,
		sig: Uint8Array,
		ph:  PreHashAlgorithm,
		ctx: Uint8Array = new Uint8Array(0),
	): boolean {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateMessage(M);
		// FIPS 204 §3.6.2, wrong-length pk or σ is not a caller bug; it
		// is a structural mismatch that cannot verify. Return false rather
		// than throw, matching how Algorithm 5 returns false on length
		// mismatch via Verify_internal's structural checks.
		if (!(vk  instanceof Uint8Array) || vk.length  !== this.params.pkBytes)  return false;
		if (!(sig instanceof Uint8Array) || sig.length !== this.params.sigBytes) return false;
		validateContext(ctx);
		const sha2x = algoNeedsSha2(ph) ? this.sha2x : undefined;
		const PH_M  = preHashMessage(this.sx, sha2x, ph, M);
		try {
			return verifyWithPrehash(this.mx, this.sx, this.params, vk, PH_M, sig, ph, ctx);
		} finally {
			wipe(PH_M);
			if (sha2x) sha2x.wipeBuffers();
		}
	}

	// ── HashML-DSA prehashed variants, FIPS 204 §5.4 ──────────────────────
	//
	// These four methods are the "caller already computed PH" surface. The
	// signHash family above runs PH ← Hash(M, ph) internally, then drives
	// Sign_internal; the prehashed family skips step 1 and accepts PH
	// directly. Use them when M is not buffered in one place (streaming
	// signers, protocols that already produced a digest as part of a
	// transcript) or when a verifier prescribes a specific prehash and
	// hands you the bytes.
	//
	// All four mirror the corresponding signHash family arg order with
	// `digest` replacing `M`. ph and ctx keep their positions; signDerand's
	// rnd stays where it is on signHashDerand. Hedged is the default per
	// FIPS 204 §3.4 recommendation; deterministic / derand exist for the
	// same testing / CAVP / no-RBG reasons as the non-prehashed forms.
	//
	// Wrong-size digest is a contract violation on the sign side (throws
	// SigningError('sig-malformed-input')) and a structural verdict on the
	// verify side (returns false, no throw), the same asymmetry §3.6.2
	// applies to wrong-size pk / σ.

	/**
	 * Hedged HashML-DSA sign with a caller-supplied prehash, FIPS 204
	 * §5.4 Algorithm 4 lines 22-24 (the post-PH path).
	 *
	 * `digest` must be exactly `digestSize(ph)` bytes (FIPS 204 §5.4.1);
	 * a mismatch throws `SigningError('sig-malformed-input')`. The caller
	 * owns `digest` and is responsible for wiping it; this method never
	 * mutates the buffer.
	 *
	 * Hedged variant generates a fresh 32-byte rnd internally per
	 * signature, see {@link sign} for the §3.4 rationale.
	 */
	signHashPrehashed(
		sk:     Uint8Array,
		digest: Uint8Array,
		ph:     PreHashAlgorithm,
		ctx:    Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateContext(ctx);
		validateDigest(digest, ph);
		const rnd = randomBytes(32);
		try {
			return signWithPrehash(this.mx, this.sx, this.params, sk, digest, ph, ctx, rnd);
		} finally {
			wipe(rnd);
		}
	}

	/**
	 * Deterministic HashML-DSA sign with a caller-supplied prehash, rnd
	 * ← 0³² per FIPS 204 §3.4. Same fault-attack caveat as
	 * {@link signDeterministic}.
	 */
	signHashPrehashedDeterministic(
		sk:     Uint8Array,
		digest: Uint8Array,
		ph:     PreHashAlgorithm,
		ctx:    Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateContext(ctx);
		validateDigest(digest, ph);
		const rnd = new Uint8Array(32);   // already zeros
		return signWithPrehash(this.mx, this.sx, this.params, sk, digest, ph, ctx, rnd);
	}

	/**
	 * Externally-randomised HashML-DSA sign with a caller-supplied
	 * prehash, testing / CAVP API. Caller supplies the 32-byte rnd (same
	 * contract as {@link signDerand}): rnd MUST come from an approved RBG
	 * and MUST NOT be reused across signatures.
	 */
	signHashPrehashedDerand(
		sk:     Uint8Array,
		digest: Uint8Array,
		ph:     PreHashAlgorithm,
		rnd:    Uint8Array,
		ctx:    Uint8Array = new Uint8Array(0),
	): Uint8Array {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		validateSigningKey(sk, this.params);
		validateContext(ctx);
		validateRnd(rnd);
		validateDigest(digest, ph);
		return signWithPrehash(this.mx, this.sx, this.params, sk, digest, ph, ctx, rnd);
	}

	/**
	 * HashML-DSA verify with a caller-supplied prehash, FIPS 204 §5.4
	 * Algorithm 5 lines 17-19 (the post-PH path).
	 *
	 * Returns boolean for every signature outcome. Wrong-length pk / σ
	 * and wrong-size `digest` all return `false` (FIPS 204 §3.6.2
	 * structural mismatch). Throws `RangeError` only on caller-side
	 * contract violations (`ctx.length > 255`, unsupported `ph`).
	 */
	verifyHashPrehashed(
		vk:     Uint8Array,
		digest: Uint8Array,
		sig:    Uint8Array,
		ph:     PreHashAlgorithm,
		ctx:    Uint8Array = new Uint8Array(0),
	): boolean {
		_assertNotOwned('sha3');
		_assertNotOwned('mldsa');
		this._assertHashPrereqs(ph);
		// FIPS 204 §3.6.2, wrong-length pk / σ are not contract violations;
		// they are structural mismatches that cannot verify. Wrong-size
		// digest follows the same posture (the digest is an input to M',
		// a wrong length means M' would have a different shape than the
		// signer used). Return false rather than throw.
		if (!(vk  instanceof Uint8Array) || vk.length  !== this.params.pkBytes)  return false;
		if (!(sig instanceof Uint8Array) || sig.length !== this.params.sigBytes) return false;
		if (!(digest instanceof Uint8Array) || digest.length !== digestSize(ph)) return false;
		validateContext(ctx);
		return verifyWithPrehash(this.mx, this.sx, this.params, vk, digest, sig, ph, ctx);
	}

	dispose(): void {
		this.mx.wipeBuffers();
		// MlDsaBase does not own the sha3 module, wiping sha3 here would
		// clobber any SHAKE128/SHAKE256 instance live at the time of
		// dispose(). The wipe is not needed: every public mldsa op (only
		// keygen* in phase 4; sign/verify in subsequent phases) calls
		// sx.wipeBuffers() before returning, under the
		// _assertNotOwned('sha3') guard it holds. sha3 scratch carries no
		// residue across an mldsa op boundary.
	}
}

// ── Public classes ──────────────────────────────────────────────────────────

/** ML-DSA-44, FIPS 204 §4 Table 1 (NIST security category 2). */
export class MlDsa44 extends MlDsaBase {
	constructor() {
		super(MLDSA44);
	}
}

/** ML-DSA-65, FIPS 204 §4 Table 1 (NIST security category 3). */
export class MlDsa65 extends MlDsaBase {
	constructor() {
		super(MLDSA65);
	}
}

/** ML-DSA-87, FIPS 204 §4 Table 1 (NIST security category 5). */
export class MlDsa87 extends MlDsaBase {
	constructor() {
		super(MLDSA87);
	}
}
