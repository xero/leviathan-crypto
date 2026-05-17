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
// src/ts/ecdsa/index.ts
//
// ECDSA-P256 public API. FIPS 186-5 §6, ECDSA over the NIST P-256
// curve (SP 800-186 §3.2.1.3). Hedged-or-deterministic K derivation
// per RFC 6979 §3.2 and draft-irtf-cfrg-det-sigs-with-noise-05,
// strict-S verification posture (low-S enforced).
//
// Per-call WASM lifecycle: every public method runs against the
// singleton p256 instance, stages inputs at fixed offsets above the
// WASM's mutable buffer region, calls the underlying export, copies
// outputs to fresh `Uint8Array`s, then wipes the staged secret-bearing
// inputs and the WASM's internal scratch. The WASM-side `wipeBuffers`
// covers the substrate's mutable region (scalars, points, HMAC-DRBG
// state, embedded SHA-256 streaming state); the TS layer is
// responsible for wiping its own I/O-staging region.
//
// SEC 1 §2.3.4 uncompressed-pk emission: `pointDecompress` is a free
// function that runs the substrate's `pointDecompress` export over a
// 33-byte compressed input and writes the 65-byte `0x04 || X || Y`
// form. `EcdsaP256.keygenUncompressed` is the keygen variant that
// returns the uncompressed form directly. The standalone
// `EcdsaP256Suite` continues to use compressed pk; the uncompressed
// surface exists for callers (notably the composite ML-DSA + ECDSA
// suites) whose wire format spec requires the uncompressed encoding.

import { getInstance, initModule, isInitialized, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import { SigningError } from '../errors.js';
import type { EcdsaP256Exports, EcdsaP256KeyPair } from './types.js';
import {
	validateSeed,
	validateSecretKey,
	validatePublicKey,
	validateMessageHash,
	validateSignature,
	validateEntropy,
} from './validate.js';

/**
 * Initialise the p256 WASM module. Loads the underlying binary
 * (scalar, no SIMD) into the `p256` slot.
 */
export async function ecdsaP256Init(source: WasmSource): Promise<void> {
	return initModule('p256', source);
}

export type { WasmSource };
export type { EcdsaP256KeyPair, EcdsaP256Exports } from './types.js';
export { isInitialized };
export { encodeEcPrivateKey, decodeEcPrivateKey } from './ecprivatekey-der.js';

// ── I/O staging layout ─────────────────────────────────────────────────────
//
// The p256 module's mutable buffer region ends at BUFFER_END = 7054
// (see src/asm/p256/buffers.ts). The TS layer stages caller-supplied
// inputs and reads outputs from a fixed region above that. The module
// is allocated 3 pages (196608 bytes); the I/O region stretches from
// 8192 to the end of linear memory.
//
// Each slot is sized to its maximum useful content and rounded to a
// 32-byte boundary for layout clarity. The WASM exports read every
// input once at the start of execution, so co-locating per-call
// inputs in this region is safe.

const IO_BASE          = 8192;
const SEED_STAGE       = IO_BASE;          // 32 bytes (seed for keygen, sk for sign)
const PK_STAGE         = IO_BASE + 64;     // 33 bytes (compressed pk, SEC 1 §2.3.3)
const SIG_STAGE        = IO_BASE + 128;    // 64 bytes (raw r||s)
const MSG_HASH_STAGE   = IO_BASE + 192;    // 32 bytes (SHA-256 digest)
const RND_STAGE        = IO_BASE + 224;    // 32 bytes (per-call entropy Z)
const POINT_STAGE      = IO_BASE + 256;    // 96 bytes (projective X:Y:Z, decompression output)
const PK_XY_STAGE      = IO_BASE + 352;    // 64 bytes (BE X || Y, staging for SEC 1 §2.3.4 emit)

function ioWipe(mx: EcdsaP256Exports): void {
	// Zero the entire TS-managed staging region. wipeBuffers covers
	// MUTABLE_START..BUFFER_END only; the I/O region above lives outside
	// that range and must be scrubbed by the wrapper.
	new Uint8Array(mx.memory.buffer).fill(0, IO_BASE, mx.memory.buffer.byteLength);
}

function rethrowTrap(err: unknown, discriminator: string, message: string): never {
	// The WASM module's fault-injection check (sign's pk-mismatch path)
	// terminates with `unreachable`, which surfaces as
	// WebAssembly.RuntimeError. Re-throw any such trap as a typed
	// SigningError so callers can branch on it.
	if (err instanceof WebAssembly.RuntimeError)
		throw new SigningError(discriminator, message);
	throw err;
}

/**
 * Normalise a caller-supplied public key to the 33-byte compressed
 * SEC 1 §2.3.3 form required by the WASM ABI. 33-byte inputs are
 * returned as-is; 65-byte inputs (uncompressed, SEC 1 §2.3.4,
 * 0x04 || x || y) are converted by dropping y and setting the prefix
 * to 0x02 or 0x03 based on the parity of the y coordinate (LSB of
 * y[31] in big-endian). Constant-time is not required: pk is public.
 *
 * Validation of the prefix byte happens at the WASM layer
 * (`pointDecompress` rejects anything that is not 0x02 / 0x03 with an
 * on-curve x), so this helper does not branch on whether the input
 * was a strict uncompressed (0x04) or hybrid (0x06 / 0x07, SEC 1
 * §2.3.5) encoding.
 */
function normalizePublicKey(pk: Uint8Array): Uint8Array {
	if (pk.length === 33) return pk;
	// pk has already passed validatePublicKey, so length is 33 or 65.
	const out = new Uint8Array(33);
	out[0] = 0x02 | (pk[64] & 0x01);
	out.set(pk.subarray(1, 33), 1);
	return out;
}

/**
 * Decompress a 33-byte SEC 1 §2.3.3 compressed P-256 public key to the
 * 65-byte SEC 1 §2.3.4 uncompressed encoding `0x04 || X || Y`.
 *
 * The compressed form encodes only the affine x coordinate plus a
 * single parity bit (in the prefix byte: 0x02 even-y, 0x03 odd-y).
 * Recovery of y solves the curve equation
 * `y² = x³ - 3x + b mod p` (SP 800-186 §3.2.1.3, P-256 has a = -3)
 * and selects the y root whose parity matches the prefix. The
 * substrate runs the modular square root inside the p256 WASM
 * (`feSqrt` via the p ≡ 3 (mod 4) shortcut, x^((p+1)/4)); rejecting
 * invalid inputs that have no square root or whose recovered (x, y)
 * lies off-curve.
 *
 * Rejection cases (all throw `SigningError('sig-malformed-input')`):
 *   - prefix byte not in {0x02, 0x03}
 *   - x coordinate is not the x of any on-curve point (no quadratic
 *     residue exists for `x³ - 3x + b mod p`)
 *
 * Length / shape rejections throw `TypeError` / `RangeError` per the
 * usual leviathan-crypto contract-violation posture.
 *
 * Requires `init({ p256: ... })`. Uses the same p256 module singleton
 * as `EcdsaP256`; concurrency-safe alongside non-stateful uses (the
 * `_assertNotOwned` check fires if a stateful instance is holding
 * the module).
 *
 * @param pk33 33-byte compressed pk per SEC 1 §2.3.3
 * @returns    65-byte uncompressed pk per SEC 1 §2.3.4 (0x04 || X || Y)
 */
export function pointDecompress(pk33: Uint8Array): Uint8Array {
	if (!isInitialized('p256'))
		throw new Error('leviathan-crypto: call init({ p256: ... }) before using pointDecompress');
	if (!(pk33 instanceof Uint8Array))
		throw new TypeError('leviathan-crypto: ecdsa-p256 compressed public key must be a Uint8Array');
	if (pk33.length !== 33)
		throw new RangeError(
			`leviathan-crypto: ecdsa-p256 compressed public key must be 33 bytes (got ${pk33.length})`,
		);
	if (pk33[0] !== 0x02 && pk33[0] !== 0x03)
		throw new SigningError(
			'sig-malformed-input',
			'leviathan-crypto: ecdsa-p256 compressed public key prefix must be 0x02 or 0x03 per SEC 1 §2.3.3 '
			+ `(got 0x${pk33[0].toString(16).padStart(2, '0')})`,
		);

	_assertNotOwned('p256');
	const mx  = getInstance('p256').exports as unknown as EcdsaP256Exports;
	const mem = new Uint8Array(mx.memory.buffer);
	mem.set(pk33, PK_STAGE);
	try {
		const ok = mx.pointDecompress(POINT_STAGE, PK_STAGE);
		if (ok !== 1)
			throw new SigningError(
				'sig-malformed-input',
				'leviathan-crypto: ecdsa-p256 compressed public key x coordinate has no on-curve y '
				+ '(point decompression failed per SEC 1 §2.3.4)',
			);
		// pointDecompress writes (X : Y : Z = 1) in the FE limb form
		// at POINT_STAGE..+96. feToBytes converts each FE to 32-byte BE
		// per SP 800-186 §3.2.1.3 coordinate encoding.
		mx.feToBytes(PK_XY_STAGE,      POINT_STAGE);       // X (32 BE)
		mx.feToBytes(PK_XY_STAGE + 32, POINT_STAGE + 32);  // Y (32 BE)
		const out = new Uint8Array(65);
		out[0] = 0x04;
		out.set(mem.subarray(PK_XY_STAGE, PK_XY_STAGE + 64), 1);
		return out;
	} finally {
		ioWipe(mx);
		mx.wipeBuffers();
	}
}

export class EcdsaP256 {
	constructor() {
		if (!isInitialized('p256'))
			throw new Error('leviathan-crypto: call init({ p256: ... }) before using EcdsaP256');
	}

	private get mx(): EcdsaP256Exports {
		return getInstance('p256').exports as unknown as EcdsaP256Exports;
	}

	/**
	 * Deterministic ECDSA-P256 key generation from a 32-byte seed.
	 * d = seed mod n per FIPS 186-5 §A.4.2 (testing-candidates style,
	 * single candidate). pk = [d]G compressed to 33 bytes per SEC 1
	 * §2.3.3. The vanishingly rare seed mod n == 0 case traps in the
	 * WASM and surfaces as a SigningError here.
	 *
	 * @param seed 32-byte BE input
	 * @returns 33-byte compressed pk and a fresh 32-byte copy of the
	 *          secret scalar d (sk === seed for this derivation, the
	 *          caller may use either as the private value).
	 */
	keygenDerand(seed: Uint8Array): EcdsaP256KeyPair {
		_assertNotOwned('p256');
		validateSeed(seed);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(seed, SEED_STAGE);
		try {
			try {
				mx.ecdsaKeygen(SEED_STAGE, PK_STAGE);
			} catch (err) {
				rethrowTrap(
					err,
					'sig-malformed-input',
					'leviathan-crypto: ecdsa-p256 keygen aborted, seed mod n is zero '
					+ '(2^-256 probability event; supply a different seed)',
				);
			}
			const publicKey = mem.slice(PK_STAGE, PK_STAGE + 33);
			const secretKey = new Uint8Array(32);
			secretKey.set(seed);
			return { publicKey, secretKey };
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/** Random ECDSA-P256 key generation, wraps `keygenDerand` with `randomBytes(32)`. */
	keygen(): EcdsaP256KeyPair {
		const seed = randomBytes(32);
		try {
			return this.keygenDerand(seed);
		} finally {
			wipe(seed);
		}
	}

	/**
	 * Key generation that returns the public key in the 65-byte SEC 1
	 * §2.3.4 uncompressed encoding `0x04 || X || Y`, rather than the
	 * 33-byte compressed form `keygen` / `keygenDerand` return. The
	 * secret-key half is the same 32-byte raw scalar `d`.
	 *
	 * Internally runs `keygen` (or `keygenDerand` if a seed is supplied)
	 * to obtain the compressed pk, then `pointDecompress` to expand it.
	 * The compressed intermediate is wiped before return.
	 *
	 * @param seed Optional 32-byte seed; passes through to `keygenDerand`
	 *             when present, falls back to `keygen` (CSPRNG seed) when
	 *             omitted.
	 */
	keygenUncompressed(seed?: Uint8Array): EcdsaP256KeyPair {
		const kp = seed === undefined ? this.keygen() : this.keygenDerand(seed);
		try {
			const publicKey = pointDecompress(kp.publicKey);
			return { publicKey, secretKey: kp.secretKey };
		} catch (err) {
			wipe(kp.secretKey);
			throw err;
		} finally {
			wipe(kp.publicKey);
		}
	}

	/**
	 * Hedged-or-deterministic ECDSA-P256 sign per FIPS 186-5 §6.4 with
	 * RFC 6979 §3.5 low-S normalisation. The K nonce is derived per
	 * RFC 6979 §3.2 (deterministic) when `rnd` is all-zero, or per
	 * draft-irtf-cfrg-det-sigs-with-noise-05 (hedged) otherwise. The
	 * hedged path is the recommended default; pass `randomBytes(32)`.
	 *
	 * The WASM re-derives pk = [d]G internally and compares it against
	 * the caller-supplied `pk`. A mismatch traps via `unreachable` and
	 * is rethrown as `SigningError('sig-malformed-input')`. This
	 * defends against fault injection that would bias the per-signature
	 * randomness derivation by forcing the caller to also know pk.
	 *
	 * @param sk       32-byte secret scalar d
	 * @param pk       33-byte compressed or 65-byte uncompressed pk;
	 *                 cross-checked by WASM after derivation
	 * @param msgHash  32-byte SHA-256(M) digest (caller-computed)
	 * @param rnd      32-byte per-call entropy Z; all-zero selects
	 *                 deterministic RFC 6979 §3.2, non-zero selects
	 *                 the hedged path
	 * @returns 64-byte raw r || s signature, low-S normalised
	 * @throws  SigningError('sig-malformed-input') on pk-mismatch
	 *          (fault-injection trap)
	 */
	sign(sk: Uint8Array, pk: Uint8Array, msgHash: Uint8Array, rnd: Uint8Array): Uint8Array {
		_assertNotOwned('p256');
		validateSecretKey(sk);
		validatePublicKey(pk);
		validateMessageHash(msgHash);
		validateEntropy(rnd);
		const pkC = normalizePublicKey(pk);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk,      SEED_STAGE);
		mem.set(pkC,     PK_STAGE);
		mem.set(msgHash, MSG_HASH_STAGE);
		mem.set(rnd,     RND_STAGE);
		try {
			try {
				mx.ecdsaSign(SEED_STAGE, PK_STAGE, MSG_HASH_STAGE, RND_STAGE, SIG_STAGE);
			} catch (err) {
				rethrowTrap(
					err,
					'sig-malformed-input',
					'leviathan-crypto: ecdsa-p256 sign aborted, pk does not match the pk derived from sk '
					+ '(likely fault injection or caller misuse)',
				);
			}
			return mem.slice(SIG_STAGE, SIG_STAGE + 64);
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/**
	 * Suite-only: hedged-or-deterministic ECDSA-P256 sign that derives
	 * pk internally and skips the fault-injection cross-check, saving
	 * one fixed-base scalar mult per call. Intended for
	 * `EcdsaP256Suite` and other suite-layer callers that hold
	 * only `sk`; the cross-check is degenerate at those call sites
	 * because the caller-supplied pk and the WASM-derived pk both come
	 * from the same call on the same module. Direct-class callers who
	 * hold a stored, known-good pk should keep using `sign(sk, pk, ...)`.
	 *
	 * Underscore-prefixed and intentionally undocumented in the public
	 * API.
	 */
	_signInternalPk(sk: Uint8Array, msgHash: Uint8Array, rnd: Uint8Array): Uint8Array {
		_assertNotOwned('p256');
		validateSecretKey(sk);
		validateMessageHash(msgHash);
		validateEntropy(rnd);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk,      SEED_STAGE);
		mem.set(msgHash, MSG_HASH_STAGE);
		mem.set(rnd,     RND_STAGE);
		try {
			mx.ecdsaSignInternalPk(SEED_STAGE, MSG_HASH_STAGE, RND_STAGE, SIG_STAGE);
			return mem.slice(SIG_STAGE, SIG_STAGE + 64);
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/**
	 * Strict ECDSA-P256 verify per FIPS 186-5 §6.5 with low-S
	 * enforcement (RFC 6979 §3.5). Returns `true` on success, `false`
	 * on every signature failure mode: off-curve / identity pk, r or
	 * s out of [1, n-1], high-S, or the signature equation failing.
	 * Throws only on caller-side contract violations (wrong-length
	 * inputs).
	 *
	 * @param pk       33-byte compressed or 65-byte uncompressed pk
	 * @param msgHash  32-byte SHA-256(M) digest
	 * @param sig      64-byte raw r || s (use `ecdsaSignatureFromDer`
	 *                 to convert DER-encoded signatures first)
	 */
	verify(pk: Uint8Array, msgHash: Uint8Array, sig: Uint8Array): boolean {
		_assertNotOwned('p256');
		validatePublicKey(pk);
		validateMessageHash(msgHash);
		validateSignature(sig);
		const pkC = normalizePublicKey(pk);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(pkC,     PK_STAGE);
		mem.set(msgHash, MSG_HASH_STAGE);
		mem.set(sig,     SIG_STAGE);
		try {
			return mx.ecdsaVerify(PK_STAGE, MSG_HASH_STAGE, SIG_STAGE) === 1;
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	dispose(): void {
		// Defensive idempotent cleanup; every public method already wipes
		// on its own success / throw path. Safe to call multiple times.
		try {
			this.mx.wipeBuffers();
			ioWipe(this.mx);
		} catch { /* idempotent */ }
	}
}
