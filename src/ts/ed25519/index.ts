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
// src/ts/ed25519/index.ts
//
// Ed25519 public API. RFC 8032 §5.1 pure + §5.1.7 prehash, strict
// verification per FIPS 186-5 §7.6.4. Both Ed25519 and X25519 share the
// curve25519 WASM module; `ed25519Init(source)` and `x25519Init(source)`
// both target it and de-dupe at the init() layer.
//
// Per-call WASM lifecycle: every public method runs against the singleton
// curve25519 instance, stages inputs at fixed offsets above the WASM's
// mutable buffer region, calls the underlying export, copies outputs to
// fresh `Uint8Array`s, then wipes the staged secret-bearing inputs and
// the WASM's internal scratch. The WASM-side `wipeBuffers` covers the
// substrate / SHA-512 / ED25519 scratch (MUTABLE_START..BUFFER_END); the
// TS layer is responsible for wiping its own I/O-staging region.

import { getInstance, initModule, isInitialized, _assertNotOwned } from '../init.js';
import type { WasmSource } from '../wasm-source.js';
import { randomBytes, wipe } from '../utils.js';
import { SigningError } from '../errors.js';
import type { Ed25519Exports, Ed25519KeyPair } from './types.js';
import {
	validateSeed,
	validateSecretKey,
	validatePublicKey,
	validateMessage,
	validateSignature,
	validateContext,
	validateDigest,
} from './validate.js';

/**
 * Initialise the curve25519 WASM module under the `ed25519` alias.
 * Equivalent to `x25519Init(source)`; both target the same WASM module
 * and the init layer de-dupes when given identical sources.
 */
export async function ed25519Init(source: WasmSource): Promise<void> {
	return initModule('curve25519', source);
}

export type { WasmSource };
export type { Ed25519KeyPair, Ed25519Exports } from './types.js';
export { isInitialized };

// ── I/O staging layout ─────────────────────────────────────────────────────
//
// The curve25519 module's own mutable buffer region ends at BUFFER_END
// = 7836 (see src/asm/curve25519/buffers.ts). The TS layer stages
// caller-supplied inputs and reads outputs from a fixed region above
// that. The module is allocated 2 pages (131072 bytes); the I/O region
// stretches from 8192 to the end of linear memory.
//
// The WASM functions read every input once at the start of execution
// before touching any of these slots, so co-locating sign's caller pk
// with the WASM's internal ED25519_PK_CHECK scratch slot is safe even
// though they are different addresses (pkOff is read before the WASM
// writes its own derived pk).

const IO_BASE        = 8192;
const SEED_STAGE     = IO_BASE;          // 32 bytes
const PK_STAGE       = IO_BASE + 32;     // 32 bytes
const SIG_STAGE      = IO_BASE + 64;     // 64 bytes
const DIGEST_STAGE   = IO_BASE + 128;    // 64 bytes
const CTX_STAGE      = IO_BASE + 192;    // up to 255 bytes (round up to 256)
const MSG_STAGE      = IO_BASE + 448;    // remainder

function maxMsgLen(memory: WebAssembly.Memory): number {
	return memory.buffer.byteLength - MSG_STAGE;
}

function ioWipe(mx: Ed25519Exports): void {
	// Zero the entire TS-managed staging region. wipeBuffers covers
	// MUTABLE_START..BUFFER_END only, the I/O region above lives outside
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

export class Ed25519 {
	constructor() {
		if (!isInitialized('curve25519'))
			throw new Error('leviathan-crypto: call init({ ed25519: ... }) before using Ed25519');
	}

	private get mx(): Ed25519Exports {
		return getInstance('curve25519').exports as unknown as Ed25519Exports;
	}

	/**
	 * Deterministic Ed25519 key generation, RFC 8032 §5.1.5.
	 * @param seed 32-byte secret seed
	 * @returns 32-byte verifying key and a fresh 32-byte secret-key copy
	 *          of the supplied seed (the spec defines sk = seed).
	 */
	keygenDerand(seed: Uint8Array): Ed25519KeyPair {
		_assertNotOwned('curve25519');
		validateSeed(seed);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(seed, SEED_STAGE);
		try {
			mx.ed25519Keygen(SEED_STAGE, PK_STAGE);
			const publicKey = mem.slice(PK_STAGE, PK_STAGE + 32);
			const secretKey = new Uint8Array(32);
			secretKey.set(seed);
			return { publicKey, secretKey };
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/** Random Ed25519 key generation, wraps `keygenDerand` with `randomBytes(32)`. */
	keygen(): Ed25519KeyPair {
		const seed = randomBytes(32);
		try {
			return this.keygenDerand(seed);
		} finally {
			wipe(seed);
		}
	}

	/**
	 * Pure Ed25519 sign, RFC 8032 §5.1.6.
	 *
	 * The WASM re-derives pk from `sk` internally and compares it against
	 * the caller-supplied `pk`; a mismatch traps via `unreachable` and is
	 * rethrown as `SigningError('sig-ed25519-pk-mismatch')`. This defends
	 * against fault injection that bias the per-signature randomness
	 * derivation by forcing the caller to also know pk.
	 */
	sign(sk: Uint8Array, pk: Uint8Array, M: Uint8Array): Uint8Array {
		_assertNotOwned('curve25519');
		validateSecretKey(sk);
		validatePublicKey(pk);
		validateMessage(M);
		const mx  = this.mx;
		const cap = maxMsgLen(mx.memory);
		if (M.length > cap)
			throw new RangeError(
				`leviathan-crypto: ed25519 pure-mode message length ${M.length} exceeds the per-call `
				+ `WASM input scratch (${cap} bytes); use Ed25519PreHashSuite or SignStream for larger payloads`,
			);
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk, SEED_STAGE);
		mem.set(pk, PK_STAGE);
		mem.set(M,  MSG_STAGE);
		try {
			try {
				mx.ed25519Sign(SEED_STAGE, PK_STAGE, MSG_STAGE, M.length, SIG_STAGE);
			} catch (err) {
				rethrowTrap(
					err,
					'sig-malformed-input',
					'leviathan-crypto: ed25519 sign aborted, pk does not match the pk derived from sk '
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
	 * Ed25519ph sign, RFC 8032 §5.1.7 (prehash, dom2 phflag=1).
	 *
	 * Caller supplies the 64-byte SHA-512(M) digest; the library does not
	 * compute it. Same pk-mismatch fault-injection trap as `sign`.
	 */
	signPrehashed(
		sk:     Uint8Array,
		pk:     Uint8Array,
		digest: Uint8Array,
		ctx:    Uint8Array,
	): Uint8Array {
		_assertNotOwned('curve25519');
		validateSecretKey(sk);
		validatePublicKey(pk);
		validateDigest(digest);
		validateContext(ctx);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk,     SEED_STAGE);
		mem.set(pk,     PK_STAGE);
		mem.set(digest, DIGEST_STAGE);
		if (ctx.length > 0) mem.set(ctx, CTX_STAGE);
		try {
			try {
				mx.ed25519SignPrehashed(
					SEED_STAGE, PK_STAGE, DIGEST_STAGE,
					CTX_STAGE, ctx.length, SIG_STAGE,
				);
			} catch (err) {
				rethrowTrap(
					err,
					'sig-malformed-input',
					'leviathan-crypto: ed25519ph sign aborted, pk does not match the pk derived from sk '
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
	 * Suite-only: pure Ed25519 sign that derives pk internally and skips
	 * the fault-injection cross-check. Saves one basepoint scalar mult per
	 * call versus `sign(sk, pk, msg)`. Intended for `Ed25519PureSuite` and
	 * `Ed25519PrehashSuite.sign` (message-taking path) where the caller
	 * holds only `sk`. The cross-check is degenerate at those call sites
	 * because the caller-supplied pk and the WASM-derived pk both come
	 * from the same call on the same module; direct-class callers who
	 * hold a stored, known-good pk should keep using `sign(sk, pk, msg)`.
	 *
	 * Underscore-prefixed and intentionally undocumented in the public
	 * API: not part of `docs/ed25519.md`'s API reference.
	 */
	_signInternalPk(sk: Uint8Array, M: Uint8Array): Uint8Array {
		_assertNotOwned('curve25519');
		validateSecretKey(sk);
		validateMessage(M);
		const mx  = this.mx;
		const cap = maxMsgLen(mx.memory);
		if (M.length > cap)
			throw new RangeError(
				`leviathan-crypto: ed25519 message length ${M.length} exceeds the per-call `
				+ `WASM input scratch (${cap} bytes); use Ed25519PreHashSuite or SignStream for larger payloads`,
			);
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk, SEED_STAGE);
		mem.set(M,  MSG_STAGE);
		try {
			mx.ed25519SignInternalPk(SEED_STAGE, MSG_STAGE, M.length, SIG_STAGE);
			return mem.slice(SIG_STAGE, SIG_STAGE + 64);
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/**
	 * Suite-only: Ed25519ph sign that derives pk internally and skips the
	 * fault-injection cross-check. Companion to `_signInternalPk`; same
	 * rationale. Intended for `Ed25519PrehashSuite.signPrehashed`.
	 */
	_signPrehashedInternalPk(
		sk:     Uint8Array,
		digest: Uint8Array,
		ctx:    Uint8Array,
	): Uint8Array {
		_assertNotOwned('curve25519');
		validateSecretKey(sk);
		validateDigest(digest);
		validateContext(ctx);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(sk,     SEED_STAGE);
		mem.set(digest, DIGEST_STAGE);
		if (ctx.length > 0) mem.set(ctx, CTX_STAGE);
		try {
			mx.ed25519SignPrehashedInternalPk(
				SEED_STAGE, DIGEST_STAGE, CTX_STAGE, ctx.length, SIG_STAGE,
			);
			return mem.slice(SIG_STAGE, SIG_STAGE + 64);
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/**
	 * Strict pure Ed25519 verify, RFC 8032 §5.1.7 / FIPS 186-5 §7.6.4.
	 *
	 * Returns `true` on success, `false` on every signature failure mode:
	 * off-curve pk, non-canonical R, non-canonical S (>= L), small-order
	 * pk, or signature equation inequality. Throws only on caller-side
	 * contract violations (wrong-length pk / M / sig).
	 */
	verify(pk: Uint8Array, M: Uint8Array, sig: Uint8Array): boolean {
		_assertNotOwned('curve25519');
		validatePublicKey(pk);
		validateMessage(M);
		validateSignature(sig);
		const mx  = this.mx;
		const cap = maxMsgLen(mx.memory);
		if (M.length > cap)
			throw new RangeError(
				`leviathan-crypto: ed25519 pure-mode message length ${M.length} exceeds the per-call `
				+ `WASM input scratch (${cap} bytes); use Ed25519PreHashSuite or SignStream for larger payloads`,
			);
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(pk,  PK_STAGE);
		mem.set(sig, SIG_STAGE);
		mem.set(M,   MSG_STAGE);
		try {
			return mx.ed25519Verify(PK_STAGE, MSG_STAGE, M.length, SIG_STAGE) === 1;
		} finally {
			ioWipe(mx);
			mx.wipeBuffers();
		}
	}

	/**
	 * Strict Ed25519ph verify, RFC 8032 §5.1.7 prehash. Same rejection
	 * conditions as {@link verify} plus the dom2(F=1, ctx) prefix on the
	 * per-spec SHA-512 inputs (handled inside the WASM).
	 */
	verifyPrehashed(
		pk:     Uint8Array,
		digest: Uint8Array,
		ctx:    Uint8Array,
		sig:    Uint8Array,
	): boolean {
		_assertNotOwned('curve25519');
		validatePublicKey(pk);
		validateDigest(digest);
		validateContext(ctx);
		validateSignature(sig);
		const mx  = this.mx;
		const mem = new Uint8Array(mx.memory.buffer);
		mem.set(pk,     PK_STAGE);
		mem.set(digest, DIGEST_STAGE);
		mem.set(sig,    SIG_STAGE);
		if (ctx.length > 0) mem.set(ctx, CTX_STAGE);
		try {
			return mx.ed25519VerifyPrehashed(
				PK_STAGE, DIGEST_STAGE, CTX_STAGE, ctx.length, SIG_STAGE,
			) === 1;
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
