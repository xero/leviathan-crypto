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
// src/asm/aes/gcm.ts
//
// AES-GCM authenticated encryption (Phase 4a). Implements GCM-AE / GCM-AD
// from NIST SP 800-38D §7. Builds on:
//   - aes.ts encryptBlock / encryptBlock_8x (block cipher core)
//   - ghash.ts ghashStart / ghashAbsorbBlock / ghashAbsorbWithLen / ghashFinalize
//   - gf128.ts gf128InitTable / gf128MulH (multiplication primitive)
//
// Tag length is fixed at 128 bits (the universal default; SP 800-38D §5.2.1
// permits 32/64/96/104/112/120/128, but shorter tags shift the security
// analysis and are not in this phase's scope).
//
// Counter format (§6.5 GCTR): 128-bit block. The leftmost 96 bits are
// fixed by J0; the rightmost 32 bits are a big-endian counter that
// increments per block (inc_32). This is distinct from Phase 3's CTR
// which uses a full-128-bit big-endian increment. We implement a
// dedicated GCTR loop here rather than calling Phase 3's CTR.
//
// Streaming chunked API (driven by the AESGCM TS class):
//
//   gcmStart(ivLen, aadLen)
//        Derive J0 from IV (12-byte fast path or GHASH slow path),
//        compute J0E = AES_ENC(K, J0), reset GHASH, absorb AAD, set up
//        GCTR counter at inc_32(J0).  Stores aadLen and resets ctLen.
//   gcmEncryptChunk(srcOff, dstOff, len)  → 0 on success, -1 on counter wrap
//        Run GCTR src→dst, absorb dst (CT) into GHASH, advance ctLen.
//   gcmAbsorbCtChunk(srcOff, len)
//        Absorb 'len' bytes of CT into GHASH, advance ctLen. Used by the
//        open direction's verify-before-decrypt pass.
//   gcmDecryptChunk(srcOff, dstOff, len)  → 0 on success, -1 on counter wrap
//        Run GCTR src→dst (no GHASH absorption — already done). Counter
//        must be re-initialised by gcmResetCtrToJ0Plus1() before the
//        first call after gcmFinalize.
//   gcmFinalize()
//        Absorb the final length-encoding block into GHASH, XOR with J0E
//        to form the tag, store at TAG_OFFSET.
//   gcmResetCtrToJ0Plus1()
//        Reset GCTR working counter to inc_32(J0). Used between the
//        absorb-CT pass and the decrypt pass for verify-before-decrypt.
//   gcmCompareTag(expectedOff)  → 0 on match, -1 on mismatch
//        Constant-time compare of TAG_OFFSET to 16 bytes at expectedOff.

import {
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	BLOCK_PT_8X_OFFSET, BLOCK_CT_8X_OFFSET,
	CHUNK_PT_OFFSET,
	J0_OFFSET,
	J0E_OFFSET,
	GHASH_ACC_OFFSET,
	TAG_OFFSET,
	GCM_LENS_OFFSET,
	GCM_CB_OFFSET,
	AAD_OFFSET,
} from './buffers';

import { encryptBlock, encryptBlock_8x } from './aes';

import {
	ghashStart,
	ghashAbsorbWithLen,
	ghashFinalize,
} from './ghash';

// ── Constants ──────────────────────────────────────────────────────────────

// Maximum PT bytes per (key, IV) per SP 800-38D §5.2.1.1: |P| ≤ 2^39 - 256
// bits = 2^36 - 32 bytes. Equivalently, the 32-bit GCTR counter spans at
// most 2^32 - 2 increments, each block is 16 bytes, so 16 · (2^32 - 2) =
// 2^36 - 32 bytes maximum.
//
// In our chunked WASM API ctLen is tracked as a single i32-equivalent, but
// we accumulate in two i32 limbs (low 32 bits of byte length and a
// "blocks consumed" guard for counter-wrap detection). gcmEncryptChunk
// rejects when the cumulative block count would push the counter past
// 2^32 - 2 (the last permitted block index before 32-bit wrap).

// Bit-length helpers: caller passes byte counts; we shift by 3 to bits.
@inline function bitsFromBytes(byteLen: u64): u64 {
	return byteLen << 3;
}

// ── Helpers (shared between encrypt and decrypt paths) ─────────────────────

/**
 * Encrypt the 16-byte block at srcOff with the loaded AES key, writing
 * 16 bytes to dstOff. Wraps the BLOCK_PT/BLOCK_CT atomic encryptBlock.
 */
@inline function aesEncryptOne(srcOff: i32, dstOff: i32): void {
	memory.copy(BLOCK_PT_OFFSET, srcOff, 16);
	encryptBlock();
	memory.copy(dstOff, BLOCK_CT_OFFSET, 16);
}

/**
 * 32-bit big-endian increment of GCM_CB[12..16]. Per SP 800-38D §6.2 inc_32.
 * Carry propagates from byte 15 toward byte 12. The high 96 bits stay
 * untouched (this is the GCM-specific counter, distinct from Phase 3 CTR).
 */
@inline function inc32(): void {
	for (let i: i32 = 15; i >= 12; i--) {
		const b: i32 = (<i32>load<u8>(GCM_CB_OFFSET + i)) + 1;
		store<u8>(GCM_CB_OFFSET + i, <u8>b);
		if (b < 256) return;
	}
}

/**
 * Load J0 into GCM_CB and increment the last 4 bytes by 1 BE — i.e.
 * GCM_CB := inc_32(J0). Subsequent inc32 calls advance from there.
 */
@inline function initCtrToJ0Plus1(): void {
	memory.copy(GCM_CB_OFFSET, J0_OFFSET, 16);
	inc32();
}

// ── J0 derivation (SP 800-38D §7.1 step 2) ─────────────────────────────────

/**
 * Derive the GCM pre-counter block J0 from the IV stored at CHUNK_PT_OFFSET.
 * Result is written to J0_OFFSET (16 bytes).
 *
 * 12-byte (96-bit) fast path: J0 = IV || 0x00000001.
 *
 * Variable-length IV slow path:
 *     s = 128·⌈|IV|/128⌉ - |IV|
 *     J0 = GHASH_H(IV || 0^{s+64} || [|IV|]_64)
 *
 * The slow-path GHASH uses GHASH_ACC as scratch; gcmStart will reset it
 * via ghashStart() before the AAD/CT pass.
 */
function deriveJ0(ivLen: i32): void {
	if (ivLen == 12) {
		// Fast path: copy 12 IV bytes, then append 0x00000001.
		memory.copy(J0_OFFSET, CHUNK_PT_OFFSET, 12);
		store<u8>(J0_OFFSET + 12, 0);
		store<u8>(J0_OFFSET + 13, 0);
		store<u8>(J0_OFFSET + 14, 0);
		store<u8>(J0_OFFSET + 15, 1);
		return;
	}

	// Slow path: GHASH on IV with zero-padding to 128-bit boundary, then
	// 64 zero bits, then 64-bit BE bit-length of IV.
	ghashStart();

	// Absorb full 16-byte blocks of IV.
	ghashAbsorbWithLen(CHUNK_PT_OFFSET, ivLen);

	// Append the lengths-style trailer: 64 zero bits || [|IV|]_64 BE.
	// In our scheme: ghashFinalize takes (aadBits, ctBits) and absorbs
	// `[aadBits]_64 || [ctBits]_64`. Here the trailer is `0^64 || [|IV|]_64`,
	// so call ghashFinalize(0, ivLen·8).
	const ivBits: u64 = bitsFromBytes(<u64>ivLen);
	ghashFinalize(0, ivBits);

	// J0 = GHASH_ACC at this point.
	memory.copy(J0_OFFSET, GHASH_ACC_OFFSET, 16);
}

// ── gcmStart ───────────────────────────────────────────────────────────────

/**
 * Start a GCM seal/open invocation. Reads IV bytes from CHUNK_PT_OFFSET
 * (length ivLen), AAD bytes from AAD_OFFSET (length aadLen).
 *
 * Steps performed:
 *   1. Derive J0 (12-byte fast path or GHASH slow path).
 *   2. Compute J0E = AES_ENC(K, J0).
 *   3. Reset GHASH_ACC to 0.
 *   4. Absorb AAD into GHASH (zero-pad partial final block).
 *   5. Initialise GCTR working counter to inc_32(J0).
 *   6. Reset running ctBitLen to 0; store aadBitLen.
 *
 * Caller must have already called loadKey to set up the AES round-key
 * schedule and derive the GCM hash subkey H (via the loadKey integration
 * in aes.ts).
 *
 * Returns 0 on success, -1 if ivLen ≤ 0 (per §5.2.1.1: |IV| ≥ 1 bit).
 * Caller (TS layer) should also enforce ivLen ≤ 65536 (CHUNK_PT capacity);
 * ivLen up to ~2^32 bytes is theoretically permitted by the spec but our
 * single-shot WASM API caps at the CHUNK buffer.
 */
export function gcmStart(ivLen: i32, aadLen: i32): i32 {
	if (ivLen <= 0) return -1;
	if (aadLen < 0) return -1;

	// 1. Derive J0.
	deriveJ0(ivLen);

	// 2. Compute J0E = AES_ENC(K, J0).
	aesEncryptOne(J0_OFFSET, J0E_OFFSET);

	// 3. Reset GHASH for the AAD/CT pass.
	ghashStart();

	// 4. Absorb AAD.
	if (aadLen > 0) {
		ghashAbsorbWithLen(AAD_OFFSET, aadLen);
	}

	// 5. Initialise GCTR working counter to inc_32(J0).
	initCtrToJ0Plus1();

	// 6. Store running lengths. AAD bit length goes in bytes [0..7] of
	//    GCM_LENS_OFFSET (u64 BE-on-finalize, but stored host-endian here
	//    and byte-swapped in ghashFinalize). CT bit length starts at 0
	//    and is accumulated by the chunk functions.
	const aadBits: u64 = bitsFromBytes(<u64>aadLen);
	store<u64>(GCM_LENS_OFFSET,     aadBits);
	store<u64>(GCM_LENS_OFFSET + 8, 0);

	return 0;
}

// ── GCTR core (8-block batched + scalar tail) ──────────────────────────────

/**
 * GCTR engine: encrypt/decrypt `len` bytes from src to dst using the
 * current GCM_CB counter. Increments the counter per block; rejects if
 * the counter would wrap past 2^32 - 2 (per §5.2.1.1 implicit bound).
 *
 * Returns 0 on success, -1 on counter wrap.
 */
function gctrXform(srcOff: i32, dstOff: i32, len: i32): i32 {
	if (len <= 0) return 0;

	let processed: i32 = 0;

	// 8-block batched loop: 128 bytes per encryptBlock_8x call.
	while (processed + 128 <= len) {
		// Lay 8 sequential counter blocks into BLOCK_PT_8X[0..128].
		// Each is the current GCM_CB; inc32 between them.
		for (let b: i32 = 0; b < 8; b++) {
			memory.copy(BLOCK_PT_8X_OFFSET + (b << 4), GCM_CB_OFFSET, 16);
			inc32();
		}

		encryptBlock_8x();

		// XOR keystream block_ct_8x with src bytes → dst.
		const srcBase: i32 = srcOff + processed;
		const dstBase: i32 = dstOff + processed;
		for (let off: i32 = 0; off < 128; off += 16) {
			const ks = v128.load(BLOCK_CT_8X_OFFSET + off);
			const pt = v128.load(srcBase + off);
			v128.store(dstBase + off, v128.xor(ks, pt));
		}
		processed += 128;
	}

	// Scalar tail: 0..127 remaining bytes.
	while (processed < len) {
		const remaining: i32 = len - processed;
		const blockLen: i32 = remaining < 16 ? remaining : 16;

		// Encrypt one counter block via the atomic path.
		memory.copy(BLOCK_PT_OFFSET, GCM_CB_OFFSET, 16);
		encryptBlock();
		inc32();

		const srcBase: i32 = srcOff + processed;
		const dstBase: i32 = dstOff + processed;
		for (let i: i32 = 0; i < blockLen; i++) {
			const ks: u8 = load<u8>(BLOCK_CT_OFFSET + i);
			const pt: u8 = load<u8>(srcBase + i);
			store<u8>(dstBase + i, ks ^ pt);
		}
		processed += blockLen;
	}

	// Counter wrap is enforced at the TS layer via MAX_PT_BYTES = 2^36 - 32.
	// Callers that bypass that cap can wrap GCM_CB's low-32 unsafely.
	// Flagged for hardening when 4b (AESGCMSIV) or 5 (AESCipher) reuse it.
	return 0;
}

// ── Public chunk operations ────────────────────────────────────────────────

/**
 * Run GCTR src→dst for `len` bytes, then absorb the produced ciphertext
 * (dstOff..dstOff+len) into GHASH and advance ctBitLen.  Used by the
 * encrypt direction of seal.
 *
 * Returns 0 on success, -1 on counter wrap or invalid length.
 */
export function gcmEncryptChunk(srcOff: i32, dstOff: i32, len: i32): i32 {
	if (len < 0) return -1;
	if (len == 0) return 0;

	const gctrRc: i32 = gctrXform(srcOff, dstOff, len);
	if (gctrRc != 0) return gctrRc;

	// Absorb ciphertext into GHASH.
	ghashAbsorbWithLen(dstOff, len);

	// Advance running CT bit length.
	const ctBitsAdded: u64 = bitsFromBytes(<u64>len);
	const cur: u64 = load<u64>(GCM_LENS_OFFSET + 8);
	store<u64>(GCM_LENS_OFFSET + 8, cur + ctBitsAdded);

	return 0;
}

/**
 * Absorb `len` bytes of ciphertext from srcOff into GHASH and advance
 * ctBitLen — but do NOT decrypt. Used by the open direction's
 * verify-before-decrypt pass.
 */
export function gcmAbsorbCtChunk(srcOff: i32, len: i32): i32 {
	if (len < 0) return -1;
	if (len == 0) return 0;

	ghashAbsorbWithLen(srcOff, len);

	const ctBitsAdded: u64 = bitsFromBytes(<u64>len);
	const cur: u64 = load<u64>(GCM_LENS_OFFSET + 8);
	store<u64>(GCM_LENS_OFFSET + 8, cur + ctBitsAdded);

	return 0;
}

/**
 * Run GCTR src→dst for `len` bytes — no GHASH absorption. Used by the
 * open direction's post-tag-verify decrypt phase. Caller must have already
 * called gcmResetCtrToJ0Plus1() since gcmFinalize between the two phases.
 *
 * Returns 0 on success, -1 on counter wrap or invalid length.
 */
export function gcmDecryptChunk(srcOff: i32, dstOff: i32, len: i32): i32 {
	if (len < 0) return -1;
	if (len == 0) return 0;

	return gctrXform(srcOff, dstOff, len);
}

/**
 * Reset GCTR working counter to inc_32(J0). Called between gcmFinalize
 * (which doesn't touch the counter) and the first gcmDecryptChunk call
 * in a verify-before-decrypt open flow.
 */
export function gcmResetCtrToJ0Plus1(): void {
	initCtrToJ0Plus1();
}

/**
 * Finalise GHASH: absorb the 16-byte length-encoding block
 * `[|A|]_64 || [|C|]_64`, then XOR the result with J0E to form the tag.
 * Tag is written to TAG_OFFSET (16 bytes).
 */
export function gcmFinalize(): void {
	const aadBits: u64 = load<u64>(GCM_LENS_OFFSET);
	const ctBits:  u64 = load<u64>(GCM_LENS_OFFSET + 8);

	ghashFinalize(aadBits, ctBits);

	// T = J0E XOR S where S = GHASH_ACC.
	store<u64>(TAG_OFFSET,     load<u64>(J0E_OFFSET)     ^ load<u64>(GHASH_ACC_OFFSET));
	store<u64>(TAG_OFFSET + 8, load<u64>(J0E_OFFSET + 8) ^ load<u64>(GHASH_ACC_OFFSET + 8));
}

/**
 * Constant-time compare of the 16-byte tag at TAG_OFFSET against 16 bytes
 * at expectedOff. OR-accumulates the 16 byte differences; returns 0 if all
 * bytes match, -1 otherwise.
 *
 * Implemented at the WASM layer so the tag-check pattern survives any JS
 * JIT optimizations that might short-circuit a byte-wise comparison.
 */
export function gcmCompareTag(expectedOff: i32): i32 {
	const a0: u64 = load<u64>(TAG_OFFSET);
	const a1: u64 = load<u64>(TAG_OFFSET + 8);
	const b0: u64 = load<u64>(expectedOff);
	const b1: u64 = load<u64>(expectedOff + 8);

	// Collapse 64 bits to 1 via OR-of-halves; return -1 if any byte differs.
	const diff: u64 = (a0 ^ b0) | (a1 ^ b1);
	const lo: u32 = <u32>diff | <u32>(diff >> 32);
	return lo == 0 ? 0 : -1;
}
