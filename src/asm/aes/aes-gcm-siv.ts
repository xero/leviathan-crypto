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
//                           ▀█████▀▀▀
//
// src/asm/aes/aes-gcm-siv.ts
//
// AES-GCM-SIV (RFC 8452) — single-shot atomic AEAD bounded by
// CHUNK_PT_BUFFER (64 KiB plaintext cap). Only AES-128 and AES-256
// keys are supported (RFC 8452 §6 explicitly excludes AES-192).
//
// Three WASM-level entry points (driven by `AESGCMSIV` in the TS layer):
//
//   sivDeriveKeys(nonceOff)
//        Encrypts 4 (AES-128) or 6 (AES-256) counter blocks under the
//        already-loaded KGK. Per RFC 8452 §4 derive_keys: counter is a
//        32-bit little-endian uint at bytes [0..4] of the input block,
//        bytes [4..16] = 12-byte nonce. The first 8 bytes of each
//        encrypted output are concatenated to form the per-message
//        authentication and encryption keys.
//
//   sivSeal(aadLen, ptLen)
//        Loads enc_key as the AES round key, runs POLYVAL over
//        padded(AAD) ‖ padded(PT) ‖ length-block, builds the tag
//        (XOR nonce, mask, AES-encrypt under enc_key), and SIV-CTR
//        encrypts CHUNK_PT in place. After return: tag at TAG_OFFSET,
//        ciphertext at CHUNK_PT_OFFSET.
//
//   sivOpen(aadLen, ctLen)
//        Loads enc_key as the AES round key, builds the initial CTR
//        block from the provided tag (caller writes it to SIV_IC_OFFSET
//        first), SIV-CTR decrypts CHUNK_CT → CHUNK_PT, runs POLYVAL,
//        builds the EXPECTED tag at TAG_OFFSET, and returns. Does NOT
//        compare. The TS layer reads the expected tag and routes the
//        constant-time compare through `constantTimeEqual` in
//        `src/ts/utils.ts` (per library policy — atomic AEADs do not
//        compare tags inside their own module).
//
//   sivWipeOnFail()
//        Zeroes everything that could carry plaintext or auth-key
//        material on the failed-open path: full CHUNK_PT (64 KiB),
//        POLYVAL accumulator, derived per-message keys, the GF128
//        table (built from auth_key), the reflected H, the SIV
//        counter, and the tag scratch.
//
// CTR convention (RFC 8452 §4): 16-byte counter block. Bytes [0..4] hold
// a 32-bit little-endian counter (incremented per block, wrapping mod
// 2^32 — silent per the RFC); bytes [4..16] are fixed across the call.
// This is materially different from GCM's CTR (96-bit fixed prefix +
// 32-bit big-endian counter at bytes [12..16]); the two share no code.

import {
	KEY_OFFSET,
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	CHUNK_PT_OFFSET, CHUNK_CT_OFFSET, CHUNK_SIZE,
	AAD_OFFSET,
	NR_OFFSET,
	NONCE_OFFSET,
	H_OFFSET,
	TAG_OFFSET,
	GHASH_ACC_OFFSET,
	GCM_LENS_OFFSET,
	GF128_TABLE_OFFSET,
	POLYVAL_AUTH_KEY_OFFSET,
	POLYVAL_ENC_KEY_OFFSET,
	SIV_IC_OFFSET,
} from './buffers'

import { encryptBlock, loadKey } from './aes'

import {
	polyvalStart,
	polyvalAbsorbBlock,
	polyvalAbsorbWithLen,
	polyvalFinalize,
} from './polyval'

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Load the per-message encryption key (at POLYVAL_ENC_KEY_OFFSET) as the
 * AES round-key schedule. RFC 8452 §6 fixes K_LEN ∈ {16, 32} and the
 * encryption key has the same length as the master KGK, so the round
 * count persisted in NR_OFFSET by the prior KGK loadKey transfers.
 *
 * Side-effect: `loadKey` re-derives H = AES_ENC(enc_key, 0^128) and
 * rebuilds the GF128 table. Both are immediately overwritten by the
 * subsequent `polyvalStart` call (which sets up the reflected POLYVAL
 * H), so the work is wasted but harmless.
 */
@inline function sivLoadEncKey(): void {
	const Nr: i32 = <i32>load<u8>(NR_OFFSET);
	const keyLen: i32 = Nr == 14 ? 32 : 16;
	memory.copy(KEY_OFFSET, POLYVAL_ENC_KEY_OFFSET, keyLen);
	loadKey(keyLen);
}

/** Absorb `len` bytes at `srcOff` into POLYVAL: full blocks, then a
 *  zero-padded tail (RFC 8452 §4 padded-input construction). */
@inline function polyvalAbsorbPadded(srcOff: i32, len: i32): void {
	const full: i32 = len >> 4;
	const tail: i32 = len & 0x0F;
	for (let i: i32 = 0; i < full; i++) {
		polyvalAbsorbBlock(srcOff + i * 16);
	}
	if (tail != 0) {
		polyvalAbsorbWithLen(srcOff + full * 16, tail);
	}
}

// ── sivDeriveKeys ──────────────────────────────────────────────────────────

/**
 * Derive the per-message authentication and encryption keys from the
 * loaded KGK and the 12-byte nonce at `nonceOff`. RFC 8452 §4:
 *
 *     for ctr in 0..N:
 *         block[0..4]  = ctr (uint32 little-endian)
 *         block[4..16] = nonce (12 bytes)
 *         out[ctr]     = AES_ENC(KGK, block)
 *     auth_key = out[0][0..8] ‖ out[1][0..8]               (16 bytes)
 *     enc_key  = out[2][0..8] ‖ out[3][0..8]               (AES-128: 16)
 *              ‖ out[4][0..8] ‖ out[5][0..8]               (AES-256: 32)
 *
 * Round count is read from NR_OFFSET (10 → AES-128 → 4 blocks; 14 →
 * AES-256 → 6 blocks).
 *
 * Outputs:
 *   POLYVAL_AUTH_KEY_OFFSET[0..16] — auth_key
 *   POLYVAL_ENC_KEY_OFFSET[0..16 or 32] — enc_key
 */
export function sivDeriveKeys(nonceOff: i32): void {
	const Nr: i32 = <i32>load<u8>(NR_OFFSET);
	const blocks: i32 = Nr == 14 ? 6 : 4;

	for (let ctr: i32 = 0; ctr < blocks; ctr++) {
		// Counter (LE uint32) | nonce.
		store<u32>(BLOCK_PT_OFFSET, <u32>ctr);
		// Bytes [4..16] = nonce[0..12].
		store<u64>(BLOCK_PT_OFFSET + 4, load<u64>(nonceOff));
		store<u32>(BLOCK_PT_OFFSET + 12, load<u32>(nonceOff + 8));

		encryptBlock();

		// Lay the first 8 bytes of each ciphertext into the appropriate
		// position of (auth_key | enc_key). Counters 0,1 → auth_key;
		// counters 2,3 → enc_key bytes 0..16; counters 4,5 → enc_key
		// bytes 16..32 (AES-256 only).
		const dst: i32 = ctr < 2
			? POLYVAL_AUTH_KEY_OFFSET + (ctr * 8)
			: POLYVAL_ENC_KEY_OFFSET  + ((ctr - 2) * 8);
		store<u64>(dst, load<u64>(BLOCK_CT_OFFSET));
	}

	// Wipe the per-derive scratch.
	memory.fill(BLOCK_PT_OFFSET, 0, 16);
	memory.fill(BLOCK_CT_OFFSET, 0, 16);
}

// ── sivCtrXform ────────────────────────────────────────────────────────────

/**
 * SIV CTR mode: XOR `len` bytes of AES_ENC(enc_key, counter_block) into
 * src→dst. Counter is the 32-bit little-endian uint at bytes [0..4] of
 * SIV_IC_OFFSET; bytes [4..16] are fixed for the duration of the call.
 *
 * Wrap is silent at 2^32 blocks (RFC 8452 §4 explicitly permits and
 * requires this). Unlike GCM's GCTR, there is no error return; the
 * 64 KiB CHUNK_PT cap on len keeps a single call below 2^12 blocks
 * regardless of where the counter starts.
 */
function sivCtrXform(srcOff: i32, dstOff: i32, len: i32): void {
	if (len <= 0) return;

	let counter: u32 = load<u32>(SIV_IC_OFFSET);
	const fixedLo: u64 = load<u64>(SIV_IC_OFFSET + 4);
	const fixedHi: u32 = load<u32>(SIV_IC_OFFSET + 12);

	let processed: i32 = 0;
	while (processed < len) {
		// Build counter block in BLOCK_PT.
		store<u32>(BLOCK_PT_OFFSET,      counter);
		store<u64>(BLOCK_PT_OFFSET + 4,  fixedLo);
		store<u32>(BLOCK_PT_OFFSET + 12, fixedHi);
		encryptBlock();

		const remaining: i32 = len - processed;
		const blockLen: i32 = remaining < 16 ? remaining : 16;
		const sBase: i32 = srcOff + processed;
		const dBase: i32 = dstOff + processed;
		for (let i: i32 = 0; i < blockLen; i++) {
			store<u8>(dBase + i, load<u8>(sBase + i) ^ load<u8>(BLOCK_CT_OFFSET + i));
		}
		processed += blockLen;
		// u32 wraps at 2^32 in AssemblyScript arithmetic.
		counter = counter + 1;
	}
	memory.fill(BLOCK_PT_OFFSET, 0, 16);
	memory.fill(BLOCK_CT_OFFSET, 0, 16);
}

// ── sivSeal ────────────────────────────────────────────────────────────────

/**
 * Single-shot AES-GCM-SIV seal. Preconditions:
 *   - KGK loaded as AES round key (caller's earlier `loadKey`).
 *   - 12-byte nonce at NONCE_OFFSET.
 *   - AAD (`aadLen` bytes) at AAD_OFFSET.
 *   - Plaintext (`ptLen` bytes) at CHUNK_PT_OFFSET.
 *   - `sivDeriveKeys(NONCE_OFFSET)` already called.
 *
 * Postconditions:
 *   - Tag (16 bytes) at TAG_OFFSET.
 *   - Ciphertext (`ptLen` bytes) at CHUNK_PT_OFFSET (in place).
 *
 * Algorithm: RFC 8452 §4 encrypt direction.
 *   S_s         = POLYVAL(auth_key, padded(AAD) ‖ padded(PT) ‖ lens)
 *   masked      = (S_s ⊕ (nonce ‖ 0^32)) with byte-15 high bit cleared
 *   tag         = AES_ENC(enc_key, masked)
 *   IC          = tag with byte-15 high bit set
 *   ciphertext  = AES-CTR(enc_key, IC, plaintext)
 */
export function sivSeal(aadLen: i32, ptLen: i32): void {
	// 1. Switch the AES key schedule from KGK to the per-message enc_key.
	sivLoadEncKey();

	// 2. POLYVAL pass.
	polyvalStart(POLYVAL_AUTH_KEY_OFFSET);
	polyvalAbsorbPadded(AAD_OFFSET, aadLen);
	polyvalAbsorbPadded(CHUNK_PT_OFFSET, ptLen);

	// Length block: [aadBits]_64_LE ‖ [ptBits]_64_LE. AssemblyScript's
	// store<u64> writes little-endian natively, matching RFC 8452 §4.
	store<u64>(GCM_LENS_OFFSET,     (<u64>aadLen) << 3);
	store<u64>(GCM_LENS_OFFSET + 8, (<u64>ptLen)  << 3);
	polyvalAbsorbBlock(GCM_LENS_OFFSET);

	polyvalFinalize(TAG_OFFSET);

	// 3. XOR nonce into TAG[0..12]; bytes [12..16] are unchanged.
	for (let j: i32 = 0; j < 12; j++) {
		store<u8>(TAG_OFFSET + j,
			load<u8>(TAG_OFFSET + j) ^ load<u8>(NONCE_OFFSET + j));
	}

	// 4. Mask: clear bit 7 of byte 15.
	store<u8>(TAG_OFFSET + 15, load<u8>(TAG_OFFSET + 15) & 0x7F);

	// 5. AES-encrypt TAG in place under enc_key (the actual tag).
	memory.copy(BLOCK_PT_OFFSET, TAG_OFFSET, 16);
	encryptBlock();
	memory.copy(TAG_OFFSET, BLOCK_CT_OFFSET, 16);

	// 6. Initial counter = tag with bit 7 of byte 15 set.
	memory.copy(SIV_IC_OFFSET, TAG_OFFSET, 16);
	store<u8>(SIV_IC_OFFSET + 15, load<u8>(SIV_IC_OFFSET + 15) | 0x80);

	// 7. CTR-encrypt CHUNK_PT in place.
	sivCtrXform(CHUNK_PT_OFFSET, CHUNK_PT_OFFSET, ptLen);

	// Wipe the length-block scratch.
	memory.fill(GCM_LENS_OFFSET, 0, 16);
}

// ── sivOpen ────────────────────────────────────────────────────────────────

/**
 * Single-shot AES-GCM-SIV open. Preconditions (per the TS layer):
 *   - KGK loaded as AES round key.
 *   - 12-byte nonce at NONCE_OFFSET.
 *   - AAD (`aadLen` bytes) at AAD_OFFSET.
 *   - Ciphertext (`ctLen` bytes) at CHUNK_CT_OFFSET.
 *   - Provided tag (16 bytes) staged at SIV_IC_OFFSET (bit-7 of byte 15
 *     not yet set; this function sets it).
 *   - `sivDeriveKeys(NONCE_OFFSET)` already called.
 *
 * Postconditions:
 *   - Decrypted plaintext at CHUNK_PT_OFFSET.
 *   - EXPECTED tag (16 bytes, computed from the decrypted plaintext) at
 *     TAG_OFFSET. The TS layer reads this and the provided tag, calls
 *     `constantTimeEqual`, and either accepts and returns CHUNK_PT or
 *     calls `sivWipeOnFail` and throws.
 *
 * IMPORTANT: this function does NOT release plaintext on its own. The
 * write-then-verify pattern is inherent to SIV — the tag depends on the
 * plaintext, so the plaintext must be computed before the tag can be
 * checked. The TS layer enforces "MUST NOT release unauthenticated
 * plaintext" (RFC 8452 §5) by gating the read of CHUNK_PT_OFFSET on a
 * successful constant-time tag compare.
 */
export function sivOpen(aadLen: i32, ctLen: i32): void {
	// 1. Switch from KGK to enc_key for AES-CTR / AES-tag-encrypt.
	sivLoadEncKey();

	// 2. The provided tag is at SIV_IC_OFFSET; OR in bit-7 of byte 15
	//    to form the initial counter (RFC 8452 §4 receive direction).
	store<u8>(SIV_IC_OFFSET + 15, load<u8>(SIV_IC_OFFSET + 15) | 0x80);

	// 3. CTR-decrypt CHUNK_CT → CHUNK_PT.
	sivCtrXform(CHUNK_CT_OFFSET, CHUNK_PT_OFFSET, ctLen);

	// 4. POLYVAL over padded(AAD) ‖ padded(decrypted PT) ‖ lens.
	polyvalStart(POLYVAL_AUTH_KEY_OFFSET);
	polyvalAbsorbPadded(AAD_OFFSET, aadLen);
	polyvalAbsorbPadded(CHUNK_PT_OFFSET, ctLen);

	store<u64>(GCM_LENS_OFFSET,     (<u64>aadLen) << 3);
	store<u64>(GCM_LENS_OFFSET + 8, (<u64>ctLen)  << 3);
	polyvalAbsorbBlock(GCM_LENS_OFFSET);

	polyvalFinalize(TAG_OFFSET);

	// 5. XOR nonce into TAG[0..12], mask bit-7 of byte 15.
	for (let j: i32 = 0; j < 12; j++) {
		store<u8>(TAG_OFFSET + j,
			load<u8>(TAG_OFFSET + j) ^ load<u8>(NONCE_OFFSET + j));
	}
	store<u8>(TAG_OFFSET + 15, load<u8>(TAG_OFFSET + 15) & 0x7F);

	// 6. AES-encrypt TAG in place under enc_key — TAG_OFFSET now holds
	//    the EXPECTED tag.
	memory.copy(BLOCK_PT_OFFSET, TAG_OFFSET, 16);
	encryptBlock();
	memory.copy(TAG_OFFSET, BLOCK_CT_OFFSET, 16);

	memory.fill(GCM_LENS_OFFSET, 0, 16);
}

// ── sivWipeOnFail ──────────────────────────────────────────────────────────

/**
 * Zero everything that could carry decrypted plaintext, key material
 * derived from the auth key, or scratch tied to the failed open. Called
 * by the TS layer when `constantTimeEqual(expected, provided)` returns
 * false.
 *
 * Does NOT wipe KEY_BUFFER or the round-key schedule; those are tied to
 * the *master* key the caller may legitimately reuse for the next call.
 * The caller's `dispose()` invokes the full `wipeBuffers` instead.
 */
export function sivWipeOnFail(): void {
	memory.fill(CHUNK_PT_OFFSET,         0, CHUNK_SIZE);
	memory.fill(GHASH_ACC_OFFSET,        0, 16);
	memory.fill(POLYVAL_AUTH_KEY_OFFSET, 0, 16);
	memory.fill(POLYVAL_ENC_KEY_OFFSET,  0, 32);
	memory.fill(SIV_IC_OFFSET,           0, 16);
	memory.fill(GF128_TABLE_OFFSET,      0, 256);
	memory.fill(H_OFFSET,                0, 16);
	memory.fill(TAG_OFFSET,              0, 16);
	memory.fill(BLOCK_PT_OFFSET,         0, 16);
	memory.fill(BLOCK_CT_OFFSET,         0, 16);
	memory.fill(GCM_LENS_OFFSET,         0, 16);
}
