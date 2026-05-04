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
// src/asm/aes/aes.ts
//
// AES-128 encrypt — bitsliced over v128 (8 blocks parallel).
// Spec: NIST FIPS 197-upd1 (2023), §5.1, §5.2, Appendix B.
// Bitsliced layout, ShiftRows-as-shuffle, MixColumns formulas:
//   Käsper-Schwabe 2009 (CHES) §4.1, §4.3, §4.4 + Appendix A.
// S-box: imported from sbox.ts (Canright tower-field).
//
// Phase 2a: AES-128 encrypt only. Decrypt + AES-192/256 are phase 2b.

import {
	KEY_OFFSET,
	BLOCK_PT_OFFSET, BLOCK_CT_OFFSET,
	BLOCK_PT_8X_OFFSET, BLOCK_CT_8X_OFFSET,
	ROUND_KEYS_OFFSET,
	BITSLICED_STATE_OFFSET,
} from './buffers'
import { sboxBitsliced } from './sbox'

// ── Bitsliced state slot helpers ────────────────────────────────────────────

@inline function bget(k: i32): v128 {
	return v128.load(BITSLICED_STATE_OFFSET + (k << 4));
}
@inline function bset(k: i32, v: v128): void {
	v128.store(BITSLICED_STATE_OFFSET + (k << 4), v);
}

// ── Bit transposition (Käsper-Schwabe §4.1) ─────────────────────────────────
//
// Input: 128 bytes at BLOCK_PT_8X_OFFSET, organised as 8 contiguous 16-byte
// AES blocks in FIPS 197 input-byte order.
//
// Output: 8 v128 registers at BITSLICED_STATE_OFFSET. Register state[k]
// holds bit-k from every byte across all 8 blocks. Within state[k], byte
// position j ∈ {0..15} corresponds to AES state row r=j/4, column c=j%4
// (row-major). Within byte j of state[k], the 8 bits are bit-k of that
// state-position from blocks 0..7.
//
// FIPS 197 §3.4: state[r,c] = in[r + 4c]. So bitsliced byte j corresponds
// to plaintext byte at offset (j%4)*4 + j/4 within each block (transpose
// of the column-major fill). This 4×4 transpose is applied per block before
// bit-slicing.

/**
 * Transpose 8-blocks input from BLOCK_PT_8X to bitsliced state.
 *
 * Reference: Käsper-Schwabe 2009 §4.1 (bitsliced layout) + FIPS 197 §3.4
 * (state-array byte ordering).
 */
function transposeIn(): void {
	// For each bit position k ∈ {0..7}, for each output bitsliced-byte j ∈
	// {0..15}, gather bit-k from byte (j%4)*4 + j/4 of each of the 8 blocks
	// into the 8 lanes of the output byte.
	for (let k: i32 = 0; k < 8; k++) {
		const dstBase = BITSLICED_STATE_OFFSET + (k << 4);
		for (let j: i32 = 0; j < 16; j++) {
			const r = j >> 2;          // state-array row
			const c = j & 3;           // state-array column
			const ptByte = c * 4 + r;  // FIPS 197 §3.4 input-byte offset
			let lane: i32 = 0;
			for (let b: i32 = 0; b < 8; b++) {
				const v = <i32>load<u8>(BLOCK_PT_8X_OFFSET + b * 16 + ptByte);
				lane |= ((v >> k) & 1) << b;
			}
			store<u8>(dstBase + j, <u8>lane);
		}
	}
}

/**
 * Inverse transpose: bitsliced state → 8-blocks output at BLOCK_CT_8X.
 *
 * Reference: Käsper-Schwabe 2009 §4.1 (inverse of transposeIn).
 */
function transposeOut(): void {
	for (let b: i32 = 0; b < 8; b++) {
		for (let p: i32 = 0; p < 16; p++) {
			// AES output byte p of block b = state[r=p%4, c=p/4]
			// = bitsliced-byte j = 4r + c at lane b across all 8 registers.
			const r = p & 3;
			const c = p >> 2;
			const j = (r << 2) | c;
			let v: i32 = 0;
			for (let k: i32 = 0; k < 8; k++) {
				const regByte = <i32>load<u8>(BITSLICED_STATE_OFFSET + (k << 4) + j);
				v |= ((regByte >> b) & 1) << k;
			}
			store<u8>(BLOCK_CT_8X_OFFSET + b * 16 + p, <u8>v);
		}
	}
}

// ── ShiftRows (Käsper-Schwabe §4.3 + FIPS 197 §5.1.2) ──────────────────────
//
// In K-S' row-major bitsliced layout, ShiftRows permutes the 16 bytes in
// each bitsliced register according to a uniform pattern. Per design notes
// §3, the shuffle indices are [0,1,2,3, 5,6,7,4, 10,11,8,9, 15,12,13,14].

/**
 * Apply ShiftRows uniformly to all 8 bitsliced state registers.
 * Reference: Käsper-Schwabe 2009 §4.3.
 */
function shiftRows(): void {
	for (let k: i32 = 0; k < 8; k++) {
		const r = bget(k);
		bset(k, v128.shuffle<i8>(r, r,
			0, 1, 2, 3,
			5, 6, 7, 4,
			10, 11, 8, 9,
			15, 12, 13, 14,
		));
	}
}

// ── MixColumns (Käsper-Schwabe §4.4 + Appendix A) ──────────────────────────
//
// In bitsliced row-major layout, "shift one row down" = byte rotation by 4
// (= bit rotation by 32) within each 128-bit register. K-S writes this as
// `rl32`. Two-row-down = `rl64` = byte rotation by 8.
//
// Per K-S Appendix A:
//   b[0] = (a[7] ⊕ rl32 a[7]) ⊕ rl32 a[0] ⊕ rl64(a[0] ⊕ rl32 a[0])
//   b[1] = (a[0] ⊕ rl32 a[0]) ⊕ (a[7] ⊕ rl32 a[7]) ⊕ rl32 a[1] ⊕ rl64(a[1] ⊕ rl32 a[1])
//   ... (full table in design notes §4)

/**
 * "Look one row down" byte permutation: dst[p] = src[(p+4) mod 16].
 * Used by K-S MixColumns to bring a_{i+1,j} into position (i,j).
 *
 * Note on K-S' "rl32" notation: the K-S paper writes this as "rotate left by
 * 32 bits", but the operational meaning (per K-S §4.4) is to produce a
 * register where byte at row-major index p reads from row p/4+1's value at
 * column p%4 — i.e., shift the indices DOWN by 4. That's what this shuffle
 * implements. Verified against FIPS 197 §5.1.3 by single-bit input
 * cross-check during development.
 */
@inline function rl32(x: v128): v128 {
	return v128.shuffle<i8>(x, x,
		4, 5, 6, 7,
		8, 9, 10, 11,
		12, 13, 14, 15,
		0, 1, 2, 3,
	);
}

/** "Look two rows down": dst[p] = src[(p+8) mod 16]. */
@inline function rl64(x: v128): v128 {
	return v128.shuffle<i8>(x, x,
		8, 9, 10, 11,
		12, 13, 14, 15,
		0, 1, 2, 3,
		4, 5, 6, 7,
	);
}

/**
 * MixColumns over bitsliced state.
 * Reference: Käsper-Schwabe 2009 §4.4 + Appendix A (full equations).
 */
function mixColumns(): void {
	const a0 = bget(0);
	const a1 = bget(1);
	const a2 = bget(2);
	const a3 = bget(3);
	const a4 = bget(4);
	const a5 = bget(5);
	const a6 = bget(6);
	const a7 = bget(7);

	const r0 = rl32(a0);
	const r1 = rl32(a1);
	const r2 = rl32(a2);
	const r3 = rl32(a3);
	const r4 = rl32(a4);
	const r5 = rl32(a5);
	const r6 = rl32(a6);
	const r7 = rl32(a7);

	// Shared subexpressions: a[k] ⊕ rl32 a[k].
	const s0 = v128.xor(a0, r0);
	const s1 = v128.xor(a1, r1);
	const s2 = v128.xor(a2, r2);
	const s3 = v128.xor(a3, r3);
	const s4 = v128.xor(a4, r4);
	const s5 = v128.xor(a5, r5);
	const s6 = v128.xor(a6, r6);
	const s7 = v128.xor(a7, r7);

	// rl64 of the shared subexpressions.
	const rs0 = rl64(s0);
	const rs1 = rl64(s1);
	const rs2 = rl64(s2);
	const rs3 = rl64(s3);
	const rs4 = rl64(s4);
	const rs5 = rl64(s5);
	const rs6 = rl64(s6);
	const rs7 = rl64(s7);

	// b[0] = s7 ⊕ r0 ⊕ rs0
	bset(0, v128.xor(v128.xor(s7, r0), rs0));
	// b[1] = s0 ⊕ s7 ⊕ r1 ⊕ rs1
	bset(1, v128.xor(v128.xor(s0, s7), v128.xor(r1, rs1)));
	// b[2] = s1 ⊕ r2 ⊕ rs2
	bset(2, v128.xor(v128.xor(s1, r2), rs2));
	// b[3] = s2 ⊕ s7 ⊕ r3 ⊕ rs3
	bset(3, v128.xor(v128.xor(s2, s7), v128.xor(r3, rs3)));
	// b[4] = s3 ⊕ s7 ⊕ r4 ⊕ rs4
	bset(4, v128.xor(v128.xor(s3, s7), v128.xor(r4, rs4)));
	// b[5] = s4 ⊕ r5 ⊕ rs5
	bset(5, v128.xor(v128.xor(s4, r5), rs5));
	// b[6] = s5 ⊕ r6 ⊕ rs6
	bset(6, v128.xor(v128.xor(s5, r6), rs6));
	// b[7] = s6 ⊕ r7 ⊕ rs7
	bset(7, v128.xor(v128.xor(s6, r7), rs7));
}

// ── AddRoundKey (Käsper-Schwabe §4.5 + FIPS 197 §5.1.4) ────────────────────
//
// Each round key occupies 8 v128 (128 bytes) at ROUND_KEYS_OFFSET +
// roundIdx * 128. AddRoundKey is 8 plain v128 XORs.

@inline function rkget(round: i32, k: i32): v128 {
	return v128.load(ROUND_KEYS_OFFSET + (round << 7) + (k << 4));
}

/** XOR round-key `roundIdx` into the bitsliced state. */
function addRoundKey(roundIdx: i32): void {
	for (let k: i32 = 0; k < 8; k++) {
		bset(k, v128.xor(bget(k), rkget(roundIdx, k)));
	}
}

// ── AES-128 key schedule (FIPS 197 §5.2 Algorithm 2) ───────────────────────
//
// Computes 11 round keys (176 bytes byte-level) from the 16-byte master key
// at KEY_OFFSET. Round keys are then bitsliced (each one duplicates across
// 8 "blocks" and is transposed) to ROUND_KEYS_OFFSET.

/** AES Rcon[j] = (x^(j-1), 0, 0, 0) in GF(2⁸). FIPS 197 Table 5. */
@inline function rcon(j: i32): u8 {
	switch (j) {
		case 1:  return 0x01;
		case 2:  return 0x02;
		case 3:  return 0x04;
		case 4:  return 0x08;
		case 5:  return 0x10;
		case 6:  return 0x20;
		case 7:  return 0x40;
		case 8:  return 0x80;
		case 9:  return 0x1b;
		case 10: return 0x36;
		default: return 0;
	}
}

/**
 * Apply forward S-box to a single byte using the bitsliced S-box.
 *
 * Used by SubWord during key expansion. Loads the byte into block 0 byte 0
 * of BLOCK_PT_8X (with all other 127 bytes zeroed), runs transposeIn →
 * sboxBitsliced → transposeOut, returns block 0 byte 0 of the result.
 *
 * Inefficient (one S-box application per byte costs the full 8-block
 * pipeline) but only invoked 4 × 10 = 40 times during AES-128 key
 * expansion — negligible in the overall cost.
 */
function sboxByte(b: u8): u8 {
	// Zero the 8x staging buffer.
	memory.fill(BLOCK_PT_8X_OFFSET, 0, 128);
	// Place the input at block 0 byte 0.
	store<u8>(BLOCK_PT_8X_OFFSET, b);
	transposeIn();
	sboxBitsliced();
	transposeOut();
	// Read the output byte from block 0 byte 0.
	return load<u8>(BLOCK_CT_8X_OFFSET);
}

/**
 * AES-128 key expansion.
 *
 * Reference: FIPS 197 §5.2 Algorithm 2. Reads 16 bytes at KEY_OFFSET;
 * writes 11 byte-level round keys (176 bytes) into a temporary scratch area
 * at the head of CANRIGHT_SCRATCH; then bit-slices each round key into the
 * format required by AddRoundKey, writing 11 × 128 bytes to ROUND_KEYS_OFFSET.
 */
function keyExpansion128(): void {
	// Use a scratch region inside ROUND_KEYS_BUFFER (which is 1920 bytes,
	// well above the 176 we need) to compute byte-level round keys, then
	// re-slice in place. We choose offset ROUND_KEYS_OFFSET + 1408 (the
	// region immediately above the 11 bitsliced round keys) for the
	// byte-level scratch — 176 bytes there leaves us within 1920.
	const SCRATCH = ROUND_KEYS_OFFSET + 1408;

	// Step 1: copy key bytes as the first 16 bytes (4 words).
	for (let i: i32 = 0; i < 16; i++) {
		store<u8>(SCRATCH + i, load<u8>(KEY_OFFSET + i));
	}

	// Step 2: derive remaining 40 words = 160 bytes.
	for (let i: i32 = 4; i < 44; i++) {
		// temp = w[i-1] (last 4 bytes).
		let t0 = load<u8>(SCRATCH + (i - 1) * 4);
		let t1 = load<u8>(SCRATCH + (i - 1) * 4 + 1);
		let t2 = load<u8>(SCRATCH + (i - 1) * 4 + 2);
		let t3 = load<u8>(SCRATCH + (i - 1) * 4 + 3);
		if (i % 4 == 0) {
			// RotWord: (t0,t1,t2,t3) → (t1,t2,t3,t0)
			const r0 = t1, r1 = t2, r2 = t3, r3 = t0;
			// SubWord: apply S-box to each byte.
			t0 = sboxByte(r0) ^ rcon(i / 4);
			t1 = sboxByte(r1);
			t2 = sboxByte(r2);
			t3 = sboxByte(r3);
		}
		store<u8>(SCRATCH + i * 4,     load<u8>(SCRATCH + (i - 4) * 4)     ^ t0);
		store<u8>(SCRATCH + i * 4 + 1, load<u8>(SCRATCH + (i - 4) * 4 + 1) ^ t1);
		store<u8>(SCRATCH + i * 4 + 2, load<u8>(SCRATCH + (i - 4) * 4 + 2) ^ t2);
		store<u8>(SCRATCH + i * 4 + 3, load<u8>(SCRATCH + (i - 4) * 4 + 3) ^ t3);
	}

	// Step 3: bitslice each of the 11 round keys.
	// For each round key, fill BLOCK_PT_8X with 8 copies of the 16-byte key,
	// transpose, then copy bitsliced state to ROUND_KEYS_OFFSET + round*128.
	for (let round: i32 = 0; round < 11; round++) {
		// Copy round key into all 8 block slots.
		for (let b: i32 = 0; b < 8; b++) {
			for (let p: i32 = 0; p < 16; p++) {
				store<u8>(BLOCK_PT_8X_OFFSET + b * 16 + p,
					load<u8>(SCRATCH + round * 16 + p));
			}
		}
		transposeIn();
		// Copy 128 bytes from BITSLICED_STATE_OFFSET to ROUND_KEYS_OFFSET + round*128.
		memory.copy(ROUND_KEYS_OFFSET + (round << 7), BITSLICED_STATE_OFFSET, 128);
	}

	// Wipe the byte-level scratch and BLOCK_PT_8X (since they held key bytes).
	memory.fill(SCRATCH, 0, 176);
	memory.fill(BLOCK_PT_8X_OFFSET, 0, 128);
	memory.fill(BITSLICED_STATE_OFFSET, 0, 128);
}

// ── Public AES-128 encrypt API ──────────────────────────────────────────────

/**
 * Validate key length and run the AES-128 key schedule.
 *
 * Phase 2a: only 16-byte keys are accepted; AES-192/256 land in phase 2b.
 *
 * @param keyLen  expected to be 16
 * @returns       0 on success, nonzero on any other key length.
 */
export function loadKey(keyLen: i32): i32 {
	if (keyLen != 16) return 1;
	keyExpansion128();
	return 0;
}

/**
 * AES-128 encrypt 8 parallel blocks at BLOCK_PT_8X_OFFSET, writing 8
 * ciphertext blocks to BLOCK_CT_8X_OFFSET.
 *
 * Reference: FIPS 197 §5.1 Algorithm 1, Nr=10. Bitsliced layout:
 * Käsper-Schwabe 2009 §4.
 */
export function encryptBlock_8x(): void {
	transposeIn();

	// Round 0: AddRoundKey only.
	addRoundKey(0);

	// Rounds 1..9: SubBytes, ShiftRows, MixColumns, AddRoundKey.
	for (let round: i32 = 1; round < 10; round++) {
		sboxBitsliced();
		shiftRows();
		mixColumns();
		addRoundKey(round);
	}

	// Round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns; FIPS 197 §5.1).
	sboxBitsliced();
	shiftRows();
	addRoundKey(10);

	transposeOut();
}

/**
 * AES-128 encrypt a single block at BLOCK_PT_OFFSET, writing to BLOCK_CT_OFFSET.
 *
 * The bitsliced kernel processes 8 blocks in parallel. For single-block
 * encryption we copy the input to block 0 of BLOCK_PT_8X, zero the other
 * 7 blocks, run encryptBlock_8x, and copy block 0 of BLOCK_CT_8X to
 * BLOCK_CT_OFFSET. The 7 dummy blocks are wasted work but later phases
 * (CTR, GCM) feed 8-block batches naturally.
 */
export function encryptBlock(): void {
	memory.copy(BLOCK_PT_8X_OFFSET, BLOCK_PT_OFFSET, 16);
	memory.fill(BLOCK_PT_8X_OFFSET + 16, 0, 112);
	encryptBlock_8x();
	memory.copy(BLOCK_CT_OFFSET, BLOCK_CT_8X_OFFSET, 16);
}

// ── DEBUG-ONLY exports for gate tests 1, 2, 3 ───────────────────────────────

/**
 * DEBUG-ONLY: used by aes_transpose.test.ts (Gate 1).
 * transposeIn followed by transposeOut on the BLOCK_PT_8X buffer; output
 * appears at BLOCK_CT_8X. Should be the identity for any 128-byte input.
 */
export function transposeRoundTrip(): void {
	transposeIn();
	transposeOut();
}

/**
 * DEBUG-ONLY: used by aes_sbox.test.ts (Gate 2).
 * transposeIn → sboxBitsliced → transposeOut. With single-byte input at
 * block 0 byte 0 of BLOCK_PT_8X (rest zeroed), block 0 byte 0 of BLOCK_CT_8X
 * should equal the FIPS 197 S-box of the input byte.
 */
export function sboxRoundTrip(): void {
	transposeIn();
	sboxBitsliced();
	transposeOut();
}

/**
 * DEBUG-ONLY: used by aes_round.test.ts (Gate 3).
 * Apply one full AES round at index `roundIdx` to BLOCK_PT_8X, writing
 * BLOCK_CT_8X. The round is the inner-round form (SubBytes + ShiftRows +
 * MixColumns + AddRoundKey) — appropriate for round 1 verification against
 * FIPS 197 §B Round 1.
 */
export function singleRound(roundIdx: i32): void {
	transposeIn();
	sboxBitsliced();
	shiftRows();
	mixColumns();
	addRoundKey(roundIdx);
	transposeOut();
}
