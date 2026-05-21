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
// src/asm/slhdsa/address.ts
//
// SLH-DSA ADRS (address) structure, FIPS 205 §4.2 Figure 2.
//
// 32 bytes total, seven type-specific layouts. ADRS is a sequence of 4-byte
// big-endian uint32 words ("each word being 4 bytes long and values encoded
// as unsigned integers in big-endian byte order"). The layer address, type
// field, keypair, chain, hash, treeHeight, and treeIndex slots are each
// one such 4-byte word. The tree address spans three words (12 bytes
// big-endian) and is split across three u32 limbs here because
// AssemblyScript's u64 is not first-class in all hosts.
//
// FIPS 205 §4.2 byte map (Figure 2 / Tables 2-7):
//
//   offset  size  field            who uses it
//   0..3    4     layer address    all (BE uint32)
//   4..15   12    tree address     all (BE int across three u32 limbs)
//   16..19  4     type             all (one of ADRS_*)
//   20..23  4     keypair address  WOTS_HASH/WOTS_PK/WOTS_PRF/FORS_*
//   24..27  4     chain / tree height  WOTS_HASH chain / FORS_TREE / TREE
//   28..31  4     hash / tree index    WOTS_HASH hash  / FORS_TREE / TREE
//
// All integer fields are written most-significant-byte first per FIPS 205
// §4.2 (cross-checked against slhdsa-c slh_adrs.h after independent
// derivation).
//
// Note: FIPS 205 §4.2 Figure 2 encodes `layer` as a 4-byte BE word, not a
// single byte. Layer values ≤ 255 land in byte 3 (low byte of BE int) with
// bytes 0..2 as zero high bytes.

// ── ADRS type constants (FIPS 205 §4.2 Algorithm 14 column "type") ─────────

export const ADRS_WOTS_HASH:  i32 = 0;
export const ADRS_WOTS_PK:    i32 = 1;
export const ADRS_TREE:       i32 = 2;
export const ADRS_FORS_TREE:  i32 = 3;
export const ADRS_FORS_ROOTS: i32 = 4;
export const ADRS_WOTS_PRF:   i32 = 5;
export const ADRS_FORS_PRF:   i32 = 6;

// ── Field offsets within the 32-byte ADRS (FIPS 205 §4.2 Table 1) ──────────

export const ADRS_LAYER_OFF:       i32 = 0;   // 4 bytes big-endian (FIPS 205 §4.2 Figure 2)
export const ADRS_TREE_OFF:        i32 = 4;   // 12 bytes big-endian
export const ADRS_TYPE_OFF:        i32 = 16;  // 4 bytes big-endian
export const ADRS_KEYPAIR_OFF:     i32 = 20;  // 4 bytes (WOTS+ / FORS)
export const ADRS_CHAIN_OFF:       i32 = 24;  // 4 bytes (WOTS_HASH)
export const ADRS_HASH_OFF:        i32 = 28;  // 4 bytes (WOTS_HASH)
export const ADRS_TREE_HEIGHT_OFF: i32 = 24;  // 4 bytes (FORS_TREE / TREE)
export const ADRS_TREE_INDEX_OFF:  i32 = 28;  // 4 bytes (FORS_TREE / TREE)

export const ADRS_BYTES: i32 = 32;

// ── Big-endian helpers ─────────────────────────────────────────────────────
// Slhdsa-c uses `__builtin_bswap32` to flip host LE → BE; AsmScript writes
// byte-by-byte so the byte order is explicit and host-independent.

@inline
function storeBE32(p: i32, v: u32): void {
	store<u8>(p + 0, <u8>((v >>> 24) & 0xff));
	store<u8>(p + 1, <u8>((v >>> 16) & 0xff));
	store<u8>(p + 2, <u8>((v >>>  8) & 0xff));
	store<u8>(p + 3, <u8>( v         & 0xff));
}

@inline
function loadBE32(p: i32): u32 {
	return (<u32>load<u8>(p + 0) << 24)
	     | (<u32>load<u8>(p + 1) << 16)
	     | (<u32>load<u8>(p + 2) <<  8)
	     | (<u32>load<u8>(p + 3));
}

// ── Setters / getters (FIPS 205 §4.2) ──────────────────────────────────────

/** Zero all 32 bytes. */
export function adrsClear(adrs: i32): void {
	memory.fill(adrs, 0, ADRS_BYTES);
}

/** FIPS 205 §4.2 Figure 2: layer is a 4-byte big-endian uint32 at bytes 0..3.
 *  All approved parameter sets have d ≤ 22 so the value fits in byte 3, with
 *  bytes 0..2 as zero high bytes; the BE write makes the encoding spec-faithful
 *  rather than relying on the receiving hash to ignore the high three bytes. */
export function adrsSetLayerAddress(adrs: i32, layer: i32): void {
	storeBE32(adrs + ADRS_LAYER_OFF, <u32>layer);
}

export function adrsGetLayerAddress(adrs: i32): i32 {
	return <i32>loadBE32(adrs + ADRS_LAYER_OFF);
}

/** Tree address: 12-byte big-endian integer split across three u32 limbs.
 *  Hi limb maps to bytes 4..7, mid to 8..11, lo to 12..15. The hi limb is
 *  always zero for the FIPS 205 approved parameter sets (max h-h' ≤ 64) but
 *  the API takes it explicitly so callers can carry the full §4.2 width. */
export function adrsSetTreeAddr(adrs: i32, treeHi: u32, treeMid: u32, treeLo: u32): void {
	storeBE32(adrs + ADRS_TREE_OFF + 0, treeHi);
	storeBE32(adrs + ADRS_TREE_OFF + 4, treeMid);
	storeBE32(adrs + ADRS_TREE_OFF + 8, treeLo);
}

export function adrsGetTreeHi(adrs:  i32): u32 { return loadBE32(adrs + ADRS_TREE_OFF + 0); }
export function adrsGetTreeMid(adrs: i32): u32 { return loadBE32(adrs + ADRS_TREE_OFF + 4); }
export function adrsGetTreeLo(adrs:  i32): u32 { return loadBE32(adrs + ADRS_TREE_OFF + 8); }

/** Type field, FIPS 205 §4.2 Table 1, 4-byte big-endian.
 *  Setting type also zeroes the three type-specific slots (bytes 20..31) per
 *  §4.2 Algorithm 14: "the type field of ADRS is set, and all subsequent
 *  type-specific fields are set to zero". */
export function adrsSetType(adrs: i32, typ: i32): void {
	storeBE32(adrs + ADRS_TYPE_OFF, <u32>typ);
	memory.fill(adrs + ADRS_KEYPAIR_OFF, 0, 12);
}

export function adrsGetType(adrs: i32): i32 {
	return <i32>loadBE32(adrs + ADRS_TYPE_OFF);
}

/** Keypair address: 4-byte big-endian (WOTS_HASH, WOTS_PK, WOTS_PRF,
 *  FORS_TREE, FORS_ROOTS, FORS_PRF). */
export function adrsSetKeyPairAddress(adrs: i32, kp: u32): void {
	storeBE32(adrs + ADRS_KEYPAIR_OFF, kp);
}

export function adrsGetKeyPairAddress(adrs: i32): u32 {
	return loadBE32(adrs + ADRS_KEYPAIR_OFF);
}

/** WOTS+ chain address (byte 24..27 in ADRS_WOTS_HASH layout, FIPS 205
 *  §4.2 Table 2). */
export function adrsSetChainAddress(adrs: i32, chain: u32): void {
	storeBE32(adrs + ADRS_CHAIN_OFF, chain);
}

export function adrsGetChainAddress(adrs: i32): u32 {
	return loadBE32(adrs + ADRS_CHAIN_OFF);
}

/** WOTS+ hash address (byte 28..31 in ADRS_WOTS_HASH layout, FIPS 205
 *  §4.2 Table 2). */
export function adrsSetHashAddress(adrs: i32, h: u32): void {
	storeBE32(adrs + ADRS_HASH_OFF, h);
}

export function adrsGetHashAddress(adrs: i32): u32 {
	return loadBE32(adrs + ADRS_HASH_OFF);
}

/** Tree height (byte 24..27 in ADRS_TREE / ADRS_FORS_TREE layouts, FIPS 205
 *  §4.2 Tables 4-5). Aliases ADRS_CHAIN_OFF; callers pick the setter that
 *  matches the active type. */
export function adrsSetTreeHeight(adrs: i32, height: u32): void {
	storeBE32(adrs + ADRS_TREE_HEIGHT_OFF, height);
}

export function adrsGetTreeHeight(adrs: i32): u32 {
	return loadBE32(adrs + ADRS_TREE_HEIGHT_OFF);
}

/** Tree index (byte 28..31 in ADRS_TREE / ADRS_FORS_TREE layouts, FIPS 205
 *  §4.2 Tables 4-5). Aliases ADRS_HASH_OFF; callers pick the setter that
 *  matches the active type. */
export function adrsSetTreeIndex(adrs: i32, index: u32): void {
	storeBE32(adrs + ADRS_TREE_INDEX_OFF, index);
}

export function adrsGetTreeIndex(adrs: i32): u32 {
	return loadBE32(adrs + ADRS_TREE_INDEX_OFF);
}

/** Copy 32 bytes from `src` to `dst`. FIPS 205 §10.1 uses copy-then-mutate
 *  patterns frequently when walking trees, exposing the copy avoids
 *  bouncing through scratch space at the TS layer. */
export function adrsCopy(dst: i32, src: i32): void {
	memory.copy(dst, src, ADRS_BYTES);
}
