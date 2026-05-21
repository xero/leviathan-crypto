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
// src/asm/slhdsa/buffers.ts
//
// SLH-DSA module, static buffer layout.
// Independent linear memory starting at offset 0. 2 pages = 128 KB.
//
// FIPS 205, Stateless Hash-Based Digital Signature Standard.
// Layout: verify(M, sig, pk) co-locates pk+M+sig in INPUT and ACVP messages
// reach 8 KB, so the verify input lands at ~58 KB worst-case. INPUT is sized
// at 60 KB; OUT/STATE/SCRATCH fill the rest of the 2 WASM pages (128 KB):
//
//   Offset    Size      Region        Purpose
//   0x00000   60 KB     INPUT         sk || M || opt_rand staging for sign;
//                                     pk || M || sig staging for verify (worst-case
//                                     for 256f sigVer: 64 + 8192 + 49856 = 58112 B)
//   0x0F000   52 KB     OUT           signature output (49856 max for 256f + slack)
//   0x1C000   4 KB      STATE         working state, current ADRS, hypertree path,
//                                     FORS auth, PARAMS slot
//   0x1D000   8 KB      SCRATCH       hash-function scratch, embedded Keccak working state
//   0x1F000   END       124 KB total, fits in 2 WASM pages (128 KB)
//
// SCRATCH carries the embedded SHAKE128/SHAKE256 sponge state. Following the
// per-module-ownership rule, the Keccak permutation is embedded here rather
// than cross-linked from sha3.wasm. The sponge sub-layout
// mirrors src/asm/sha3/buffers.ts so the verbatim Keccak port below stays
// readable side-by-side with the sha3 source.
//
// STATE holds the algorithm working set (WOTS+ chains, FORS auth paths, XMSS
// authentication paths, hypertree idx_tree) plus the ADRS scratch and PARAMS
// slot exposed via ADRS_OFFSET / PARAMS_OFFSET.

// ── User-facing regions ─────────────────────────────────────────────────────

/** sk || M || opt_rand staging for sign; pk || M || sig staging for verify.
 *  ACVP corpus has messages up to 8 KB, so 256f sigVer worst-case input is
 *  pk (64) + M (8192) + sig (49856) = 58112 B. 60 KB gives ~2.4 KB of slack. */
export const INPUT_OFFSET:   i32 = 0x00000;
export const INPUT_SIZE:     i32 = 0x0F000;   // 60 KB

/** Signature output, max sig is 49856 B (256f) per FIPS 205 §9 sigEncode. */
export const OUT_OFFSET:     i32 = 0x0F000;
export const OUT_SIZE:       i32 = 0x0D000;   // 52 KB (49856 + 2432 slack)

/** Working state: current ADRS, hypertree authentication path, FORS auth,
 *  PARAMS slot. Sub-offsets below. */
export const STATE_OFFSET:   i32 = 0x1C000;
export const STATE_SIZE:     i32 = 0x01000;   // 4 KB

/** Hash-function scratch, embedded SHAKE128/SHAKE256 sponge state.
 *  Sub-offsets below. */
export const SCRATCH_OFFSET: i32 = 0x1D000;
export const SCRATCH_SIZE:   i32 = 0x02000;   // 8 KB

export const END_OFFSET:     i32 = 0x1F000;   // 124 KB total

// ── STATE sub-layout ────────────────────────────────────────────────────────
// The ADRS scratch + PARAMS slot occupy bytes 0..63 of STATE. The hypertree /
// FORS / XMSS working buffers start at STATE_OFFSET + 64 upward (see wots.ts,
// fors.ts, xmss.ts, hypertree.ts for the per-algorithm sub-offsets).

/** Canonical ADRS scratch (32 bytes, FIPS 205 §4.2 Table 1). */
export const ADRS_OFFSET:    i32 = STATE_OFFSET;
export const ADRS_SIZE:      i32 = 32;

/** Active parameter set slot, populated by slhSetParams{128f,192f,256f}.
 *  Layout (16 bytes total):
 *    +0  i32  n  (security parameter, bytes)
 *    +4  i32  m  (Hmsg output length, bytes)
 *    +8  i32  paramSet (0=128f, 1=192f, 2=256f)
 *    +12 i32  reserved
 *  h/d/h'/k/a are derived by per-set lookup inside the WOTS+/FORS/XMSS
 *  modules and do not occupy slots in PARAMS. */
export const PARAMS_OFFSET:  i32 = STATE_OFFSET + 32;
export const PARAMS_SIZE:    i32 = 16;

export const PARAMS_N_OFF:        i32 = PARAMS_OFFSET + 0;
export const PARAMS_M_OFF:        i32 = PARAMS_OFFSET + 4;
export const PARAMS_PARAMSET_OFF: i32 = PARAMS_OFFSET + 8;

// Param-set numeric tags. Match SlhDsaParams in src/ts/slhdsa/params.ts.
export const PARAMSET_128F: i32 = 0;
export const PARAMSET_192F: i32 = 1;
export const PARAMSET_256F: i32 = 2;

// ── SCRATCH sub-layout (embedded Keccak sponge) ─────────────────────────────
// Mirrors src/asm/sha3/buffers.ts. The sub-region is private to keccak.ts
// + hashes.ts; nothing outside this module reads it.

/** Keccak-f[1600] lane state, 25 × u64 = 200 bytes. FIPS 202 §3. */
export const KECCAK_STATE_OFFSET:    i32 = SCRATCH_OFFSET + 0;
export const KECCAK_RATE_OFFSET:     i32 = SCRATCH_OFFSET + 200;
export const KECCAK_ABSORBED_OFFSET: i32 = SCRATCH_OFFSET + 204;
export const KECCAK_DSBYTE_OFFSET:   i32 = SCRATCH_OFFSET + 208;
// 209..255 reserved (alignment slack before staging buffer).
/** Sponge input staging, sized for the SHAKE128 rate (168). */
export const KECCAK_INPUT_OFFSET:    i32 = SCRATCH_OFFSET + 256;
/** Sponge output staging, one squeeze block max. */
export const KECCAK_OUT_OFFSET:      i32 = SCRATCH_OFFSET + 424;
// 424 + 168 = 592 bytes used inside SCRATCH; 8 KB - 592 = ~7.4 KB free for
// hash-family scratch when WOTS+/FORS/XMSS/hypertree compose.

// ── Module identity / offset getters ────────────────────────────────────────

export function getModuleId():       i32 { return 7;             }
export function getMemoryPages():    i32 { return memory.size(); }

export function getInputOffset():    i32 { return INPUT_OFFSET;   }
export function getOutOffset():      i32 { return OUT_OFFSET;     }
export function getStateOffset():    i32 { return STATE_OFFSET;   }
export function getScratchOffset():  i32 { return SCRATCH_OFFSET; }
export function getAdrsOffset():     i32 { return ADRS_OFFSET;    }
export function getParamsOffset():   i32 { return PARAMS_OFFSET;  }
export function getParamN():         i32 { return load<i32>(PARAMS_N_OFF);        }
export function getParamM():         i32 { return load<i32>(PARAMS_M_OFF);        }
export function getParamSet():       i32 { return load<i32>(PARAMS_PARAMSET_OFF); }

// ── Parameter-set selectors (FIPS 205 §11.1 Table 2) ───────────────────────

/** SLH-DSA-SHAKE-128f: n=16, m=34 (category 1). FIPS 205 §11.1 Table 2;
 *  m = ⌈(h-h')/8⌉ + ⌈h'/8⌉ + ⌈k·a/8⌉ = 8 + 1 + 25 = 34. */
export function slhSetParams128f(): void {
	store<i32>(PARAMS_N_OFF,        16);
	store<i32>(PARAMS_M_OFF,        34);
	store<i32>(PARAMS_PARAMSET_OFF, PARAMSET_128F);
}

/** SLH-DSA-SHAKE-192f: n=24, m=42 (category 3). FIPS 205 §11.1 Table 2;
 *  m = ⌈(h-h')/8⌉ + ⌈h'/8⌉ + ⌈k·a/8⌉ = 8 + 1 + 33 = 42. */
export function slhSetParams192f(): void {
	store<i32>(PARAMS_N_OFF,        24);
	store<i32>(PARAMS_M_OFF,        42);
	store<i32>(PARAMS_PARAMSET_OFF, PARAMSET_192F);
}

/** SLH-DSA-SHAKE-256f: n=32, m=49 (category 5). */
export function slhSetParams256f(): void {
	store<i32>(PARAMS_N_OFF,        32);
	store<i32>(PARAMS_M_OFF,        49);
	store<i32>(PARAMS_PARAMSET_OFF, PARAMSET_256F);
}

// ── wipeBuffers ─────────────────────────────────────────────────────────────

/** Zero OUT, STATE, SCRATCH in that order. INPUT is caller-supplied material
 *  so the lib does not own its zeroing; TS callers wipe their own input
 *  buffers per the universal hygiene rule. */
export function wipeBuffers(): void {
	memory.fill(OUT_OFFSET,     0, OUT_SIZE);
	memory.fill(STATE_OFFSET,   0, STATE_SIZE);
	memory.fill(SCRATCH_OFFSET, 0, SCRATCH_SIZE);
}
