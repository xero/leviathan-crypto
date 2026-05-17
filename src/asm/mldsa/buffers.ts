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
// src/asm/mldsa/buffers.ts
//
// ML-DSA module, static buffer layout.
// Independent linear memory starting at offset 0. 4 pages = 256KB.
//
// Coefficient size: i32 (FIPS 204 §2.3, q=8380417 ≈ 2²³ does not fit i16).
// Polynomial size:  256 × 4 = 1024 bytes.
// Polyvec size (ML-DSA-87, max k/ℓ=8): 8 × 1024 = 8192 bytes.
//
// The AS runtime places the zetas StaticArray<i32> (from ntt.ts) in the data
// segment at low memory. The ML-DSA zetas table is 256 × 4 = 1024 bytes, well
// within the reserved 4096-byte region. Mutable regions start at 4096.
//
// Byte-buffer sizing per FIPS 204 §4 Table 2:
//
//                 ML-DSA-44  ML-DSA-65  ML-DSA-87
//   pk bytes        1312       1952       2592
//   sk bytes        2560       4032       4896
//   sig bytes       2420       3309       4627
//
// MATRIX_SLOT is sized for the largest matrix Â expanded by Algorithm 32:
//   ML-DSA-87: k × ℓ = 8 × 7 = 56 polynomials × 1024 = 57344 bytes; the slot
//   is rounded up to 8 × 8 = 64 polys = 65536 bytes for clean addressing and
//   to allow row-major access at row stride = ℓ * 1024 with the worst-case ℓ.
// POLYVEC_SLOTS gives 8 polyvec scratches sized for k=8 (any of k or ℓ fits).
//
// Offset    Size      Name
// 0..4095   4096      (AS data segment, zetas table)
// 4096      8192      POLY_SLOTS    (8 × 1024, POLY_SLOT_0..7)
// 12288     65536     MATRIX_SLOT   (matrix Â, k×ℓ max = 8×8 polys × 1024)
// 77824     65536     POLYVEC_SLOTS (8 × 8192, POLYVEC_SLOT_0..7, k=8 max)
// 143360    128       SEED_OFFSET   (ρ ‖ ρ′ ‖ K = 32+64+32, H(ξ‖k‖ℓ, 128) lands here)
// 143488    64        TR_OFFSET     (tr = H(pk, 64))
// 143552    64        MSG_REP_OFFSET (μ, message representative, FIPS 204 D.1)
// 143616    64        C_TILDE_OFFSET (signature commitment hash, ≤ λ/4 max = 64)
// 143680    64        (alignment / reserved)
// 143744    2624      PK_OFFSET     (≥ 2592 for ML-DSA-87)
// 146368    4928      SK_OFFSET     (≥ 4896 for ML-DSA-87)
// 151296    4736      SIG_OFFSET    (≥ 4627 for ML-DSA-87)
// 156032    8192      XOF_PRF_OFFSET (SHAKE squeeze landing zone)
// 164224..262143 reserved (97920 bytes free for future expansion)
//
// Mutable total: 160128 bytes starting at offset 4096. Memory pages = 4.

// ── Poly slot constants ─────────────────────────────────────────────────────

export const POLY_SLOT_BASE: i32 = 4096;
export const POLY_SLOT_SIZE: i32 = 1024;  // 256 × i32

export const POLY_SLOT_0: i32 = 4096;
export const POLY_SLOT_1: i32 = 5120;
export const POLY_SLOT_2: i32 = 6144;
export const POLY_SLOT_3: i32 = 7168;
export const POLY_SLOT_4: i32 = 8192;
export const POLY_SLOT_5: i32 = 9216;
export const POLY_SLOT_6: i32 = 10240;
export const POLY_SLOT_7: i32 = 11264;

// ── Matrix slot ─────────────────────────────────────────────────────────────

/** Â matrix region, row-major, sized for ML-DSA-87 (k × ℓ = 8 × 7, rounded
 *  to 8 × 8 = 64 polys × 1024 = 65536 bytes). Row stride at runtime is
 *  ℓ × 1024 supplied by the orchestration layer. */
export const MATRIX_SLOT:      i32 = 12288;
export const MATRIX_SLOT_SIZE: i32 = 65536;

// ── Polyvec slot constants ──────────────────────────────────────────────────

export const POLYVEC_SLOT_BASE: i32 = 77824;
export const POLYVEC_SLOT_SIZE: i32 = 8192;  // 8 × 1024 (k=ℓ=8 max)

export const POLYVEC_SLOT_0: i32 = 77824;
export const POLYVEC_SLOT_1: i32 = 86016;
export const POLYVEC_SLOT_2: i32 = 94208;
export const POLYVEC_SLOT_3: i32 = 102400;
export const POLYVEC_SLOT_4: i32 = 110592;
export const POLYVEC_SLOT_5: i32 = 118784;
export const POLYVEC_SLOT_6: i32 = 126976;
export const POLYVEC_SLOT_7: i32 = 135168;

// ── Byte buffer constants ───────────────────────────────────────────────────

/** Seed scratch. Holds H(ξ‖k‖ℓ, 128) output: ρ(32) ‖ ρ′(64) ‖ K(32) = 128 B. */
export const SEED_OFFSET:    i32 = 143360;
/** tr = H(pk, 64), public-key digest cached in sk for signing. */
export const TR_OFFSET:      i32 = 143488;
/** μ, message representative (FIPS 204 §6.2 / Appendix D.1). */
export const MSG_REP_OFFSET: i32 = 143552;
/** c̃, signature commitment hash, λ/4 bytes (≤ 64 for λ=256). */
export const C_TILDE_OFFSET: i32 = 143616;
/** Public key buffer (max 2592 for ML-DSA-87, FIPS 204 §4 Table 2). */
export const PK_OFFSET:      i32 = 143744;
/** Secret key buffer (max 4896 for ML-DSA-87). */
export const SK_OFFSET:      i32 = 146368;
/** Signature buffer (max 4627 for ML-DSA-87). */
export const SIG_OFFSET:     i32 = 151296;

// ── XOF/PRF buffer ──────────────────────────────────────────────────────────

/** 8192-byte landing zone for SHAKE/AES output (rejection / noise sampling). */
export const XOF_PRF_OFFSET: i32 = 156032;

// ── Mutable region bounds ───────────────────────────────────────────────────

const MUTABLE_START: i32 = 4096;
const MUTABLE_SIZE:  i32 = 160128;  // 164224 - 4096 (XOF_PRF inclusive)

// ── Module identity ─────────────────────────────────────────────────────────

export function getModuleId():     i32 { return 6; }
export function getMemoryPages():  i32 { return memory.size(); }

// ── Offset getters, poly slots ─────────────────────────────────────────────

export function getPolySlotBase():  i32 { return POLY_SLOT_BASE; }
export function getPolySlotSize():  i32 { return POLY_SLOT_SIZE; }
export function getPolySlot0():     i32 { return POLY_SLOT_0; }
export function getPolySlot1():     i32 { return POLY_SLOT_1; }
export function getPolySlot2():     i32 { return POLY_SLOT_2; }
export function getPolySlot3():     i32 { return POLY_SLOT_3; }
export function getPolySlot4():     i32 { return POLY_SLOT_4; }
export function getPolySlot5():     i32 { return POLY_SLOT_5; }
export function getPolySlot6():     i32 { return POLY_SLOT_6; }
export function getPolySlot7():     i32 { return POLY_SLOT_7; }

// ── Offset getters, matrix slot ────────────────────────────────────────────

export function getMatrixSlot():     i32 { return MATRIX_SLOT; }
export function getMatrixSlotSize(): i32 { return MATRIX_SLOT_SIZE; }

// ── Offset getters, polyvec slots ──────────────────────────────────────────

export function getPolyvecSlotBase():  i32 { return POLYVEC_SLOT_BASE; }
export function getPolyvecSlotSize():  i32 { return POLYVEC_SLOT_SIZE; }
export function getPolyvecSlot0():     i32 { return POLYVEC_SLOT_0; }
export function getPolyvecSlot1():     i32 { return POLYVEC_SLOT_1; }
export function getPolyvecSlot2():     i32 { return POLYVEC_SLOT_2; }
export function getPolyvecSlot3():     i32 { return POLYVEC_SLOT_3; }
export function getPolyvecSlot4():     i32 { return POLYVEC_SLOT_4; }
export function getPolyvecSlot5():     i32 { return POLYVEC_SLOT_5; }
export function getPolyvecSlot6():     i32 { return POLYVEC_SLOT_6; }
export function getPolyvecSlot7():     i32 { return POLYVEC_SLOT_7; }

// ── Offset getters, byte buffers ───────────────────────────────────────────

export function getSeedOffset():     i32 { return SEED_OFFSET;    }
export function getTrOffset():       i32 { return TR_OFFSET;      }
export function getMsgRepOffset():   i32 { return MSG_REP_OFFSET; }
export function getCTildeOffset():   i32 { return C_TILDE_OFFSET; }
export function getPkOffset():       i32 { return PK_OFFSET;      }
export function getSkOffset():       i32 { return SK_OFFSET;      }
export function getSigOffset():      i32 { return SIG_OFFSET;     }
export function getXofPrfOffset():   i32 { return XOF_PRF_OFFSET; }

// ── wipeBuffers ─────────────────────────────────────────────────────────────

/** Zero all mutable regions (poly slots, matrix slot, polyvec slots, byte
 *  buffers, XOF/PRF buffer). Called from MlDsaBase.dispose(). */
export function wipeBuffers(): void {
	memory.fill(MUTABLE_START, 0, MUTABLE_SIZE);
}
