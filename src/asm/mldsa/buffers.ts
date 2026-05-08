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
// ML-DSA module — static buffer layout.
// Independent linear memory starting at offset 0. 4 pages = 256KB.
//
// Coefficient size: i32 (FIPS 204 §2.3 — q=8380417 ≈ 2²³ does not fit i16).
// Polynomial size:  256 × 4 = 1024 bytes.
// Polyvec size (ML-DSA-87, max k/ℓ=8): 8 × 1024 = 8192 bytes.
//
// The AS runtime places the zetas StaticArray<i32> (from ntt.ts) in the data
// segment at low memory. Mutable regions start at 4096 to leave room.
//
// Offset    Size      Name
// 0..4095   (AS data segment — zetas table placed here by compiler)
// 4096      8192      POLY_SLOTS    (8 × 1024 bytes = 8 scratch polynomials)
// 12288     32768     POLYVEC_SLOTS (4 × 8192 bytes = 4 scratch polyvecs, k=ℓ=8 max)
// 45056     16384     BYTE_BUFFERS  (seeds, μ, pk, sk, sig — sized in phase 4)
//   45056      32     SEED_OFFSET     (ρ / ρ′ scratch, ML-DSA-87 ρ′ uses 64 → grow later)
//   45088      64     MSG_REP_OFFSET  (μ — message representative, FIPS 204 D.1)
//   45152    2624     PK_OFFSET       (ML-DSA-87 pk: 32 + 8·320 = 2592 ≤ 2624)
//   47776    4960     SK_OFFSET       (ML-DSA-87 sk: 32+32+64+15·128+8·416 ≤ 4960)
//   52736    4768     SIG_OFFSET      (ML-DSA-87 sig: 64+7·640+(75+8) ≤ 4768)
//   57504    3936     RESERVED        (matrix expansion / aux scratch — phase 3+)
// 61440     4096      XOF_PRF_OFFSET  (SHAKE squeezed bytes for sampling)
// END 65536           = 1 page (64KB) of mutable region; full memory = 4 pages
//
// Mutable total: 61440 bytes starting at offset 4096.
//
// Byte buffer offsets are placeholder sizes; full-precision sizing arrives in
// phase 4 with the keygen / sign / verify wrappers. The reservation is
// intentionally generous to avoid layout churn across phases.

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

// ── Polyvec slot constants ──────────────────────────────────────────────────

export const POLYVEC_SLOT_BASE: i32 = 12288;
export const POLYVEC_SLOT_SIZE: i32 = 8192;  // 8 × 1024 (k=ℓ=8 max)

export const POLYVEC_SLOT_0: i32 = 12288;
export const POLYVEC_SLOT_1: i32 = 20480;
export const POLYVEC_SLOT_2: i32 = 28672;
export const POLYVEC_SLOT_3: i32 = 36864;

// ── Byte buffer constants ───────────────────────────────────────────────────

export const BYTE_BUF_BASE: i32 = 45056;

/** Seed buffer (ρ / ρ′ scratch). Reserve 32 bytes; grow later if needed. */
export const SEED_OFFSET: i32    = 45056;
/** Message representative μ (64 bytes per FIPS 204 §3.1 / D.1). */
export const MSG_REP_OFFSET: i32 = 45088;
/** Public key buffer (sized for ML-DSA-87: 32 + 8·320 = 2592 ≤ 2624). */
export const PK_OFFSET: i32      = 45152;
/** Secret key buffer (sized for ML-DSA-87: ≤ 4960). */
export const SK_OFFSET: i32      = 47776;
/** Signature buffer (sized for ML-DSA-87: ≤ 4768). */
export const SIG_OFFSET: i32     = 52736;

// ── XOF/PRF buffer ──────────────────────────────────────────────────────────

/** 4096-byte input buffer for SHAKE/AES output (rejection / noise sampling). */
export const XOF_PRF_OFFSET: i32 = 61440;

// ── Mutable region bounds ───────────────────────────────────────────────────

const MUTABLE_START: i32 = 4096;
const MUTABLE_SIZE:  i32 = 61440;  // 65536 - 4096 — XOF_PRF (4096) inclusive

// ── Module identity ─────────────────────────────────────────────────────────

export function getModuleId():     i32 { return 6; }
export function getMemoryPages():  i32 { return memory.size(); }

// ── Offset getters — poly slots ─────────────────────────────────────────────

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

// ── Offset getters — polyvec slots ──────────────────────────────────────────

export function getPolyvecSlotBase():  i32 { return POLYVEC_SLOT_BASE; }
export function getPolyvecSlotSize():  i32 { return POLYVEC_SLOT_SIZE; }
export function getPolyvecSlot0():     i32 { return POLYVEC_SLOT_0; }
export function getPolyvecSlot1():     i32 { return POLYVEC_SLOT_1; }
export function getPolyvecSlot2():     i32 { return POLYVEC_SLOT_2; }
export function getPolyvecSlot3():     i32 { return POLYVEC_SLOT_3; }

// ── Offset getters — byte buffers ───────────────────────────────────────────

export function getSeedOffset():     i32 { return SEED_OFFSET;    }
export function getMsgRepOffset():   i32 { return MSG_REP_OFFSET; }
export function getPkOffset():       i32 { return PK_OFFSET;      }
export function getSkOffset():       i32 { return SK_OFFSET;      }
export function getSigOffset():      i32 { return SIG_OFFSET;     }
export function getXofPrfOffset():   i32 { return XOF_PRF_OFFSET; }

// ── wipeBuffers ─────────────────────────────────────────────────────────────

/** Zero all mutable regions (poly slots, polyvec slots, byte buffers, XOF buffer). */
export function wipeBuffers(): void {
	memory.fill(MUTABLE_START, 0, MUTABLE_SIZE);
}
