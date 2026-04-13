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
// src/asm/kyber/buffers.ts
//
// Kyber module — static buffer layout.
// Independent linear memory starting at offset 0. 3 pages = 192KB.
//
// The AS runtime places the zetas StaticArray<i16> (from ntt.ts) in the data
// segment at low memory. Mutable regions start at 4096 to leave room.
//
// Offset    Size      Name
// 0..4095   (AS data segment — zetas table placed here by compiler)
// 4096      5120      POLY_SLOTS  (10 × 512 bytes = 10 scratch polynomials)
// 9216      16384     POLYVEC_SLOTS (8 × 2048 bytes = 8 scratch polyvecs, K=4 max)
// 25600     8192      BYTE_BUFFERS (8 × 1024 bytes — named sub-regions below)
//   25600     32      SEED_BUFFER
//   25632     32      MSG_BUFFER
//   25664   1568      PK_BUFFER (k=4: polyvec_bytes 1536 + seed 32)
//   27232   1536      SK_BUFFER (k=4: polyvec_bytes 1536)
//   28768   1568      CT_BUFFER (k=4: polyvec compress 1408 + poly compress 160)
//   30336   1568      CT_PRIME_BUFFER (decaps re-encrypt comparison, k=4 max)
// 31904     1024      XOF_PRF_BUFFER
// 32928      512      POLY_ACC_BUFFER
// END 33440            < 192KB ✓
//
// Mutable total: 29344 bytes starting at offset 4096.
//
// ── Byte buffer sequencing contract ─────────────────────────────────────────
// PK, SK, CT are contiguous at k=4. The KEM decaps path relies on
// indcpaDecrypt completing (consuming SK via polyvec_frombytes) before
// indcpaEncrypt reuses PK_OFFSET. Do not interleave decrypt/encrypt calls.
// CT_PRIME sits after CT for the decaps re-encrypt → ct_verify comparison.

// ── Poly slot constants ─────────────────────────────────────────────────────

export const POLY_SLOT_BASE: i32 = 4096;
export const POLY_SLOT_SIZE: i32 = 512;  // 256 × i16

export const POLY_SLOT_0: i32 = 4096;
export const POLY_SLOT_1: i32 = 4608;
export const POLY_SLOT_2: i32 = 5120;
export const POLY_SLOT_3: i32 = 5632;
export const POLY_SLOT_4: i32 = 6144;
export const POLY_SLOT_5: i32 = 6656;
export const POLY_SLOT_6: i32 = 7168;
export const POLY_SLOT_7: i32 = 7680;
export const POLY_SLOT_8: i32 = 8192;
export const POLY_SLOT_9: i32 = 8704;

// ── Polyvec slot constants ──────────────────────────────────────────────────

export const POLYVEC_SLOT_BASE: i32 = 9216;
export const POLYVEC_SLOT_SIZE: i32 = 2048;  // 4 × 512 (k=4 max)

export const POLYVEC_SLOT_0: i32 = 9216;
export const POLYVEC_SLOT_1: i32 = 11264;
export const POLYVEC_SLOT_2: i32 = 13312;
export const POLYVEC_SLOT_3: i32 = 15360;
export const POLYVEC_SLOT_4: i32 = 17408;
export const POLYVEC_SLOT_5: i32 = 19456;
export const POLYVEC_SLOT_6: i32 = 21504;
export const POLYVEC_SLOT_7: i32 = 23552;

// ── Byte buffer constants ───────────────────────────────────────────────────

export const BYTE_BUF_BASE: i32   = 25600;

/** 32-byte seed buffer (rho, sigma, etc.) */
export const SEED_OFFSET: i32     = 25600;
/** 32-byte message/shared-key buffer */
export const MSG_OFFSET: i32      = 25632;
/** Public key buffer: k×384 polyvec bytes + 32-byte seed (max k=4: 1568B) */
export const PK_OFFSET: i32       = 25664;
/** Secret key buffer: k×384 polyvec bytes (max k=4: 1536B) */
export const SK_OFFSET: i32       = 27232;
/** Ciphertext buffer: polyvec compress + poly compress (max k=4: 1568B) */
export const CT_OFFSET: i32       = 28768;
/** Ciphertext comparison buffer for KEM decaps re-encrypt (max k=4: 1568B) */
export const CT_PRIME_OFFSET: i32 = 30336;

// ── XOF/PRF buffer ──────────────────────────────────────────────────────────

/** 1024-byte input buffer for XOF/PRF output (rejection/noise sampling) */
export const XOF_PRF_OFFSET: i32  = 31904;

/**
 * Internal 512-byte scratch polynomial for polyvec_basemul_acc_montgomery.
 * Not intended for TS-layer use.
 */
export const POLY_ACC_OFFSET: i32 = 32928;

// ── Mutable region bounds ───────────────────────────────────────────────────

const MUTABLE_START: i32 = 4096;
const MUTABLE_SIZE:  i32 = 29344;  // 33440 - 4096

// ── Module identity ─────────────────────────────────────────────────────────

export function getModuleId():     i32 { return 5; }
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
export function getPolySlot8():     i32 { return POLY_SLOT_8; }
export function getPolySlot9():     i32 { return POLY_SLOT_9; }

// ── Offset getters — polyvec slots ──────────────────────────────────────────

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

// ── Offset getters — byte buffers ───────────────────────────────────────────

export function getSeedOffset():      i32 { return SEED_OFFSET;     }
export function getMsgOffset():       i32 { return MSG_OFFSET;      }
export function getPkOffset():        i32 { return PK_OFFSET;       }
export function getSkOffset():        i32 { return SK_OFFSET;       }
export function getCtOffset():        i32 { return CT_OFFSET;       }
export function getCtPrimeOffset():   i32 { return CT_PRIME_OFFSET; }
export function getXofPrfOffset():    i32 { return XOF_PRF_OFFSET;  }

// ── wipeBuffers ─────────────────────────────────────────────────────────────

/** Zero all mutable regions (poly slots, polyvec slots, byte buffers, XOF buffer). */
export function wipeBuffers(): void {
	memory.fill(MUTABLE_START, 0, MUTABLE_SIZE);
}
