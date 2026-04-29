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
// src/asm/sha2/buffers.ts
//
// SHA-2 module — static linear-memory buffer layout
// All offsets start at 0 (independent module memory).
//
// Layout (byte offsets):
//
//   SHA-256 buffers:
//     SHA256_H_OFFSET:       0    (32 bytes — hash state H0..H7)
//     SHA256_BLOCK_OFFSET:   32   (64 bytes — block accumulator)
//     SHA256_W_OFFSET:       96   (256 bytes — message schedule W[0..63])
//     SHA256_OUT_OFFSET:     352  (32 bytes — digest output)
//     SHA256_INPUT_OFFSET:   384  (64 bytes — user input staging)
//     SHA256_PARTIAL_OFFSET: 448  (4 bytes — u32 partial block len)
//     SHA256_TOTAL_OFFSET:   452  (8 bytes — u64 total bytes hashed)
//     HMAC256_IPAD_OFFSET:   460  (64 bytes — K' XOR ipad)
//     HMAC256_OPAD_OFFSET:   524  (64 bytes — K' XOR opad)
//     HMAC256_INNER_OFFSET:  588  (32 bytes — inner hash saved by hmacFinal)
//
//   SHA-512 buffers (SHA-384 shares these):
//     SHA512_H_OFFSET:       620  (64 bytes — hash state H0..H7)
//     SHA512_BLOCK_OFFSET:   684  (128 bytes — block accumulator)
//     SHA512_W_OFFSET:       812  (640 bytes — message schedule W[0..79])
//     SHA512_OUT_OFFSET:     1452 (64 bytes — digest output)
//     SHA512_INPUT_OFFSET:   1516 (128 bytes — user input staging)
//     SHA512_PARTIAL_OFFSET: 1644 (4 bytes — u32 partial block len)
//     SHA512_TOTAL_OFFSET:   1648 (8 bytes — u64 total bytes hashed)
//     HMAC512_IPAD_OFFSET:   1656 (128 bytes — K' XOR ipad)
//     HMAC512_OPAD_OFFSET:   1784 (128 bytes — K' XOR opad)
//     HMAC512_INNER_OFFSET:  1912 (64 bytes — inner hash saved by hmacFinal)
//     BUFFER_END:            HMAC512_INNER_OFFSET + 64 = end of the last buffer

// ── SHA-256 buffer offsets ───────────────────────────────────────────────────

export const SHA256_H_OFFSET:       i32 = 0
export const SHA256_BLOCK_OFFSET:   i32 = 32
export const SHA256_W_OFFSET:       i32 = 96
export const SHA256_OUT_OFFSET:     i32 = 352
export const SHA256_INPUT_OFFSET:   i32 = 384
export const SHA256_PARTIAL_OFFSET: i32 = 448
export const SHA256_TOTAL_OFFSET:   i32 = 452
export const HMAC256_IPAD_OFFSET:   i32 = 460
export const HMAC256_OPAD_OFFSET:   i32 = 524
export const HMAC256_INNER_OFFSET:  i32 = 588

// ── SHA-512 buffer offsets ───────────────────────────────────────────────────

export const SHA512_H_OFFSET:       i32 = 620
export const SHA512_BLOCK_OFFSET:   i32 = 684
export const SHA512_W_OFFSET:       i32 = 812
export const SHA512_OUT_OFFSET:     i32 = 1452
export const SHA512_INPUT_OFFSET:   i32 = 1516
export const SHA512_PARTIAL_OFFSET: i32 = 1644
export const SHA512_TOTAL_OFFSET:   i32 = 1648
export const HMAC512_IPAD_OFFSET:   i32 = 1656
export const HMAC512_OPAD_OFFSET:   i32 = 1784
export const HMAC512_INNER_OFFSET:  i32 = 1912

/**
 * End of the SHA-2 module buffer region (exclusive upper bound).
 * `HMAC512_INNER_OFFSET + 64` = end of the last 64-byte buffer.
 * Used by `wipeBuffers()` in `index.ts`.
 */
export const BUFFER_END:            i32 = HMAC512_INNER_OFFSET + 64

// ── Module identity ──────────────────────────────────────────────────────────

export function getModuleId(): i32 {
	return 2
}

export function getMemoryPages(): i32 {
	return memory.size()
}

// ── Offset getter functions ──────────────────────────────────────────────────

export function getSha256HOffset():       i32 { return SHA256_H_OFFSET       }
export function getSha256BlockOffset():   i32 { return SHA256_BLOCK_OFFSET   }
export function getSha256WOffset():       i32 { return SHA256_W_OFFSET       }
export function getSha256OutOffset():     i32 { return SHA256_OUT_OFFSET     }
export function getSha256InputOffset():   i32 { return SHA256_INPUT_OFFSET   }
export function getSha256PartialOffset(): i32 { return SHA256_PARTIAL_OFFSET }
export function getSha256TotalOffset():   i32 { return SHA256_TOTAL_OFFSET   }
export function getHmac256IpadOffset():   i32 { return HMAC256_IPAD_OFFSET   }
export function getHmac256OpadOffset():   i32 { return HMAC256_OPAD_OFFSET   }
export function getHmac256InnerOffset():  i32 { return HMAC256_INNER_OFFSET  }

export function getSha512HOffset():       i32 { return SHA512_H_OFFSET       }
export function getSha512BlockOffset():   i32 { return SHA512_BLOCK_OFFSET   }
export function getSha512WOffset():       i32 { return SHA512_W_OFFSET       }
export function getSha512OutOffset():     i32 { return SHA512_OUT_OFFSET     }
export function getSha512InputOffset():   i32 { return SHA512_INPUT_OFFSET   }
export function getSha512PartialOffset(): i32 { return SHA512_PARTIAL_OFFSET }
export function getSha512TotalOffset():   i32 { return SHA512_TOTAL_OFFSET   }
export function getHmac512IpadOffset():   i32 { return HMAC512_IPAD_OFFSET   }
export function getHmac512OpadOffset():   i32 { return HMAC512_OPAD_OFFSET   }
export function getHmac512InnerOffset():  i32 { return HMAC512_INNER_OFFSET  }
