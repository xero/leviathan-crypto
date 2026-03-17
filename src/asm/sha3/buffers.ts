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
// src/asm/sha3/buffers.ts
//
// SHA-3 module — static buffer layout.
// Independent linear memory starting at offset 0.
//
// Total: 545 bytes < 3 × 64KB = 196608.
//
// Offset   Size     Name
// 0        200      KECCAK_STATE (25 × u64 = 5×5 lane matrix)
// 200        4      KECCAK_RATE (u32 rate in bytes, variant-specific)
// 204        4      KECCAK_ABSORBED (u32 bytes absorbed into current block)
// 208        1      KECCAK_DSBYTE (u8 domain separation byte)
// 209      168      KECCAK_INPUT (input staging — max rate = SHAKE128 at 168)
// 377      168      KECCAK_OUT (output buffer — one SHAKE128 squeeze block)
// 545               END (< 196608 = 3 × 64KB ✓)

export const STATE_OFFSET:    i32 = 0;    // 200 bytes
export const RATE_OFFSET:     i32 = 200;  //   4 bytes
export const ABSORBED_OFFSET: i32 = 204;  //   4 bytes
export const DSBYTE_OFFSET:   i32 = 208;  //   1 byte
export const INPUT_OFFSET:    i32 = 209;  // 168 bytes
export const OUT_OFFSET:      i32 = 377;  // 168 bytes
// END = 545 < 196608 ✓

export function getModuleId():       i32 { return 3               }
export function getStateOffset():    i32 { return STATE_OFFSET    }
export function getRateOffset():     i32 { return RATE_OFFSET     }
export function getAbsorbedOffset(): i32 { return ABSORBED_OFFSET }
export function getDsByteOffset():   i32 { return DSBYTE_OFFSET   }
export function getInputOffset():    i32 { return INPUT_OFFSET    }
export function getOutOffset():      i32 { return OUT_OFFSET      }
export function getMemoryPages():    i32 { return memory.size()   }
