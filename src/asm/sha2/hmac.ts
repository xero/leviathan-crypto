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
// src/asm/sha2/hmac.ts
//
// HMAC-SHA256, RFC 2104
// https://www.rfc-editor.org/rfc/rfc2104
//
// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
// where K' = K padded to 64 bytes with zeros (or H(K) if len(K) > 64).
//
// Buffer layout (buffers.ts):
//   SHA256_INPUT_OFFSET   (384, 64 bytes), key staging for hmac256Init;
//                                           message staging for hmac256Update
//   HMAC256_IPAD_OFFSET   (460, 64 bytes), K' XOR 0x36 (ipad key material)
//   HMAC256_OPAD_OFFSET   (524, 64 bytes), K' XOR 0x5C (opad key material)
//   HMAC256_INNER_OFFSET  (588, 32 bytes), inner hash saved by hmac256Final
//   SHA256_OUT_OFFSET     (352, 32 bytes), final HMAC output
//
// Streaming API:
//   hmac256Init(keyLen)  , write key (≤ 64 bytes) to SHA256_INPUT_OFFSET before calling.
//                           Builds ipad/opad, starts inner SHA-256 with the ipad block.
//                           SHA256_INPUT_OFFSET is free for message data after this returns.
//   hmac256Update(len)   , write message chunk (≤ 64 bytes) to SHA256_INPUT_OFFSET, then call.
//                           Passes through to the running inner SHA-256 state.
//   hmac256Final()       , finalize inner hash, run outer hash, write HMAC to SHA256_OUT_OFFSET.
//
// Keys longer than 64 bytes:
//   RFC 2104 §3 requires H(K) when len(K) > B. Since SHA256_INPUT_OFFSET is 64 bytes,
//   the caller must pre-hash the long key using sha256Init/sha256Update/sha256Final, then
//   copy the 32-byte SHA256_OUT_OFFSET result to SHA256_INPUT_OFFSET and call hmac256Init(32).

import {
	SHA256_INPUT_OFFSET,
	SHA256_OUT_OFFSET,
	HMAC256_IPAD_OFFSET,
	HMAC256_OPAD_OFFSET,
	HMAC256_INNER_OFFSET,
} from './buffers'
import { sha256Init, sha256Update, sha256Final } from './sha256'

// Set up ipad/opad from key in SHA256_INPUT_OFFSET[0..keyLen-1].
// keyLen must be ≤ 64. Starts the inner hash by processing the ipad block.
// After this call SHA256_INPUT_OFFSET is free for message data.
export function hmac256Init(keyLen: i32): void {
	// RFC 2104 §3: K' = K padded to block size (64 bytes) with zeros.
	// Single 64-iteration pass with branchless masking, work per iteration
	// is constant, so total time does not depend on keyLen.
	for (let i: i32 = 0; i < 64; i++) {
		// mask = 0xFF when i < keyLen, 0x00 when i >= keyLen
		const inKey: i32 = (i - keyLen) >> 31
		const mask:  u8  = <u8>inKey
		const kb:    u8  = load<u8>(SHA256_INPUT_OFFSET + i) & mask
		store<u8>(HMAC256_IPAD_OFFSET + i, kb ^ 0x36)
		store<u8>(HMAC256_OPAD_OFFSET + i, kb ^ 0x5c)
	}
	// Begin inner hash: H((K' ⊕ ipad) || m)
	sha256Init()
	memory.copy(SHA256_INPUT_OFFSET, HMAC256_IPAD_OFFSET, 64)
	sha256Update(64)
}

// Hash len bytes from SHA256_INPUT_OFFSET into the inner hash state.
// Same contract as sha256Update: len ≤ 64, caller writes bytes to SHA256_INPUT_OFFSET first.
export function hmac256Update(len: i32): void {
	sha256Update(len)
}

// Finalize inner hash, compute outer hash, write 32-byte HMAC to SHA256_OUT_OFFSET.
export function hmac256Final(): void {
	// Step 1: finalize H((K' ⊕ ipad) || m) → SHA256_OUT_OFFSET
	sha256Final()
	// Step 2: save inner hash before sha256Init() clears SHA256_H_OFFSET
	memory.copy(HMAC256_INNER_OFFSET, SHA256_OUT_OFFSET, 32)
	// Step 3: outer hash, H((K' ⊕ opad) || inner_hash)
	sha256Init()
	memory.copy(SHA256_INPUT_OFFSET, HMAC256_OPAD_OFFSET, 64)
	sha256Update(64)
	memory.copy(SHA256_INPUT_OFFSET, HMAC256_INNER_OFFSET, 32)
	sha256Update(32)
	sha256Final()
	// SHA256_OUT_OFFSET now contains the final HMAC result.
}
