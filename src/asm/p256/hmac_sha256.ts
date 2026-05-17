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
// src/asm/p256/hmac_sha256.ts
//
// HMAC-SHA-256 embedded into p256.wasm, RFC 2104.
// https://www.rfc-editor.org/rfc/rfc2104
//
// Verbatim port from src/asm/sha2/hmac.ts with buffer offsets rewritten
// to ./buffers (p256 local memory layout). Algorithm code is byte-
// equivalent to the canonical source. The function drives RFC 6979 §3.2
// HMAC_DRBG-style K derivation; the per-derivation rejection-sampling
// loop in ./rfc6979.ts hammers hmac256Init / hmac256Update / hmac256Final
// repeatedly (key = HMAC_DRBG_K, message = V || octet || ... varies).
//
// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
// where K' = K padded to 64 bytes with zeros (or H(K) if len(K) > 64).
//
// Streaming API (module-internal; NOT re-exported from index.ts):
//   hmac256Init(keyLen)        , write key to SHA256_INPUT_OFFSET before calling
//   hmac256Update(len)         , write chunk to SHA256_INPUT_OFFSET, then call
//   hmac256UpdateBytes(src,n)  , chunked update over arbitrary memory offset
//   hmac256Final()             , finalize, write HMAC to SHA256_OUT_OFFSET
//
// Key-length contract: keyLen ≤ 64. RFC 6979 §3.2 uses a 32-byte key
// (V or K from the DRBG state) on every call, so the long-key path
// (H(K) when len(K) > B) is dead code in this module and is not
// implemented. Removing it shrinks the audit surface; callers that
// would feed a > 64-byte key must pre-hash externally.

import {
	SHA256_INPUT_OFFSET,
	SHA256_OUT_OFFSET,
	HMAC256_IPAD_OFFSET,
	HMAC256_OPAD_OFFSET,
	HMAC256_INNER_OFFSET,
} from './buffers'
import {sha256Init, sha256Update, sha256Final, sha256UpdateBytes} from './sha256'

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
// Same contract as sha256Update: len ≤ 64, caller writes bytes to
// SHA256_INPUT_OFFSET first.
export function hmac256Update(len: i32): void {
	sha256Update(len)
}

// Chunked update over arbitrary linear-memory source. Mirrors
// sha256UpdateBytes, used by RFC 6979 to feed V || 0x00 || int2octets(d)
// || bits2octets(h1) into the running inner hash without per-piece
// staging by the caller.
export function hmac256UpdateBytes(src: i32, len: i32): void {
	sha256UpdateBytes(src, len)
}

// Finalize inner hash, compute outer hash, write 32-byte HMAC to
// SHA256_OUT_OFFSET.
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
