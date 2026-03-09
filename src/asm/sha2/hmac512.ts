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
// src/asm/sha2/hmac512.ts
//
// HMAC-SHA512 and HMAC-SHA384 — RFC 2104
// https://www.rfc-editor.org/rfc/rfc2104
//
// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
// where K' = K padded to 128 bytes with zeros (or H(K) if len(K) > 128).
//
// Differences from HMAC-SHA256 (src/asm/sha2/hmac.ts):
//   - Block size: 128 bytes (not 64)
//   - Hash function: sha512Init/Update/Final (not sha256 equivalents)
//   - Keys > 128 bytes pre-hashed with SHA-512 (not SHA-256)
//   - ipad/opad buffers: 128 bytes each
//   - Inner hash: 64 bytes (SHA-512) or 48 bytes (SHA-384)
//
// Buffer layout:
//   SHA512_INPUT_OFFSET   (1516, 128 bytes) — key staging for hmac512Init;
//                                             message staging for hmac512Update
//   HMAC512_IPAD_OFFSET   (1656, 128 bytes) — K' XOR 0x36 (ipad key material)
//   HMAC512_OPAD_OFFSET   (1784, 128 bytes) — K' XOR 0x5C (opad key material)
//   HMAC512_INNER_OFFSET  (1912,  64 bytes) — inner hash saved by hmac512Final
//   SHA512_OUT_OFFSET     (1452,  64 bytes) — final HMAC output
//
// Streaming API:
//   hmac512Init(keyLen)   — write key (≤ 128 bytes) to SHA512_INPUT_OFFSET before calling.
//                           Builds ipad/opad, starts inner SHA-512 with the ipad block.
//   hmac512Update(len)    — write message chunk (≤ 128 bytes) to SHA512_INPUT_OFFSET, then call.
//   hmac512Final()        — finalize inner hash, run outer hash, write HMAC to SHA512_OUT_OFFSET.
//
//   hmac384Init/Update/Final — same pattern for HMAC-SHA384 (48-byte tag).
//
// Keys longer than 128 bytes:
//   RFC 2104 §3 requires H(K) when len(K) > B. The TypeScript wrapper layer handles
//   pre-hashing via sha512Init/Update/Final before calling hmac512Init(64).

import {
	SHA512_INPUT_OFFSET,
	SHA512_OUT_OFFSET,
	HMAC512_IPAD_OFFSET,
	HMAC512_OPAD_OFFSET,
	HMAC512_INNER_OFFSET,
} from './buffers'
import { sha512Init, sha384Init, sha512Update, sha512Final, sha384Final } from './sha512'

// ── HMAC-SHA512 ─────────────────────────────────────────────────────────────

// Set up ipad/opad from key in SHA512_INPUT_OFFSET[0..keyLen-1].
// keyLen must be ≤ 128. Starts the inner hash by processing the ipad block.
// After this call, SHA512_INPUT_OFFSET is free for message data.
export function hmac512Init(keyLen: i32): void {
	// RFC 2104 §3: K' = K padded to block size (128 bytes) with zeros.
	// Build HMAC512_IPAD_OFFSET = K' XOR ipad and HMAC512_OPAD_OFFSET = K' XOR opad.
	for (let i = 0; i < keyLen; i++) {
		const kb = load<u8>(SHA512_INPUT_OFFSET + i)
		store<u8>(HMAC512_IPAD_OFFSET + i, kb ^ 0x36)
		store<u8>(HMAC512_OPAD_OFFSET + i, kb ^ 0x5c)
	}
	for (let i = keyLen; i < 128; i++) {
		store<u8>(HMAC512_IPAD_OFFSET + i, 0x36)   // K'[i]=0x00 XOR ipad = 0x36
		store<u8>(HMAC512_OPAD_OFFSET + i, 0x5c)   // K'[i]=0x00 XOR opad = 0x5c
	}
	// Begin inner hash: H((K' ⊕ ipad) || m)
	sha512Init()
	memory.copy(SHA512_INPUT_OFFSET, HMAC512_IPAD_OFFSET, 128)
	sha512Update(128)
}

// Hash len bytes from SHA512_INPUT_OFFSET into the inner hash state.
// Same contract as sha512Update: len ≤ 128, caller writes bytes to SHA512_INPUT_OFFSET first.
export function hmac512Update(len: i32): void {
	sha512Update(len)
}

// Finalize inner hash, compute outer hash, write 64-byte HMAC to SHA512_OUT_OFFSET.
export function hmac512Final(): void {
	// Step 1: finalize H((K' ⊕ ipad) || m) → SHA512_OUT_OFFSET (64 bytes)
	sha512Final()
	// Step 2: save inner hash before sha512Init() clears SHA512_H_OFFSET
	memory.copy(HMAC512_INNER_OFFSET, SHA512_OUT_OFFSET, 64)
	// Step 3: outer hash — H((K' ⊕ opad) || inner_hash)
	sha512Init()
	memory.copy(SHA512_INPUT_OFFSET, HMAC512_OPAD_OFFSET, 128)
	sha512Update(128)
	memory.copy(SHA512_INPUT_OFFSET, HMAC512_INNER_OFFSET, 64)
	sha512Update(64)
	sha512Final()
	// SHA512_OUT_OFFSET now contains the 64-byte HMAC-SHA512 tag.
}

// ── HMAC-SHA384 ─────────────────────────────────────────────────────────────
//
// HMAC-SHA384 uses the same 128-byte block size as HMAC-SHA512.
// The inner and outer hashes use SHA-384 (sha384Init + sha384Final).
// The tag is 48 bytes (SHA512_OUT_OFFSET[0..47]).

// Set up ipad/opad from key in SHA512_INPUT_OFFSET[0..keyLen-1].
// keyLen must be ≤ 128. Starts the inner SHA-384 hash with the ipad block.
export function hmac384Init(keyLen: i32): void {
	// Same ipad/opad construction as hmac512Init — same 128-byte block size.
	for (let i = 0; i < keyLen; i++) {
		const kb = load<u8>(SHA512_INPUT_OFFSET + i)
		store<u8>(HMAC512_IPAD_OFFSET + i, kb ^ 0x36)
		store<u8>(HMAC512_OPAD_OFFSET + i, kb ^ 0x5c)
	}
	for (let i = keyLen; i < 128; i++) {
		store<u8>(HMAC512_IPAD_OFFSET + i, 0x36)
		store<u8>(HMAC512_OPAD_OFFSET + i, 0x5c)
	}
	// Begin inner SHA-384 hash: H384((K' ⊕ ipad) || m)
	sha384Init()
	memory.copy(SHA512_INPUT_OFFSET, HMAC512_IPAD_OFFSET, 128)
	sha512Update(128)
}

// Hash len bytes from SHA512_INPUT_OFFSET into the inner SHA-384 hash state.
export function hmac384Update(len: i32): void {
	sha512Update(len)
}

// Finalize inner SHA-384 hash, compute outer hash, write 48-byte tag
// to SHA512_OUT_OFFSET[0..47].
export function hmac384Final(): void {
	// Step 1: finalize H384((K' ⊕ ipad) || m) → SHA512_OUT_OFFSET[0..47]
	sha384Final()
	// Step 2: save inner 48-byte hash before sha384Init() clears SHA512_H_OFFSET
	memory.copy(HMAC512_INNER_OFFSET, SHA512_OUT_OFFSET, 48)
	// Step 3: outer hash — H384((K' ⊕ opad) || inner_hash_48)
	sha384Init()
	memory.copy(SHA512_INPUT_OFFSET, HMAC512_OPAD_OFFSET, 128)
	sha512Update(128)
	memory.copy(SHA512_INPUT_OFFSET, HMAC512_INNER_OFFSET, 48)
	sha512Update(48)
	sha384Final()
	// SHA512_OUT_OFFSET[0..47] now contains the 48-byte HMAC-SHA384 tag.
}
