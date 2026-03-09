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
// src/asm/chacha/poly1305.ts
//
// Poly1305 MAC — AssemblyScript implementation
// Standard: RFC 8439 §2.5
// URL: https://www.rfc-editor.org/rfc/rfc8439
//
// State representation: 5 × u64 limbs (26 bits each) stored in linear memory.
// No module-level globals — wipeBuffers() uses memory.fill() to zero all state.

import {
	POLY_KEY_OFFSET, POLY_MSG_OFFSET,
	POLY_BUF_OFFSET, POLY_BUF_LEN_OFFSET,
	POLY_TAG_OFFSET,
	POLY_H_OFFSET, POLY_R_OFFSET, POLY_RS_OFFSET, POLY_S_OFFSET,
} from './buffers'

const MASK26: u64 = 0x3ffffff

// ── Internal: absorb one 16-byte block ────────────────────────────────────────
// h = (h + n) * r  mod  p
@inline
function absorbBlock(src: i32, hibit: u64): void {
	const n0 = u64(load<u32>(src +  0))        & MASK26
	const n1 = u64(load<u32>(src +  3)) >>  2  & MASK26
	const n2 = u64(load<u32>(src +  6)) >>  4  & MASK26
	const n3 = u64(load<u32>(src +  9)) >>  6  & MASK26
	const n4 = u64(load<u32>(src + 12)) >>  8  | hibit

	let h0 = load<u64>(POLY_H_OFFSET +  0)
	let h1 = load<u64>(POLY_H_OFFSET +  8)
	let h2 = load<u64>(POLY_H_OFFSET + 16)
	let h3 = load<u64>(POLY_H_OFFSET + 24)
	let h4 = load<u64>(POLY_H_OFFSET + 32)

	h0 += n0; h1 += n1; h2 += n2; h3 += n3; h4 += n4

	const r0 = load<u64>(POLY_R_OFFSET  +  0)
	const r1 = load<u64>(POLY_R_OFFSET  +  8)
	const r2 = load<u64>(POLY_R_OFFSET  + 16)
	const r3 = load<u64>(POLY_R_OFFSET  + 24)
	const r4 = load<u64>(POLY_R_OFFSET  + 32)
	const s1 = load<u64>(POLY_RS_OFFSET +  0)
	const s2 = load<u64>(POLY_RS_OFFSET +  8)
	const s3 = load<u64>(POLY_RS_OFFSET + 16)
	const s4 = load<u64>(POLY_RS_OFFSET + 24)

	let d0: u64 = h0*r0 + h4*s1 + h3*s2 + h2*s3 + h1*s4
	let d1: u64 = h1*r0 + h0*r1 + h4*s2 + h3*s3 + h2*s4
	let d2: u64 = h2*r0 + h1*r1 + h0*r2 + h4*s3 + h3*s4
	let d3: u64 = h3*r0 + h2*r1 + h1*r2 + h0*r3 + h4*s4
	let d4: u64 = h4*r0 + h3*r1 + h2*r2 + h1*r3 + h0*r4

	let c: u64
	c = d0 >> 26; h0 = d0 & MASK26; d1 += c
	c = d1 >> 26; h1 = d1 & MASK26; d2 += c
	c = d2 >> 26; h2 = d2 & MASK26; d3 += c
	c = d3 >> 26; h3 = d3 & MASK26; d4 += c
	c = d4 >> 26; h4 = d4 & MASK26; h0 += c * 5
	c = h0 >> 26; h0 &= MASK26;     h1 += c

	store<u64>(POLY_H_OFFSET +  0, h0)
	store<u64>(POLY_H_OFFSET +  8, h1)
	store<u64>(POLY_H_OFFSET + 16, h2)
	store<u64>(POLY_H_OFFSET + 24, h3)
	store<u64>(POLY_H_OFFSET + 32, h4)
}

// ── polyInit ──────────────────────────────────────────────────────────────────
export function polyInit(): void {
	const k = POLY_KEY_OFFSET

	// Clamp r (RFC §2.5)
	store<u8>(k +  3, load<u8>(k +  3) & 15)
	store<u8>(k +  7, load<u8>(k +  7) & 15)
	store<u8>(k + 11, load<u8>(k + 11) & 15)
	store<u8>(k + 15, load<u8>(k + 15) & 15)
	store<u8>(k +  4, load<u8>(k +  4) & 252)
	store<u8>(k +  8, load<u8>(k +  8) & 252)
	store<u8>(k + 12, load<u8>(k + 12) & 252)

	const r0 = u64(load<u32>(k +  0))        & MASK26
	const r1 = u64(load<u32>(k +  3)) >>  2  & MASK26
	const r2 = u64(load<u32>(k +  6)) >>  4  & MASK26
	const r3 = u64(load<u32>(k +  9)) >>  6  & MASK26
	const r4 = u64(load<u32>(k + 12)) >>  8

	store<u64>(POLY_R_OFFSET +  0, r0)
	store<u64>(POLY_R_OFFSET +  8, r1)
	store<u64>(POLY_R_OFFSET + 16, r2)
	store<u64>(POLY_R_OFFSET + 24, r3)
	store<u64>(POLY_R_OFFSET + 32, r4)

	store<u64>(POLY_RS_OFFSET +  0, 5 * r1)
	store<u64>(POLY_RS_OFFSET +  8, 5 * r2)
	store<u64>(POLY_RS_OFFSET + 16, 5 * r3)
	store<u64>(POLY_RS_OFFSET + 24, 5 * r4)

	store<u32>(POLY_S_OFFSET +  0, load<u32>(k + 16))
	store<u32>(POLY_S_OFFSET +  4, load<u32>(k + 20))
	store<u32>(POLY_S_OFFSET +  8, load<u32>(k + 24))
	store<u32>(POLY_S_OFFSET + 12, load<u32>(k + 28))

	store<u64>(POLY_H_OFFSET +  0, 0)
	store<u64>(POLY_H_OFFSET +  8, 0)
	store<u64>(POLY_H_OFFSET + 16, 0)
	store<u64>(POLY_H_OFFSET + 24, 0)
	store<u64>(POLY_H_OFFSET + 32, 0)
	memory.fill(POLY_BUF_OFFSET, 0, 16)
	store<u32>(POLY_BUF_LEN_OFFSET, 0)
}

// ── polyUpdate ────────────────────────────────────────────────────────────────
export function polyUpdate(len: i32): void {
	if (len <= 0) return

	let src = POLY_MSG_OFFSET
	let bufLen = i32(load<u32>(POLY_BUF_LEN_OFFSET))

	if (bufLen > 0) {
		const need = 16 - bufLen
		if (len < need) {
			memory.copy(POLY_BUF_OFFSET + bufLen, src, len)
			store<u32>(POLY_BUF_LEN_OFFSET, u32(bufLen + len))
			return
		}
		memory.copy(POLY_BUF_OFFSET + bufLen, src, need)
		absorbBlock(POLY_BUF_OFFSET, u64(1) << 24)
		store<u32>(POLY_BUF_LEN_OFFSET, 0)
		src += need
		len -= need
	}

	while (len >= 16) {
		absorbBlock(src, u64(1) << 24)
		src += 16
		len -= 16
	}

	if (len > 0) {
		memory.copy(POLY_BUF_OFFSET, src, len)
		store<u32>(POLY_BUF_LEN_OFFSET, u32(len))
	}
}

// ── polyFinal ─────────────────────────────────────────────────────────────────
export function polyFinal(): void {
	const bufLen = i32(load<u32>(POLY_BUF_LEN_OFFSET))

	if (bufLen > 0) {
		memory.fill(POLY_BUF_OFFSET + bufLen, 0, 16 - bufLen)
		store<u8>(POLY_BUF_OFFSET + bufLen, 1)
		absorbBlock(POLY_BUF_OFFSET, 0)
	}

	let h0 = load<u64>(POLY_H_OFFSET +  0)
	let h1 = load<u64>(POLY_H_OFFSET +  8)
	let h2 = load<u64>(POLY_H_OFFSET + 16)
	let h3 = load<u64>(POLY_H_OFFSET + 24)
	let h4 = load<u64>(POLY_H_OFFSET + 32)

	let c: u64
	c = h4 >> 26; h4 &= MASK26; h0 += c * 5
	c = h0 >> 26; h0 &= MASK26; h1 += c
	c = h1 >> 26; h1 &= MASK26; h2 += c
	c = h2 >> 26; h2 &= MASK26; h3 += c
	c = h3 >> 26; h3 &= MASK26; h4 += c

	let g0 = h0 + 5; c = g0 >> 26; g0 &= MASK26
	let g1 = h1 + c; c = g1 >> 26; g1 &= MASK26
	let g2 = h2 + c; c = g2 >> 26; g2 &= MASK26
	let g3 = h3 + c; c = g3 >> 26; g3 &= MASK26
	let g4 = h4 + c

	const mask: u64 = u64(0) - (g4 >> 26)
	h0 = (h0 & ~mask) | (g0 & mask)
	h1 = (h1 & ~mask) | (g1 & mask)
	h2 = (h2 & ~mask) | (g2 & mask)
	h3 = (h3 & ~mask) | (g3 & mask)
	h4 = (h4 & ~mask) | (g4 & mask & MASK26)

	const lo: u64 = h0 | (h1 << 26) | ((h2 & 0xfff) << 52)
	const hi: u64 = (h2 >> 12) | (h3 << 14) | (h4 << 40)

	const s0 = u64(load<u32>(POLY_S_OFFSET +  0))
	const s1 = u64(load<u32>(POLY_S_OFFSET +  4))
	const s2 = u64(load<u32>(POLY_S_OFFSET +  8))
	const s3 = u64(load<u32>(POLY_S_OFFSET + 12))
	const slo: u64 = s0 | (s1 << 32)
	const shi: u64 = s2 | (s3 << 32)

	const rlo: u64 = lo + slo
	const carry: u64 = u64(rlo < lo)
	const rhi: u64 = hi + shi + carry

	store<u64>(POLY_TAG_OFFSET + 0, rlo)
	store<u64>(POLY_TAG_OFFSET + 8, rhi)
}
