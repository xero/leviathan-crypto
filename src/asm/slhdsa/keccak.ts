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
// src/asm/slhdsa/keccak.ts
//
// FIPS 202 §3 Keccak-f[1600] permutation.
// Verbatim port from src/asm/sha3/keccak.ts; embedded here per the
// per-module-ownership design rather than cross-linked from sha3.wasm.
// The permutation is byte-identical to the sha3 source; only
// the offset symbols are remapped to the slhdsa buffer layout, and a
// pointer-argument absorb variant is added (`keccakAbsorbAt`) so the SHAKE
// wrappers in hashes.ts can absorb data from arbitrary memory regions without
// a staging copy.
//
// Standard: FIPS 202, "SHA-3 Standard", August 2015
// URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//
// State: 25 × u64 at KECCAK_STATE_OFFSET (200 bytes, 5×5 lane matrix)
// Indexing: A[x][y] stored at offset (x + 5y) × 8
// Endianness: little-endian lanes (WASM native, no byte-swap needed)

import {
	KECCAK_STATE_OFFSET    as STATE_OFFSET,
	KECCAK_RATE_OFFSET     as RATE_OFFSET,
	KECCAK_ABSORBED_OFFSET as ABSORBED_OFFSET,
	KECCAK_DSBYTE_OFFSET   as DSBYTE_OFFSET,
	KECCAK_INPUT_OFFSET    as INPUT_OFFSET,
	KECCAK_OUT_OFFSET      as OUT_OFFSET,
} from './buffers';

// Round constants (ι step), FIPS 202 §3.2.5
const RC0:  i64 = 0x0000000000000001;
const RC1:  i64 = 0x0000000000008082;
const RC2:  i64 = 0x800000000000808a;
const RC3:  i64 = 0x8000000080008000;
const RC4:  i64 = 0x000000000000808b;
const RC5:  i64 = 0x0000000080000001;
const RC6:  i64 = 0x8000000080008081;
const RC7:  i64 = 0x8000000000008009;
const RC8:  i64 = 0x000000000000008a;
const RC9:  i64 = 0x0000000000000088;
const RC10: i64 = 0x0000000080008009;
const RC11: i64 = 0x000000008000000a;
const RC12: i64 = 0x000000008000808b;
const RC13: i64 = 0x800000000000008b;
const RC14: i64 = 0x8000000000008089;
const RC15: i64 = 0x8000000000008003;
const RC16: i64 = 0x8000000000008002;
const RC17: i64 = 0x8000000000000080;
const RC18: i64 = 0x000000000000800a;
const RC19: i64 = 0x800000008000000a;
const RC20: i64 = 0x8000000080008081;
const RC21: i64 = 0x8000000000008080;
const RC22: i64 = 0x0000000080000001;
const RC23: i64 = 0x8000000080008008;

@inline
function rot64(v: i64, n: i32): i64 {
	return (v << n) | (v >>> (64 - n));
}

// Keccak-f[1600]: 24 rounds of (θ, ρ, π, χ, ι) in-place
function keccakF(): void {
	let s = STATE_OFFSET;

	let a00 = load<i64>(s +   0);
	let a10 = load<i64>(s +   8);
	let a20 = load<i64>(s +  16);
	let a30 = load<i64>(s +  24);
	let a40 = load<i64>(s +  32);
	let a01 = load<i64>(s +  40);
	let a11 = load<i64>(s +  48);
	let a21 = load<i64>(s +  56);
	let a31 = load<i64>(s +  64);
	let a41 = load<i64>(s +  72);
	let a02 = load<i64>(s +  80);
	let a12 = load<i64>(s +  88);
	let a22 = load<i64>(s +  96);
	let a32 = load<i64>(s + 104);
	let a42 = load<i64>(s + 112);
	let a03 = load<i64>(s + 120);
	let a13 = load<i64>(s + 128);
	let a23 = load<i64>(s + 136);
	let a33 = load<i64>(s + 144);
	let a43 = load<i64>(s + 152);
	let a04 = load<i64>(s + 160);
	let a14 = load<i64>(s + 168);
	let a24 = load<i64>(s + 176);
	let a34 = load<i64>(s + 184);
	let a44 = load<i64>(s + 192);

	for (let round = 0; round < 24; round++) {
		// θ (theta), FIPS 202 §3.2.1
		let c0 = a00 ^ a01 ^ a02 ^ a03 ^ a04;
		let c1 = a10 ^ a11 ^ a12 ^ a13 ^ a14;
		let c2 = a20 ^ a21 ^ a22 ^ a23 ^ a24;
		let c3 = a30 ^ a31 ^ a32 ^ a33 ^ a34;
		let c4 = a40 ^ a41 ^ a42 ^ a43 ^ a44;

		let d0 = c4 ^ rot64(c1, 1);
		let d1 = c0 ^ rot64(c2, 1);
		let d2 = c1 ^ rot64(c3, 1);
		let d3 = c2 ^ rot64(c4, 1);
		let d4 = c3 ^ rot64(c0, 1);

		a00 ^= d0; a10 ^= d1; a20 ^= d2; a30 ^= d3; a40 ^= d4;
		a01 ^= d0; a11 ^= d1; a21 ^= d2; a31 ^= d3; a41 ^= d4;
		a02 ^= d0; a12 ^= d1; a22 ^= d2; a32 ^= d3; a42 ^= d4;
		a03 ^= d0; a13 ^= d1; a23 ^= d2; a33 ^= d3; a43 ^= d4;
		a04 ^= d0; a14 ^= d1; a24 ^= d2; a34 ^= d3; a44 ^= d4;

		// ρ + π combined, FIPS 202 §3.2.2, §3.2.3
		let b00 = rot64(a00,  0);
		let b01 = rot64(a30, 28);
		let b02 = rot64(a10,  1);
		let b03 = rot64(a40, 27);
		let b04 = rot64(a20, 62);

		let b10 = rot64(a11, 44);
		let b11 = rot64(a41, 20);
		let b12 = rot64(a21,  6);
		let b13 = rot64(a01, 36);
		let b14 = rot64(a31, 55);

		let b20 = rot64(a22, 43);
		let b21 = rot64(a02,  3);
		let b22 = rot64(a32, 25);
		let b23 = rot64(a12, 10);
		let b24 = rot64(a42, 39);

		let b30 = rot64(a33, 21);
		let b31 = rot64(a13, 45);
		let b32 = rot64(a43,  8);
		let b33 = rot64(a23, 15);
		let b34 = rot64(a03, 41);

		let b40 = rot64(a44, 14);
		let b41 = rot64(a24, 61);
		let b42 = rot64(a04, 18);
		let b43 = rot64(a34, 56);
		let b44 = rot64(a14,  2);

		// χ (chi), FIPS 202 §3.2.4
		a00 = b00 ^ (~b10 & b20);
		a10 = b10 ^ (~b20 & b30);
		a20 = b20 ^ (~b30 & b40);
		a30 = b30 ^ (~b40 & b00);
		a40 = b40 ^ (~b00 & b10);

		a01 = b01 ^ (~b11 & b21);
		a11 = b11 ^ (~b21 & b31);
		a21 = b21 ^ (~b31 & b41);
		a31 = b31 ^ (~b41 & b01);
		a41 = b41 ^ (~b01 & b11);

		a02 = b02 ^ (~b12 & b22);
		a12 = b12 ^ (~b22 & b32);
		a22 = b22 ^ (~b32 & b42);
		a32 = b32 ^ (~b42 & b02);
		a42 = b42 ^ (~b02 & b12);

		a03 = b03 ^ (~b13 & b23);
		a13 = b13 ^ (~b23 & b33);
		a23 = b23 ^ (~b33 & b43);
		a33 = b33 ^ (~b43 & b03);
		a43 = b43 ^ (~b03 & b13);

		a04 = b04 ^ (~b14 & b24);
		a14 = b14 ^ (~b24 & b34);
		a24 = b24 ^ (~b34 & b44);
		a34 = b34 ^ (~b44 & b04);
		a44 = b44 ^ (~b04 & b14);

		// ι (iota), FIPS 202 §3.2.5
		if (round === 0)       { a00 ^= RC0  }
		else if (round === 1)  { a00 ^= RC1  }
		else if (round === 2)  { a00 ^= RC2  }
		else if (round === 3)  { a00 ^= RC3  }
		else if (round === 4)  { a00 ^= RC4  }
		else if (round === 5)  { a00 ^= RC5  }
		else if (round === 6)  { a00 ^= RC6  }
		else if (round === 7)  { a00 ^= RC7  }
		else if (round === 8)  { a00 ^= RC8  }
		else if (round === 9)  { a00 ^= RC9  }
		else if (round === 10) { a00 ^= RC10 }
		else if (round === 11) { a00 ^= RC11 }
		else if (round === 12) { a00 ^= RC12 }
		else if (round === 13) { a00 ^= RC13 }
		else if (round === 14) { a00 ^= RC14 }
		else if (round === 15) { a00 ^= RC15 }
		else if (round === 16) { a00 ^= RC16 }
		else if (round === 17) { a00 ^= RC17 }
		else if (round === 18) { a00 ^= RC18 }
		else if (round === 19) { a00 ^= RC19 }
		else if (round === 20) { a00 ^= RC20 }
		else if (round === 21) { a00 ^= RC21 }
		else if (round === 22) { a00 ^= RC22 }
		else                   { a00 ^= RC23 }
	}

	store<i64>(s +   0, a00);
	store<i64>(s +   8, a10);
	store<i64>(s +  16, a20);
	store<i64>(s +  24, a30);
	store<i64>(s +  32, a40);
	store<i64>(s +  40, a01);
	store<i64>(s +  48, a11);
	store<i64>(s +  56, a21);
	store<i64>(s +  64, a31);
	store<i64>(s +  72, a41);
	store<i64>(s +  80, a02);
	store<i64>(s +  88, a12);
	store<i64>(s +  96, a22);
	store<i64>(s + 104, a32);
	store<i64>(s + 112, a42);
	store<i64>(s + 120, a03);
	store<i64>(s + 128, a13);
	store<i64>(s + 136, a23);
	store<i64>(s + 144, a33);
	store<i64>(s + 152, a43);
	store<i64>(s + 160, a04);
	store<i64>(s + 168, a14);
	store<i64>(s + 176, a24);
	store<i64>(s + 184, a34);
	store<i64>(s + 192, a44);
}

// Initialize state for a new hash
function keccakInit(rate: i32, dsByte: u8): void {
	memory.fill(STATE_OFFSET, 0, 200);
	memory.fill(INPUT_OFFSET, 0, 168);
	store<i32>(RATE_OFFSET,     rate);
	store<i32>(ABSORBED_OFFSET, 0);
	store<u8> (DSBYTE_OFFSET,   dsByte);
}

// Variant-specific init, FIPS 202 §B.2
// Domain sep: SHAKE* = 0x1f. SLH-DSA only consumes SHAKE128/SHAKE256
// (FIPS 205 §11.2 SHAKE family); fixed-output SHA3-* variants are out of
// scope for this module.
export function shake128Init(): void { keccakInit(168, 0x1f); }
export function shake256Init(): void { keccakInit(136, 0x1f); }

// Absorb len bytes from KECCAK_INPUT_OFFSET into the sponge
export function keccakAbsorb(len: i32): void {
	let rate     = load<i32>(RATE_OFFSET);
	let absorbed = load<i32>(ABSORBED_OFFSET);
	let inputPtr = INPUT_OFFSET;

	let offset: i32 = 0;
	while (offset < len) {
		let canTake = rate - absorbed;
		let taking  = len - offset < canTake ? len - offset : canTake;

		for (let i = 0; i < taking; i++) {
			let byte = load<u8>(inputPtr + offset + i);
			let stateByteAddr = STATE_OFFSET + absorbed + i;
			store<u8>(stateByteAddr, load<u8>(stateByteAddr) ^ byte);
		}
		absorbed += taking;
		offset   += taking;

		if (absorbed === rate) {
			keccakF();
			absorbed = 0;
		}
	}

	store<i32>(ABSORBED_OFFSET, absorbed);
}

// Pointer-argument absorb. Behaves like `keccakAbsorb` but reads from `srcPtr`
// rather than KECCAK_INPUT_OFFSET. Slhdsa's FIPS 205 §11.2 hash family chains
// PK.seed || ADRS || M from three distinct memory regions per call, so a
// pointer-arg form avoids unnecessary staging copies.
export function keccakAbsorbAt(srcPtr: i32, len: i32): void {
	let rate     = load<i32>(RATE_OFFSET);
	let absorbed = load<i32>(ABSORBED_OFFSET);

	let offset: i32 = 0;
	while (offset < len) {
		let canTake = rate - absorbed;
		let taking  = len - offset < canTake ? len - offset : canTake;

		for (let i = 0; i < taking; i++) {
			let byte = load<u8>(srcPtr + offset + i);
			let stateByteAddr = STATE_OFFSET + absorbed + i;
			store<u8>(stateByteAddr, load<u8>(stateByteAddr) ^ byte);
		}
		absorbed += taking;
		offset   += taking;

		if (absorbed === rate) {
			keccakF();
			absorbed = 0;
		}
	}

	store<i32>(ABSORBED_OFFSET, absorbed);
}

// Apply sponge padding and run first permutation; FIPS 202 §4 squeeze step.
// Pad10*1 with SHAKE's 0x1f domain-separation byte; matches the sha3 source.
function shakePad(): void {
	const rate     = load<i32>(RATE_OFFSET);
	const absorbed = load<i32>(ABSORBED_OFFSET);
	const dsByte   = load<u8> (DSBYTE_OFFSET);

	const dsAddr = STATE_OFFSET + absorbed;
	store<u8>(dsAddr, load<u8>(dsAddr) ^ dsByte);

	const lastAddr = STATE_OFFSET + rate - 1;
	store<u8>(lastAddr, load<u8>(lastAddr) ^ 0x80);

	keccakF();
}

// Squeeze `outLen` bytes to `dstPtr`. Handles outLen ≥ rate by issuing
// follow-up Keccak-f permutations between rate-sized chunks.
export function keccakSqueezeTo(dstPtr: i32, outLen: i32): void {
	shakePad();
	const rate = load<i32>(RATE_OFFSET);

	let written: i32 = 0;
	while (written < outLen) {
		const want   = outLen - written;
		const taking = want < rate ? want : rate;
		for (let i = 0; i < taking; i++) {
			store<u8>(dstPtr + written + i, load<u8>(STATE_OFFSET + i));
		}
		written += taking;
		if (written < outLen) keccakF();
	}
}

// Fixed-output squeeze to KECCAK_OUT_OFFSET. Useful for the substrate gate
// test which reads from a known location.
export function shakeFinal(outLen: i32): void {
	keccakSqueezeTo(OUT_OFFSET, outLen);
}
