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
// constant-time byte equality, AS-internal shared helper
//
// Scalar XOR-accumulate, branch-free 0/1 reduction. Imported by other
// AS modules and inlined into each importer's compile unit; never
// emitted as a WASM export because the `export` is source-level only
// (the symbol is not re-exported from any module's entry file).
//
// Scalar (not SIMD) so the helper compiles cleanly into binaries that
// do not enable the SIMD feature (slhdsa, curve25519, p256). Sibling
// `index.ts` keeps the SIMD `compare()` path for cte.wasm's
// JS-boundary callers, where buffer sizes are larger.
//
// Returns 1 if equal, 0 if not. Caller writes both arrays into the
// importing module's linear memory before calling.

@inline
export function ctEqual(aOff: i32, bOff: i32, len: i32): i32 {
	let diff: i32 = 0;
	for (let i: i32 = 0; i < len; i++) {
		diff |= (<i32>load<u8>(aOff + i)) ^ (<i32>load<u8>(bOff + i));
	}
	// Branch-free "diff == 0 → 1, else 0":
	//   (diff | -diff) has its sign bit set iff diff != 0; arithmetic
	//   shift propagates it to all 32 bits. Invert and mask to low bit.
	//   Avoids relying on the engine's i32.eqz being uniform-timed.
	return ~((diff | -diff) >> 31) & 1;
}
