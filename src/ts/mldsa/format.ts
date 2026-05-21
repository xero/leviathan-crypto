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
// src/ts/mldsa/format.ts
//
// External-API M' construction. Lives in its own file because HashML-DSA
// reuses the same byte layout with a different domain separator (0x01)
// and a hash-of-message tail.
//
// FIPS 204 Algorithm 2 line 10 (Sign) and Algorithm 3 line 5 (Verify):
//   M' ← BytesToBits(IntegerToBytes(domSep, 1)
//                    ‖ IntegerToBytes(|ctx|, 1)
//                    ‖ ctx
//                    ‖ <message-bytes>)
//
// In a byte-oriented SHAKE wrapper, BytesToBits is a no-op, the absorbed
// bytes are the same. So we hand the absorber a contiguous Uint8Array
// laid out exactly as the spec describes, plus the domain-separator byte
// up front.

/**
 * Build M' = domSep ‖ |ctx| ‖ ctx ‖ M.
 *
 * domSep = 0x00 for pure ML-DSA, 0x01 for HashML-DSA.
 * Caller has already validated ctx.length ≤ 255.
 */
export function constructMPrime(domSep: number, ctx: Uint8Array, M: Uint8Array): Uint8Array {
	const out = new Uint8Array(2 + ctx.length + M.length);
	out[0] = domSep & 0xFF;
	out[1] = ctx.length & 0xFF;
	out.set(ctx, 2);
	out.set(M, 2 + ctx.length);
	return out;
}

/**
 * Build the HashML-DSA M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH_M.
 *
 * FIPS 204 §5.4 / Algorithm 4 line 23 (sign) and Algorithm 5 line 18 (verify).
 * The leading byte is 0x01 (vs 0x00 for pure ML-DSA), domain separation
 * across pure / pre-hash modes per FIPS 204 §3.6.4. Caller has already
 * validated ctx.length ≤ 255.
 */
export function constructMPrimeHash(
	ctx:  Uint8Array,
	oid:  Uint8Array,
	PH_M: Uint8Array,
): Uint8Array {
	const out = new Uint8Array(2 + ctx.length + oid.length + PH_M.length);
	out[0] = 0x01;
	out[1] = ctx.length & 0xFF;
	out.set(ctx,  2);
	out.set(oid,  2 + ctx.length);
	out.set(PH_M, 2 + ctx.length + oid.length);
	return out;
}
