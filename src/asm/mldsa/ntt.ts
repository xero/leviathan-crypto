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
// src/asm/mldsa/ntt.ts
//
// ML-DSA — Number-Theoretic Transform (NTT) and inverse NTT.
// FIPS 204 Algorithms 41 (NTT), 42 (NTT⁻¹), 43 (BitRev₈).
//
// Algorithm 41 is Cooley-Tukey forward; Algorithm 42 is Gentleman-Sande
// inverse with a closing scalar multiply by 256⁻¹ mod q. The zetas table
// holds ζ^BitRev₈(k) mod q for k ∈ 1..255 (FIPS 204 §7.5 / Appendix B),
// stored in Montgomery form (× 2³² mod q, centered) so each butterfly
// uses a single MontgomeryReduce instead of a generic mod q.

import { F_MONT } from './params';
import { fqmul, barrett_reduce } from './reduce';

// ── Zetas table ─────────────────────────────────────────────────────────────
// 256 i32 entries. zetas[k] = ζ^BitRev₈(k) · 2³² mod q, centered to (-q/2, q/2].
//
// Source: FIPS 204 Appendix B regular-form table, converted offline to
// Montgomery form. Two key sanity checks (verified at table-generation time):
//   - ζ = 1753 (FIPS 204 §2.5):  zetas[128] = 1753 · 2³² mod q  (BitRev₈(128)=1)
//   - ζ¹²⁸ matches Appendix B's first non-zero entry: zetas[1] in regular form
//     equals 1753¹²⁸ mod q = 4808194 (FIPS 204 Appendix B row 1 col 2).
//
// The Montgomery form is verified at runtime by the NTT round-trip gate test
// (test/unit/mldsa/ntt_simd_gate.test.ts) — invntt(ntt(p)) == p coefficient-wise.
const zetas: StaticArray<i32> = [
	        0,     25847,  -2608894,   -518909,    237124,   -777960,   -876248,    466468,
	  1826347,   2353451,   -359251,  -2091905,   3119733,  -2884855,   3111497,   2680103,
	  2725464,   1024112,  -1079900,   3585928,   -549488,  -1119584,   2619752,  -2108549,
	 -2118186,  -3859737,  -1399561,  -3277672,   1757237,    -19422,   4010497,    280005,
	  2706023,     95776,   3077325,   3530437,  -1661693,  -3592148,  -2537516,   3915439,
	 -3861115,  -3043716,   3574422,  -2867647,   3539968,   -300467,   2348700,   -539299,
	 -1699267,  -1643818,   3505694,  -3821735,   3507263,  -2140649,  -1600420,   3699596,
	   811944,    531354,    954230,   3881043,   3900724,  -2556880,   2071892,  -2797779,
	 -3930395,  -1528703,  -3677745,  -3041255,  -1452451,   3475950,   2176455,  -1585221,
	 -1257611,   1939314,  -4083598,  -1000202,  -3190144,  -3157330,  -3632928,    126922,
	  3412210,   -983419,   2147896,   2715295,  -2967645,  -3693493,   -411027,  -2477047,
	  -671102,  -1228525,    -22981,  -1308169,   -381987,   1349076,   1852771,  -1430430,
	 -3343383,    264944,    508951,   3097992,     44288,  -1100098,    904516,   3958618,
	 -3724342,     -8578,   1653064,  -3249728,   2389356,   -210977,    759969,  -1316856,
	   189548,  -3553272,   3159746,  -1851402,  -2409325,   -177440,   1315589,   1341330,
	  1285669,  -1584928,   -812732,  -1439742,  -3019102,  -3881060,  -3628969,   3839961,
	  2091667,   3407706,   2316500,   3817976,  -3342478,   2244091,  -2446433,  -3562462,
	   266997,   2434439,  -1235728,   3513181,  -3520352,  -3759364,  -1197226,  -3193378,
	   900702,   1859098,    909542,    819034,    495491,  -1613174,    -43260,   -522500,
	  -655327,  -3122442,   2031748,   3207046,  -3556995,   -525098,   -768622,  -3595838,
	   342297,    286988,  -2437823,   4108315,   3437287,  -3342277,   1735879,    203044,
	  2842341,   2691481,  -2590150,   1265009,   4055324,   1247620,   2486353,   1595974,
	 -3767016,   1250494,   2635921,  -3548272,  -2994039,   1869119,   1903435,  -1050970,
	 -1333058,   1237275,  -3318210,  -1430225,   -451100,   1312455,   3306115,  -1962642,
	 -1279661,   1917081,  -2546312,  -1374803,   1500165,    777191,   2235880,   3406031,
	  -542412,  -2831860,  -1671176,  -1846953,  -2584293,  -3724270,    594136,  -3776993,
	 -2013608,   2432395,   2454455,   -164721,   1957272,   3369112,    185531,  -1207385,
	 -3183426,    162844,   1616392,   3014001,    810149,   1652634,  -3694233,  -1799107,
	 -3038916,   3523897,   3866901,    269760,   2213111,   -975884,   1717735,    472078,
	  -426683,   1723600,  -1803090,   1910376,  -1667432,  -1104333,   -260646,  -3833893,
	 -2939036,  -2235985,   -420899,  -2286327,    183443,   -976891,   1612842,  -3545687,
	  -554416,   3919660,    -48306,  -1362209,   3937738,   1400424,   -846154,   1976782,
];

/**
 * Returns the byte offset of zetas[0] in WASM linear memory.
 * Used by ntt_simd.ts and by tests for direct introspection.
 */
export function getZetasOffset(): i32 {
	return changetype<i32>(zetas);
}

/**
 * Returns zetas[i] (Montgomery form) for tests / cross-checks.
 */
export function getZeta(i: i32): i32 {
	return unchecked(zetas[i]);
}

// ── BitRev₈ ─────────────────────────────────────────────────────────────────
//
// FIPS 204 Algorithm 43: bit-reverse the 8-bit binary expansion of m ∈ [0, 255].
// Exported for test introspection.
export function BitRev8(m: i32): i32 {
	let r: i32 = 0;
	for (let i: i32 = 0; i < 8; i++) {
		r |= ((m >> i) & 1) << (7 - i);
	}
	return r;
}

// ── NTT (forward) — FIPS 204 Algorithm 41 ───────────────────────────────────
//
// In-place Cooley-Tukey forward NTT.
// Input  (in WASM memory at polyOffset): w ∈ R_q in standard order (256 × i32).
// Output (in place):                     ŵ ∈ T_q with elements in regular form.
//
// Each butterfly multiplies by zetas[m] (Montgomery form) via fqmul, which
// internally applies MontgomeryReduce to cancel the 2³² factor — the
// coefficient stream therefore stays in regular (non-Montgomery) form
// throughout. The output of fqmul has magnitude < 2q (FIPS 204 Appendix A);
// the cumulative add/sub stages keep coefficients well within i32 range
// across all 8 layers.
export function ntt(polyOffset: i32): void {
	let m: i32 = 0;
	let len: i32 = 128;
	while (len >= 1) {
		let start: i32 = 0;
		while (start < 256) {
			m++;
			const z: i32 = unchecked(zetas[m]);
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const t: i32 = fqmul(z, load<i32>(polyOffset + (j + len) * 4));
				const wj: i32 = load<i32>(polyOffset + j * 4);
				store<i32>(polyOffset + (j + len) * 4, wj - t);
				store<i32>(polyOffset + j * 4,         wj + t);
			}
			start = end + len;
		}
		len >>= 1;
	}
}

// ── NTT⁻¹ (inverse) — FIPS 204 Algorithm 42 ─────────────────────────────────
//
// In-place Gentleman-Sande inverse NTT, followed by the canonical
// 256⁻¹ multiplication (Algorithm 42 lines 21–24, with f = 8347681).
//
// f is stored pre-multiplied by 2³² (params.ts F_MONT) so that the closing
// fqmul applies the scalar in regular form, consistent with the rest of the
// transform. Coefficients are Barrett-reduced to centered residues on the
// "sum" leg of each butterfly to bound their growth across layers.
export function invntt(polyOffset: i32): void {
	let m: i32 = 256;
	let len: i32 = 1;
	while (len < 256) {
		let start: i32 = 0;
		while (start < 256) {
			m--;
			const z: i32 = -unchecked(zetas[m]);
			const end: i32 = start + len;
			for (let j: i32 = start; j < end; j++) {
				const wj:  i32 = load<i32>(polyOffset + j * 4);
				const wjl: i32 = load<i32>(polyOffset + (j + len) * 4);
				store<i32>(polyOffset + j * 4,         barrett_reduce(wj + wjl));
				store<i32>(polyOffset + (j + len) * 4, fqmul(z, wj - wjl));
			}
			start = end + len;
		}
		len <<= 1;
	}
	// Final scale: w[j] ← (256⁻¹ · w[j]) mod q for j ∈ [0, 256).
	for (let j: i32 = 0; j < 256; j++) {
		store<i32>(polyOffset + j * 4, fqmul(F_MONT, load<i32>(polyOffset + j * 4)));
	}
}

