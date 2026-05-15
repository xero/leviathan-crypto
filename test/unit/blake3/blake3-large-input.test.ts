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
/**
 * BLAKE3 large-input cross-check against the BLAKE3-team Rust oracle.
 *
 * Picks three input sizes outside the upstream 35-record KAT corpus
 * and asserts the WASM hash output (hash / keyed_hash / derive_key,
 * 131-byte XOF) is byte-identical to the value computed by Rust's
 * `blake3 = "=1.8.5"` crate. The expected values are pre-computed via
 * `scripts/verify-vectors/src/bin/gen_blake3_large.rs`
 * (`cargo run --bin gen-blake3-large`) and embedded verbatim below;
 * the input bytes are the same `i mod 251` pattern the upstream KAT
 * uses, so the test is reproducible without any extra fixtures.
 *
 * Sizes (all within the v3 BLAKE3 module's INPUT_SCRATCH_MAX of 103424
 * bytes; 256 KiB and larger are blocked by the buffered-streaming
 * design and are tracked separately in the test-suite docs):
 *   8000   - between KAT 7169 and 8192 (cross-boundary novel size)
 *   65536  - in the gap between KAT 31744 and 102400
 *   100000 - just past KAT 31744, well into the multi-level tree
 *
 * Audit posture: VERIFIED, oracle is BLAKE3-team's official Rust crate
 * (independent-lineage from the WASM port).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	BLAKE3, BLAKE3KeyedHash, BLAKE3DeriveKey,
	blake3Init,
} from '../../../src/ts/blake3/index.js';
import { blake3Wasm } from '../../../src/ts/blake3/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { blake3Key, blake3ContextString } from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);
const XOF_LEN   = 131;

function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function makeInput(len: number): Uint8Array {
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) out[i] = i % 251;
	return out;
}

// Embedded oracle output. Generator: `cargo run --release --bin
// gen-blake3-large --manifest-path scripts/verify-vectors/Cargo.toml`.
// Source: BLAKE3-team's `blake3` Rust crate, version pinned in
// scripts/verify-vectors/Cargo.toml.
const LARGE_VECTORS = [
	{
		inputLen: 8000,
		hashHex: 'dbf46aaa08b263e06d4c5ce91c646b3199cafe6c5243bcc9cc11cd41b32b6cb0472beba5dd2d1682ad154e649604ceb7665300cdf218edc6288d3d8a66552c4944a4f55ec574aaacfb2f6b67fc06cbc8b2fd88b3cb1c5b01432b48255ed42cd7b9bc41f030c56686aebe7dd5850c5d4190220ce64004f58bc4c11db412a62436e7db2c',
		keyedHashHex: '445a1d24750d30c83395821e4d8cf3e1bc0d1e1a220cb83db97086cff19d77379afe38d9618450015fa965fd059f76cd6fbae458b35be75190f1b678e833f4ad77afa359325d427eb51efb68569ec04a9cb5131713d544383ae995939973c65e06797b33f3eb3a9b2cb611fadf06756b90f152c14b521d43efebcf4855c8c3cd6ec649',
		deriveKeyHex: '5686f4743ef39cb42ba82e003213043957c9cb991c36bff7aadac85daa4623414410b5c156acf27027dee5460744bc0f51eac2418274849c0e21840c5287255cea812d581f69ae5ea2bd2a7c54982b81018a7dfe21c5a91e52d6427adbea066f778c6326076806e988ee4fb94c6859ddae81da9dc84ac919f1bca4207d68046197ceb0',
	},
	{
		inputLen: 65536,
		hashHex: '68d647e619a930e7b1082f74f334b0c65a315725569bdc123f0ee11881717bfe8fac26c37377907a14c02ebeb2c99745c2e6c5602092e0efa50e31245104cad4290d110b7456dcb3cdccd0ae2f62e1c041264cbe2e6275a62881964a2d223ad57513a27e47745e64dd1a0f7e2510eaab2138cc875889ffd67979dfa6e2b8137edeee9c',
		keyedHashHex: '160fb7538a11d83b9b311825a6baef08484d6aabb8276900a1fb08648085cca232af91f00a4719fcfee45e6a2105956b4d04cba1f6373e27cb6929b7aab967a04810dad78d9685e4f12ecc4a5e4a911722951faea1bbac42e9680daf7f0f5519ce209e91aee3e51e97d00a72bdb0a90e609ac28fe2766a940e66a720f922cb9e6861fd',
		deriveKeyHex: '18a76cadb7e87ef4ed8faa11a9f79a0561dfc2b49e00d2c654405f479bcf34c8ecd8c9538ee32a25d6c243846a9d9beff6115b3ab3386022902ededac014461ce5cdcc5fc816daa8498e726b26ada54268879905fbd28d01ae09a62f738daffa49a72ab25fb495a15ff62652dee6195a222e5de2568c77275560ab066914e0820f9ef1',
	},
	{
		inputLen: 100000,
		hashHex: 'd93c23eedaf165a7e0be908ba86f1a7a520d568d2d13cde787c8580c5c72cc54902b765d0e69ff7f278ef2f8bb839b673f0db20afa0566c78965ad819674822fd11a507251555fc6daec7437074bc7b7307dfe122411b3676a932b5b0360d5ad495f8e7431d3d025fac5b4e955ce893a3504f2569f838eea47cf1bb21c4ae659db522f',
		keyedHashHex: '74c836d008247adebbc032d1bced2e71d19050b5c39fa03c43d4160ad8d170732f3b73e374a4500825c13d2c8c9384ce12c033adc49245ce42f50d5b48237397b8447bd414b0693bef98518db8a3494e6e8e3abc931f92f472d938f07eac97d1cc69b375426bce26c5e829b5b41cacbb5543544977749d503fa78309e7a158640e579c',
		deriveKeyHex: '039c0c0d76eacefea9c8d042698bd012d3cef4091ed5c5a7e32a30e4d51718930a99481bb11214d9e9e79e58d11875a789447731a887aa77499843148d35b1752c6314af6d36559341bd6895c5ee0a452c99cb47a9b22dfe36042932fc9a423d245b91b6246c85e4b0d415cbece3e0545d6e242853da7f3dd1f9b0f146ec72706b8c28',
	},
] as const;

beforeAll(async () => {
	_resetForTesting();
	await blake3Init(blake3Wasm);
});

describe('BLAKE3 large-input cross-check vs Rust oracle', () => {
	for (const v of LARGE_VECTORS) {
		it(`hash, full 131-byte XOF, inputLen = ${v.inputLen}`, () => {
			const input = makeInput(v.inputLen);
			const h     = new BLAKE3();
			let out: Uint8Array;
			try        {
				out = h.hash(input, XOF_LEN);
			} finally    {
				h.dispose();
			}
			expect(toHex(out)).toBe(v.hashHex);
		});

		it(`keyed_hash, full 131-byte XOF, inputLen = ${v.inputLen}`, () => {
			const input = makeInput(v.inputLen);
			const h     = new BLAKE3KeyedHash();
			let out: Uint8Array;
			try        {
				out = h.hash(KEY_BYTES, input, XOF_LEN);
			} finally    {
				h.dispose();
			}
			expect(toHex(out)).toBe(v.keyedHashHex);
		});

		it(`derive_key, full 131-byte XOF, inputLen = ${v.inputLen}`, () => {
			const input = makeInput(v.inputLen);
			const dk    = new BLAKE3DeriveKey();
			let out: Uint8Array;
			try        {
				out = dk.derive(blake3ContextString, input, XOF_LEN);
			} finally    {
				dk.dispose();
			}
			expect(toHex(out)).toBe(v.deriveKeyHex);
		});
	}
});
