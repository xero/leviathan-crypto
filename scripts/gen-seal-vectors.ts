#!/usr/bin/env node
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
 * Generate Seal KAT vectors for both cipher families.
 *
 * Uses Seal._fromNonce for deterministic output, then independently verifies
 * each blob against raw primitives. Verified vectors are pinned as hex KATs.
 *
 * usage:
 *   bun run scripts/gen-seal-vectors.ts                    # default --cipher all
 *   bun run scripts/gen-seal-vectors.ts --cipher xchacha   # writes seal_xchacha_v3.ts only
 *   bun run scripts/gen-seal-vectors.ts --cipher serpent   # writes seal_serpent_v3.ts only
 */
import {
	init, SerpentCbc, HMAC_SHA256, HKDF_SHA256,
	bytesToHex,
} from '../src/ts/index.js';
import { serpentWasm } from '../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../src/ts/sha2/embedded.js';
import { Seal, OpenStream, HEADER_SIZE } from '../src/ts/stream/index.js';
import { SerpentCipher } from '../src/ts/serpent/cipher-suite.js';
import { XChaCha20Cipher } from '../src/ts/chacha20/cipher-suite.js';
import { readHeader, makeCounterNonce } from '../src/ts/stream/header.js';
import { TAG_FINAL } from '../src/ts/stream/constants.js';
import { aeadEncrypt, deriveSubkey } from '../src/ts/chacha20/ops.js';
import { getInstance } from '../src/ts/init.js';
import type { ChaChaExports } from '../src/ts/chacha20/types.js';
import { writeFileSync } from 'fs';

const args = process.argv.slice(2);
const cipherFlag = args.indexOf('--cipher');
const cipher = cipherFlag >= 0 ? args[cipherFlag + 1] : 'all';
if (!['xchacha', 'serpent', 'all'].includes(cipher))
	throw new Error(`unknown --cipher: ${cipher} (expected: xchacha, serpent, all)`);

await init({ serpent: serpentWasm, sha2: sha2Wasm, chacha20: chacha20Wasm });

function hex(b: Uint8Array): string { return bytesToHex(b); }
function assert(cond: boolean, msg: string) {
	if (!cond) { console.error('ASSERTION FAILED:', msg); process.exit(1); }
}
function splitHex(h: string, indent = '\t\t'): string {
	const lines: string[] = [];
	for (let i = 0; i < h.length; i += 64) lines.push(`'${h.slice(i, i + 64)}'`);
	return lines.join(' +\n' + indent);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const hkdf = new HKDF_SHA256();
const hmac = new HMAC_SHA256();
// SerpentCbc holds the 'serpent' WASM module exclusively. We construct it
// lazily for verification only after all SerpentCipher seal calls complete.
const x    = getInstance('chacha20').exports as unknown as ChaChaExports;

const xcInfo = new TextEncoder().encode('xchacha20-sealstream-v3');
const scInfo = new TextEncoder().encode('serpent-sealstream-v3');

function concat(...arrays: Uint8Array[]): Uint8Array {
	let len = 0;
	for (const a of arrays) len += a.length;
	const out = new Uint8Array(len);
	let off = 0;
	for (const a of arrays) { out.set(a, off); off += a.length; }
	return out;
}

function u32be(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, false);
	return b;
}

const asciiHeader = `//                  ▄▄▄▄▄▄▄▄▄▄
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
//`;

// ═══════════════════════════════════════════════════════════════════════════════
// XChaCha20 path — v3 wire format (commitment + header-bound HKDF)
// ═══════════════════════════════════════════════════════════════════════════════

function buildXChacha(): string {
	// XC1: 100-byte plaintext
	const xc1_key   = new Uint8Array(32); xc1_key.fill(0x01);
	const xc1_nonce = new Uint8Array(16); xc1_nonce.fill(0xaa);
	const xc1_pt    = new Uint8Array(100); xc1_pt.fill(0xcd);

	const xc1_blob       = Seal._fromNonce(XChaCha20Cipher, xc1_key, xc1_pt, xc1_nonce);
	const xc1_preambleLen = HEADER_SIZE + XChaCha20Cipher.commitmentSize;
	const xc1_preamble   = xc1_blob.subarray(0, xc1_preambleLen);
	const xc1_header     = xc1_preamble.subarray(0, HEADER_SIZE);
	const xc1_commitment = xc1_preamble.subarray(HEADER_SIZE, xc1_preambleLen);
	const { nonce: xc1_headerNonce } = readHeader(xc1_header);
	// HKDF info = INFO || 20-byte header — bind header into derivation
	const xc1_info = concat(xcInfo, xc1_header);
	const xc1_okm  = hkdf.derive(xc1_key, xc1_headerNonce, xc1_info, 64);
	const xc1_streamKey = xc1_okm.subarray(0, 32);
	const xc1_expCommit = xc1_okm.subarray(32, 64);
	assert(hex(xc1_commitment) === hex(xc1_expCommit), 'XC1 commitment matches HKDF bytes 32..64');
	const xc1_subkey = deriveSubkey(x, xc1_streamKey, xc1_headerNonce);
	const xc1_cn0    = makeCounterNonce(0, TAG_FINAL);
	const xc1_enc    = aeadEncrypt(x, xc1_subkey, xc1_cn0, xc1_pt, new Uint8Array(0));
	const xc1_expected = concat(xc1_preamble, xc1_enc.ciphertext, xc1_enc.tag);
	assert(hex(xc1_blob) === hex(xc1_expected), 'XC1 verify');
	const xc1_opener = new OpenStream(XChaCha20Cipher, xc1_key, xc1_preamble);
	assert(hex(xc1_opener.finalize(xc1_blob.subarray(xc1_preambleLen))) === hex(xc1_pt), 'XC1 round-trip');
	console.log('XC1 (xchacha v3): verified');

	// XC_EMPTY: empty plaintext
	const xce_key   = new Uint8Array(32); xce_key.fill(0x02);
	const xce_nonce = new Uint8Array(16); xce_nonce.fill(0xbb);
	const xce_pt    = new Uint8Array(0);

	const xce_blob       = Seal._fromNonce(XChaCha20Cipher, xce_key, xce_pt, xce_nonce);
	const xce_preambleLen = HEADER_SIZE + XChaCha20Cipher.commitmentSize;
	const xce_preamble   = xce_blob.subarray(0, xce_preambleLen);
	const xce_header     = xce_preamble.subarray(0, HEADER_SIZE);
	const xce_commitment = xce_preamble.subarray(HEADER_SIZE, xce_preambleLen);
	const { nonce: xce_headerNonce } = readHeader(xce_header);
	const xce_info = concat(xcInfo, xce_header);
	const xce_okm  = hkdf.derive(xce_key, xce_headerNonce, xce_info, 64);
	const xce_streamKey = xce_okm.subarray(0, 32);
	const xce_expCommit = xce_okm.subarray(32, 64);
	assert(hex(xce_commitment) === hex(xce_expCommit), 'XC_EMPTY commitment matches HKDF bytes 32..64');
	const xce_subkey = deriveSubkey(x, xce_streamKey, xce_headerNonce);
	const xce_cn0    = makeCounterNonce(0, TAG_FINAL);
	const xce_enc    = aeadEncrypt(x, xce_subkey, xce_cn0, xce_pt, new Uint8Array(0));
	const xce_expected = concat(xce_preamble, xce_enc.ciphertext, xce_enc.tag);
	assert(hex(xce_blob) === hex(xce_expected), 'XC_EMPTY verify');
	const xce_opener = new OpenStream(XChaCha20Cipher, xce_key, xce_preamble);
	assert(hex(xce_opener.finalize(xce_blob.subarray(xce_preambleLen))) === hex(xce_pt), 'XC_EMPTY round-trip');
	console.log('XC_EMPTY (xchacha v3): verified');

	return `${asciiHeader}
// Seal XChaCha20 v3 KAT vectors — single-chunk STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// XChaCha20 v3 wire format: 20-byte header + 32-byte key commitment in the
// preamble (52 bytes total). HKDF info string is 'xchacha20-sealstream-v3'
// concatenated with the 20-byte header, binding formatEnum, framed flag,
// nonce, and chunkSize into the derived material. Generated with fixed
// nonce seams, then independently verified against the underlying
// primitives (HKDF-SHA-256, HChaCha20, ChaCha20-Poly1305).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealXChachaV3Vector {
\tdescription: string;
\tkey: string;          // hex, 32 bytes
\tnonce: string;        // hex, 16 bytes
\tplaintext: string;    // hex
\tpreamble: string;     // hex, 52 bytes (20 header + 32 commitment)
\tblob: string;         // hex, full output = preamble || ciphertext
}

export const xc1: SealXChachaV3Vector = {
\tdescription: 'XC1: xchacha20 v3, 0x01 key, 0xaa nonce, 100-byte 0xcd plaintext',
\tkey: '${hex(xc1_key)}',
\tnonce: '${hex(xc1_nonce)}',
\tplaintext:
\t\t${splitHex(hex(xc1_pt))},
\tpreamble:
\t\t${splitHex(hex(xc1_preamble))},
\tblob:
\t\t${splitHex(hex(xc1_blob))},
};

export const xc_empty: SealXChachaV3Vector = {
\tdescription: 'XC_EMPTY: xchacha20 v3, 0x02 key, 0xbb nonce, empty plaintext',
\tkey: '${hex(xce_key)}',
\tnonce: '${hex(xce_nonce)}',
\tplaintext: '',
\tpreamble:
\t\t${splitHex(hex(xce_preamble))},
\tblob:
\t\t${splitHex(hex(xce_blob))},
};
`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Serpent path — v3 wire format
// ═══════════════════════════════════════════════════════════════════════════════

function buildSerpent(): string {
	// Phase A: drive SerpentCipher seal/open paths. SerpentCbc cannot be alive
	// here — it holds the 'serpent' WASM module exclusively and would block
	// SerpentCipher.sealChunk via the _assertNotOwned guard.

	const sc1_key   = new Uint8Array(32); sc1_key.fill(0x03);
	const sc1_nonce = new Uint8Array(16); sc1_nonce.fill(0xcc);
	const sc1_pt    = new Uint8Array(100); sc1_pt.fill(0xef);

	const sc1_blob     = Seal._fromNonce(SerpentCipher, sc1_key, sc1_pt, sc1_nonce);
	const sc1_preamble = sc1_blob.subarray(0, HEADER_SIZE);
	const { nonce: sc1_headerNonce } = readHeader(sc1_preamble);
	const sc1_opener = new OpenStream(SerpentCipher, sc1_key, sc1_preamble);
	assert(hex(sc1_opener.finalize(sc1_blob.subarray(HEADER_SIZE))) === hex(sc1_pt), 'SC1 round-trip');

	const sce_key   = new Uint8Array(32); sce_key.fill(0x04);
	const sce_nonce = new Uint8Array(16); sce_nonce.fill(0xdd);
	const sce_pt    = new Uint8Array(0);

	const sce_blob     = Seal._fromNonce(SerpentCipher, sce_key, sce_pt, sce_nonce);
	const sce_preamble = sce_blob.subarray(0, HEADER_SIZE);
	const { nonce: sce_headerNonce } = readHeader(sce_preamble);
	const sce_opener = new OpenStream(SerpentCipher, sce_key, sce_preamble);
	assert(hex(sce_opener.finalize(sce_blob.subarray(HEADER_SIZE))) === hex(sce_pt), 'SC_EMPTY round-trip');

	// Phase B: independent verification against raw primitives. SerpentCbc
	// constructed here, used, disposed before exiting.
	const cbc = new SerpentCbc({ dangerUnauthenticated: true });
	try {
		const sc1_derived  = hkdf.derive(sc1_key, sc1_headerNonce, scInfo, 96);
		const sc1_encKey   = sc1_derived.subarray(0, 32);
		const sc1_macKey   = sc1_derived.subarray(32, 64);
		const sc1_ivKey    = sc1_derived.subarray(64, 96);
		const sc1_cn0      = makeCounterNonce(0, TAG_FINAL);
		const sc1_iv       = hmac.hash(sc1_ivKey, sc1_cn0).subarray(0, 16);
		const sc1_cbcCt    = cbc.encrypt(sc1_encKey, sc1_iv, sc1_pt);
		const sc1_tagInput = concat(sc1_cn0, u32be(0), sc1_cbcCt);
		const sc1_tag      = hmac.hash(sc1_macKey, sc1_tagInput);
		assert(hex(sc1_blob) === hex(concat(sc1_preamble, sc1_cbcCt, sc1_tag)), 'SC1 verify');
		console.log('SC1 (serpent v3): verified');

		const sce_derived  = hkdf.derive(sce_key, sce_headerNonce, scInfo, 96);
		const sce_encKey   = sce_derived.subarray(0, 32);
		const sce_macKey   = sce_derived.subarray(32, 64);
		const sce_ivKey    = sce_derived.subarray(64, 96);
		const sce_cn0      = makeCounterNonce(0, TAG_FINAL);
		const sce_iv       = hmac.hash(sce_ivKey, sce_cn0).subarray(0, 16);
		const sce_cbcCt    = cbc.encrypt(sce_encKey, sce_iv, sce_pt);
		const sce_tagInput = concat(sce_cn0, u32be(0), sce_cbcCt);
		const sce_tag      = hmac.hash(sce_macKey, sce_tagInput);
		assert(hex(sce_blob) === hex(concat(sce_preamble, sce_cbcCt, sce_tag)), 'SC_EMPTY verify');
		console.log('SC_EMPTY (serpent v3): verified');
	} finally {
		cbc.dispose();
	}

	return `${asciiHeader}
// Seal Serpent v2 KAT vectors — single-chunk STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// Serpent v3 wire format: 20-byte header preamble. HMAC-SHA-256 chunk
// authentication is collision-resistant under SHA-256, which is
// key-committing — no separate commitment is needed in the preamble.
// Generated with fixed nonce seams, then independently verified against
// the underlying primitives (HKDF-SHA-256, SerpentCbc, HMAC-SHA-256).
// Vectors serve as regression trip-wires for Seal wire format stability.
// Audit status: SELF-VERIFIED

export interface SealSerpentV3Vector {
\tdescription: string;
\tkey: string;          // hex, 32 bytes
\tnonce: string;        // hex, 16 bytes
\tplaintext: string;    // hex
\tpreamble: string;     // hex, 20 bytes
\tblob: string;         // hex, full output = preamble || ciphertext
}

export const sc1: SealSerpentV3Vector = {
\tdescription: 'SC1: serpent v3, 0x03 key, 0xcc nonce, 100-byte 0xef plaintext',
\tkey: '${hex(sc1_key)}',
\tnonce: '${hex(sc1_nonce)}',
\tplaintext:
\t\t${splitHex(hex(sc1_pt))},
\tpreamble: '${hex(sc1_preamble)}',
\tblob:
\t\t${splitHex(hex(sc1_blob))},
};

export const sc_empty: SealSerpentV3Vector = {
\tdescription: 'SC_EMPTY: serpent v3, 0x04 key, 0xdd nonce, empty plaintext',
\tkey: '${hex(sce_key)}',
\tnonce: '${hex(sce_nonce)}',
\tplaintext: '',
\tpreamble: '${hex(sce_preamble)}',
\tblob:
\t\t${splitHex(hex(sce_blob))},
};
`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Drive the requested cipher path(s)
// ═══════════════════════════════════════════════════════════════════════════════

if (cipher === 'xchacha' || cipher === 'all') {
	const file = buildXChacha();
	writeFileSync('test/vectors/seal_xchacha_v3.ts', file);
	console.log('Written test/vectors/seal_xchacha_v3.ts');
}
if (cipher === 'serpent' || cipher === 'all') {
	const file = buildSerpent();
	writeFileSync('test/vectors/seal_serpent_v3.ts', file);
	console.log('Written test/vectors/seal_serpent_v3.ts');
}

hmac.dispose(); hkdf.dispose();
