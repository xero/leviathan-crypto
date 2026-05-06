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
 * Generate SealStream KAT vectors for both cipher families.
 *
 * Uses SealStream with deterministic _nonce seam, then independently verifies
 * each chunk against raw primitives. Verified vectors are pinned as hex KATs.
 *
 * usage:
 *   bun run scripts/gen-sealstream-vectors.ts                  # default --cipher all
 *   bun run scripts/gen-sealstream-vectors.ts --cipher xchacha # writes sealstream_xchacha_v3.ts only
 *   bun run scripts/gen-sealstream-vectors.ts --cipher serpent # writes sealstream_serpent_v3.ts only
 */
import {
	init, SerpentCbc, HMAC_SHA256, HKDF_SHA256,
	bytesToHex,
} from '../src/ts/index.js';
import { serpentWasm } from '../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../src/ts/chacha20/embedded.js';
import { aesWasm } from '../src/ts/aes/embedded.js';
import { sha2Wasm } from '../src/ts/sha2/embedded.js';
import { SealStream, OpenStream } from '../src/ts/stream/index.js';
import { SerpentCipher } from '../src/ts/serpent/cipher-suite.js';
import { XChaCha20Cipher } from '../src/ts/chacha20/cipher-suite.js';
import { AESGCMSIVCipher } from '../src/ts/aes/cipher-suite.js';
import { writeHeader, makeCounterNonce } from '../src/ts/stream/header.js';
import { TAG_DATA, TAG_FINAL, HEADER_SIZE } from '../src/ts/stream/constants.js';
import { aeadEncrypt, deriveSubkey } from '../src/ts/chacha20/ops.js';
import { sivAeadEncrypt } from '../src/ts/aes/ops.js';
import { getInstance } from '../src/ts/init.js';
import type { ChaChaExports } from '../src/ts/chacha20/types.js';
import type { AesExports } from '../src/ts/aes/types.js';
import { writeFileSync } from 'fs';

const args = process.argv.slice(2);
const cipherFlag = args.indexOf('--cipher');
const cipher = cipherFlag >= 0 ? args[cipherFlag + 1] : 'all';
if (!['xchacha', 'serpent', 'aes', 'all'].includes(cipher))
	throw new Error(`unknown --cipher: ${cipher} (expected: xchacha, serpent, aes, all)`);

await init({ serpent: serpentWasm, sha2: sha2Wasm, chacha20: chacha20Wasm, aes: aesWasm });

function hex(b: Uint8Array): string { return bytesToHex(b); }
function assert(cond: boolean, msg: string) {
	if (!cond) { console.error('ASSERTION FAILED:', msg); process.exit(1); }
}
function splitHex(h: string, indent = '\t\t'): string {
	const lines: string[] = [];
	for (let i = 0; i < h.length; i += 64) lines.push(`'${h.slice(i, i + 64)}'`);
	return lines.join(' +\n' + indent);
}

const hkdf = new HKDF_SHA256();
const hmac = new HMAC_SHA256();
// SerpentCbc holds the 'serpent' WASM module exclusively. We construct it
// lazily for verification only after all SerpentCipher seal calls complete.

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

const xcInfo  = new TextEncoder().encode('xchacha20-sealstream-v3');
const scInfo  = new TextEncoder().encode('serpent-sealstream-v3');
const aesInfo = new TextEncoder().encode('aes-gcm-siv-sealstream-v3');
const x = getInstance('chacha20').exports as unknown as ChaChaExports;

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
	// XC1: single-chunk
	const xc1_key   = new Uint8Array(32); xc1_key.fill(0x01);
	const xc1_nonce = new Uint8Array(16); xc1_nonce.fill(0xaa);
	const xc1_pt    = new Uint8Array(100); xc1_pt.fill(0xcd);

	const xc1_sealer   = SealStream._fromNonce(XChaCha20Cipher, xc1_key, { chunkSize: 1024 }, xc1_nonce);
	const xc1_preamble = xc1_sealer.preamble;
	const xc1_ct0      = xc1_sealer.finalize(xc1_pt);
	const xc1_header   = xc1_preamble.subarray(0, HEADER_SIZE);
	const xc1_commit   = xc1_preamble.subarray(HEADER_SIZE, HEADER_SIZE + XChaCha20Cipher.commitmentSize);
	const xc1_expHeader = writeHeader(XChaCha20Cipher.formatEnum, false, xc1_nonce, 1024);
	assert(hex(xc1_header) === hex(xc1_expHeader), 'XC1 header structure');
	const xc1_info  = concat(xcInfo, xc1_header);
	const xc1_okm   = hkdf.derive(xc1_key, xc1_nonce, xc1_info, 64);
	const xc1_streamKey = xc1_okm.subarray(0, 32);
	assert(hex(xc1_commit) === hex(xc1_okm.subarray(32, 64)), 'XC1 commitment');
	const xc1_subkey = deriveSubkey(x, xc1_streamKey, xc1_nonce);
	const xc1_cn0    = makeCounterNonce(0, TAG_FINAL);
	const xc1_enc    = aeadEncrypt(x, xc1_subkey, xc1_cn0, xc1_pt, new Uint8Array(0));
	assert(hex(xc1_ct0) === hex(concat(xc1_enc.ciphertext, xc1_enc.tag)), 'XC1 chunk 0 verify');
	const xc1_opener = new OpenStream(XChaCha20Cipher, xc1_key, xc1_preamble);
	assert(hex(xc1_opener.finalize(xc1_ct0)) === hex(xc1_pt), 'XC1 round-trip');
	console.log('XC1 (xchacha v3): single-chunk verified');

	// XC3: multi-chunk
	const xc3_key   = new Uint8Array(32); for (let i = 0; i < 32; i++) xc3_key[i] = i;
	const xc3_nonce = new Uint8Array(16); for (let i = 0; i < 16; i++) xc3_nonce[i] = 0xf0 + i;
	const xc3_pts = [
		new Uint8Array(1024).fill(0x11),
		new Uint8Array(512).fill(0x22),
		new Uint8Array(256).fill(0x33),
		new Uint8Array(0),
	];

	const xc3_sealer   = SealStream._fromNonce(XChaCha20Cipher, xc3_key, { chunkSize: 1024 }, xc3_nonce);
	const xc3_preamble = xc3_sealer.preamble;
	const xc3_header   = xc3_preamble.subarray(0, HEADER_SIZE);
	const xc3_commit   = xc3_preamble.subarray(HEADER_SIZE, HEADER_SIZE + XChaCha20Cipher.commitmentSize);
	const xc3_cts: Uint8Array[] = [];
	for (let i = 0; i < 3; i++) xc3_cts.push(xc3_sealer.push(xc3_pts[i]));
	xc3_cts.push(xc3_sealer.finalize(xc3_pts[3]));
	const xc3_info = concat(xcInfo, xc3_header);
	const xc3_okm  = hkdf.derive(xc3_key, xc3_nonce, xc3_info, 64);
	const xc3_streamKey = xc3_okm.subarray(0, 32);
	assert(hex(xc3_commit) === hex(xc3_okm.subarray(32, 64)), 'XC3 commitment');
	const xc3_subkey = deriveSubkey(x, xc3_streamKey, xc3_nonce);
	for (let i = 0; i < 4; i++) {
		const flag = i === 3 ? TAG_FINAL : TAG_DATA;
		const cn = makeCounterNonce(i, flag);
		const enc = aeadEncrypt(x, xc3_subkey, cn, xc3_pts[i], new Uint8Array(0));
		assert(hex(xc3_cts[i]) === hex(concat(enc.ciphertext, enc.tag)), `XC3 chunk ${i} verify`);
	}
	const xc3_opener = new OpenStream(XChaCha20Cipher, xc3_key, xc3_preamble);
	for (let i = 0; i < 3; i++)
		assert(hex(xc3_opener.pull(xc3_cts[i])) === hex(xc3_pts[i]), `XC3 chunk ${i} round-trip`);
	assert(hex(xc3_opener.finalize(xc3_cts[3])) === hex(xc3_pts[3]), 'XC3 final round-trip');
	console.log('XC3 (xchacha v3): multi-chunk verified');

	// XCF1: framed two-chunk
	const xcf1_key   = new Uint8Array(32); xcf1_key.fill(0x03);
	const xcf1_nonce = new Uint8Array(16); xcf1_nonce.fill(0xcc);
	const xcf1_pts = [new Uint8Array(200).fill(0x77), new Uint8Array(100).fill(0x88)];

	const xcf1_unframed = SealStream._fromNonce(XChaCha20Cipher, xcf1_key, { chunkSize: 1024 }, xcf1_nonce);
	const xcf1_uf_cts = [xcf1_unframed.push(xcf1_pts[0]), xcf1_unframed.finalize(xcf1_pts[1])];

	const xcf1_sealer   = SealStream._fromNonce(XChaCha20Cipher, xcf1_key, { chunkSize: 1024, framed: true }, xcf1_nonce);
	const xcf1_preamble = xcf1_sealer.preamble;
	const xcf1_header   = xcf1_preamble.subarray(0, HEADER_SIZE);
	const xcf1_commit   = xcf1_preamble.subarray(HEADER_SIZE, HEADER_SIZE + XChaCha20Cipher.commitmentSize);
	const xcf1_cts = [xcf1_sealer.push(xcf1_pts[0]), xcf1_sealer.finalize(xcf1_pts[1])];

	// Framed differs from unframed because the framed flag bit changes the header,
	// which changes the HKDF info and therefore the derived keys + commitment.
	const xcf1_info = concat(xcInfo, xcf1_header);
	const xcf1_okm  = hkdf.derive(xcf1_key, xcf1_nonce, xcf1_info, 64);
	const xcf1_streamKey = xcf1_okm.subarray(0, 32);
	assert(hex(xcf1_commit) === hex(xcf1_okm.subarray(32, 64)), 'XCF1 commitment');
	const xcf1_subkey = deriveSubkey(x, xcf1_streamKey, xcf1_nonce);
	for (let i = 0; i < 2; i++) {
		const flag = i === 1 ? TAG_FINAL : TAG_DATA;
		const cn = makeCounterNonce(i, flag);
		const enc = aeadEncrypt(x, xcf1_subkey, cn, xcf1_pts[i], new Uint8Array(0));
		const expectedRaw = concat(enc.ciphertext, enc.tag);
		const expectedFramed = concat(u32be(expectedRaw.length), expectedRaw);
		assert(hex(xcf1_cts[i]) === hex(expectedFramed), `XCF1 chunk ${i} framed verify`);
	}
	// Framed v3 ciphertexts differ from unframed because the framed flag enters
	// HKDF info, producing different streamKeys and different keystreams. Assert
	// divergence so a future header-binding regression cannot silently collide.
	for (let i = 0; i < 2; i++) {
		assert(
			hex(xcf1_cts[i].subarray(4)) !== hex(xcf1_uf_cts[i]),
			`XCF1 framed chunk ${i} must differ from unframed (header binding regression check)`,
		);
	}
	const xcf1_opener = new OpenStream(XChaCha20Cipher, xcf1_key, xcf1_preamble);
	assert(hex(xcf1_opener.pull(xcf1_cts[0])) === hex(xcf1_pts[0]), 'XCF1 chunk 0 round-trip');
	assert(hex(xcf1_opener.finalize(xcf1_cts[1])) === hex(xcf1_pts[1]), 'XCF1 chunk 1 round-trip');
	console.log('XCF1 (xchacha v3): framed verified');

	return `${asciiHeader}
// SealStream XChaCha20 v3 KAT vectors — STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// XChaCha20 v3 wire format: 20-byte header + 32-byte key commitment in the
// preamble (52 bytes total). HKDF info string is 'xchacha20-sealstream-v3'
// concatenated with the 20-byte header, binding formatEnum, framed flag,
// nonce, and chunkSize into the derived material. Generated with fixed
// nonce seams, then each chunk independently verified against the
// underlying primitives (HKDF-SHA-256, HChaCha20, ChaCha20-Poly1305).
// Vectors serve as regression trip-wires for wire format stability.
// Audit status: SELF-VERIFIED

export interface SealStreamXChachaV3Vector {
\tdescription: string;
\tkey: string;
\tnonce: string;
\tchunkSize: number;
\tframed?: boolean;
\tpreamble: string;     // 52 bytes hex (20 header + 32 commitment)
\tchunks: { plaintext: string; ciphertext: string }[];
}

export const xc1: SealStreamXChachaV3Vector = {
\tdescription: 'XC1: xchacha20 v3 single-chunk, 0x01 key, 0xaa nonce, 100-byte 0xcd plaintext',
\tkey: '${hex(xc1_key)}',
\tnonce: '${hex(xc1_nonce)}',
\tchunkSize: 1024,
\tpreamble:
\t\t${splitHex(hex(xc1_preamble))},
\tchunks: [
\t\t{
\t\t\tplaintext: '${hex(xc1_pt)}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(xc1_ct0), '\t\t\t\t')},
\t\t},
\t],
};

export const xc3: SealStreamXChachaV3Vector = {
\tdescription: 'XC3: xchacha20 v3 multi-chunk, sequential key, 0xf0+ nonce, varied plaintexts + empty finalize',
\tkey: '${hex(xc3_key)}',
\tnonce: '${hex(xc3_nonce)}',
\tchunkSize: 1024,
\tpreamble:
\t\t${splitHex(hex(xc3_preamble))},
\tchunks: [
${xc3_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(xc3_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};

export const xcf1: SealStreamXChachaV3Vector = {
\tdescription: 'XCF1: xchacha20 v3 framed, 2 chunks (push + finalize)',
\tkey: '${hex(xcf1_key)}',
\tnonce: '${hex(xcf1_nonce)}',
\tchunkSize: 1024,
\tframed: true,
\tpreamble:
\t\t${splitHex(hex(xcf1_preamble))},
\tchunks: [
${xcf1_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(xcf1_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
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

	const sc1_key   = new Uint8Array(32); sc1_key.fill(0x02);
	const sc1_nonce = new Uint8Array(16); sc1_nonce.fill(0xbb);
	const sc1_pt    = new Uint8Array(100); sc1_pt.fill(0xef);

	const sc1_sealer   = SealStream._fromNonce(SerpentCipher, sc1_key, { chunkSize: 1024 }, sc1_nonce);
	const sc1_preamble = sc1_sealer.preamble;
	const sc1_ct0      = sc1_sealer.finalize(sc1_pt);
	const sc1_opener = new OpenStream(SerpentCipher, sc1_key, sc1_preamble);
	assert(hex(sc1_opener.finalize(sc1_ct0)) === hex(sc1_pt), 'SC1 round-trip');

	const sc3_key   = new Uint8Array(32); for (let i = 0; i < 32; i++) sc3_key[i] = i + 0x10;
	const sc3_nonce = new Uint8Array(16); for (let i = 0; i < 16; i++) sc3_nonce[i] = 0xe0 + i;
	const sc3_pts = [
		new Uint8Array(1024).fill(0x44),
		new Uint8Array(512).fill(0x55),
		new Uint8Array(256).fill(0x66),
		new Uint8Array(0),
	];

	const sc3_sealer   = SealStream._fromNonce(SerpentCipher, sc3_key, { chunkSize: 1024 }, sc3_nonce);
	const sc3_preamble = sc3_sealer.preamble;
	const sc3_cts: Uint8Array[] = [];
	for (let i = 0; i < 3; i++) sc3_cts.push(sc3_sealer.push(sc3_pts[i]));
	sc3_cts.push(sc3_sealer.finalize(sc3_pts[3]));
	const sc3_opener = new OpenStream(SerpentCipher, sc3_key, sc3_preamble);
	for (let i = 0; i < 3; i++)
		assert(hex(sc3_opener.pull(sc3_cts[i])) === hex(sc3_pts[i]), `SC3 chunk ${i} round-trip`);
	assert(hex(sc3_opener.finalize(sc3_cts[3])) === hex(sc3_pts[3]), 'SC3 final round-trip');

	const scf1_key   = new Uint8Array(32); scf1_key.fill(0x04);
	const scf1_nonce = new Uint8Array(16); scf1_nonce.fill(0xdd);
	const scf1_pts = [new Uint8Array(200).fill(0x99), new Uint8Array(100).fill(0xaa)];

	const scf1_unframed = SealStream._fromNonce(SerpentCipher, scf1_key, { chunkSize: 1024 }, scf1_nonce);
	const scf1_uf_cts = [scf1_unframed.push(scf1_pts[0]), scf1_unframed.finalize(scf1_pts[1])];

	const scf1_sealer   = SealStream._fromNonce(SerpentCipher, scf1_key, { chunkSize: 1024, framed: true }, scf1_nonce);
	const scf1_preamble = scf1_sealer.preamble;
	const scf1_cts = [scf1_sealer.push(scf1_pts[0]), scf1_sealer.finalize(scf1_pts[1])];
	const scf1_opener = new OpenStream(SerpentCipher, scf1_key, scf1_preamble);
	assert(hex(scf1_opener.pull(scf1_cts[0])) === hex(scf1_pts[0]), 'SCF1 chunk 0 round-trip');
	assert(hex(scf1_opener.finalize(scf1_cts[1])) === hex(scf1_pts[1]), 'SCF1 chunk 1 round-trip');

	// Phase B: independent verification with raw primitives. SerpentCbc is
	// constructed here, used, and disposed before exit.
	const cbc = new SerpentCbc({ dangerUnauthenticated: true });
	try {
		const sc1_derived  = hkdf.derive(sc1_key, sc1_nonce, scInfo, 96);
		const sc1_encKey   = sc1_derived.subarray(0, 32);
		const sc1_macKey   = sc1_derived.subarray(32, 64);
		const sc1_ivKey    = sc1_derived.subarray(64, 96);
		const sc1_cn0      = makeCounterNonce(0, TAG_FINAL);
		const sc1_iv       = hmac.hash(sc1_ivKey, sc1_cn0).subarray(0, 16);
		const sc1_cbcCt    = cbc.encrypt(sc1_encKey, sc1_iv, sc1_pt);
		const sc1_tagInput = concat(sc1_cn0, u32be(0), sc1_cbcCt);
		const sc1_tag      = hmac.hash(sc1_macKey, sc1_tagInput);
		assert(hex(sc1_ct0) === hex(concat(sc1_cbcCt, sc1_tag)), 'SC1 chunk 0 verify');
		console.log('SC1 (serpent v3): single-chunk verified');

		const sc3_derived = hkdf.derive(sc3_key, sc3_nonce, scInfo, 96);
		const sc3_encKey  = sc3_derived.subarray(0, 32);
		const sc3_macKey  = sc3_derived.subarray(32, 64);
		const sc3_ivKey   = sc3_derived.subarray(64, 96);
		for (let i = 0; i < 4; i++) {
			const flag = i === 3 ? TAG_FINAL : TAG_DATA;
			const cn = makeCounterNonce(i, flag);
			const iv = hmac.hash(sc3_ivKey, cn).subarray(0, 16);
			const cbcCt = cbc.encrypt(sc3_encKey, iv, sc3_pts[i]);
			const tagInput = concat(cn, u32be(0), cbcCt);
			const tag = hmac.hash(sc3_macKey, tagInput);
			assert(hex(sc3_cts[i]) === hex(concat(cbcCt, tag)), `SC3 chunk ${i} verify`);
		}
		console.log('SC3 (serpent v3): multi-chunk verified');

		for (let i = 0; i < 2; i++) {
			const expected = concat(u32be(scf1_uf_cts[i].length), scf1_uf_cts[i]);
			assert(hex(scf1_cts[i]) === hex(expected), `SCF1 chunk ${i} framing verify`);
		}
		console.log('SCF1 (serpent v3): framed verified');
	} finally {
		cbc.dispose();
	}

	return `${asciiHeader}
// SealStream Serpent v2 KAT vectors — STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// Serpent v3 wire format: 20-byte header preamble. HMAC-SHA-256 chunk
// authentication is collision-resistant under SHA-256, which is
// key-committing — no separate commitment is needed in the preamble.
// Generated with fixed nonce seams, then each chunk independently
// verified against the underlying primitives (HKDF-SHA-256, SerpentCbc,
// HMAC-SHA-256). Vectors serve as regression trip-wires for wire format
// stability.
// Audit status: SELF-VERIFIED

export interface SealStreamSerpentV3Vector {
\tdescription: string;
\tkey: string;
\tnonce: string;
\tchunkSize: number;
\tframed?: boolean;
\tpreamble: string;     // 20 bytes hex
\tchunks: { plaintext: string; ciphertext: string }[];
}

export const sc1: SealStreamSerpentV3Vector = {
\tdescription: 'SC1: serpent v3 single-chunk, 0x02 key, 0xbb nonce, 100-byte 0xef plaintext',
\tkey: '${hex(sc1_key)}',
\tnonce: '${hex(sc1_nonce)}',
\tchunkSize: 1024,
\tpreamble: '${hex(sc1_preamble)}',
\tchunks: [
\t\t{
\t\t\tplaintext: '${hex(sc1_pt)}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(sc1_ct0), '\t\t\t\t')},
\t\t},
\t],
};

export const sc3: SealStreamSerpentV3Vector = {
\tdescription: 'SC3: serpent v3 multi-chunk, sequential key, 0xe0+ nonce, varied plaintexts + empty finalize',
\tkey: '${hex(sc3_key)}',
\tnonce: '${hex(sc3_nonce)}',
\tchunkSize: 1024,
\tpreamble: '${hex(sc3_preamble)}',
\tchunks: [
${sc3_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(sc3_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};

export const scf1: SealStreamSerpentV3Vector = {
\tdescription: 'SCF1: serpent v3 framed, 2 chunks (push + finalize)',
\tkey: '${hex(scf1_key)}',
\tnonce: '${hex(scf1_nonce)}',
\tchunkSize: 1024,
\tframed: true,
\tpreamble: '${hex(scf1_preamble)}',
\tchunks: [
${scf1_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(scf1_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};
`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-GCM-SIV path — v3 wire format (commitment + header-bound HKDF)
// ═══════════════════════════════════════════════════════════════════════════════

function buildAes(): string {
	const aesX = getInstance('aes').exports as unknown as AesExports;

	// AC1: single-chunk
	const ac1_key   = new Uint8Array(32); ac1_key.fill(0x05);
	const ac1_nonce = new Uint8Array(16); ac1_nonce.fill(0xee);
	const ac1_pt    = new Uint8Array(100); ac1_pt.fill(0x12);

	const ac1_sealer   = SealStream._fromNonce(AESGCMSIVCipher, ac1_key, { chunkSize: 1024 }, ac1_nonce);
	const ac1_preamble = ac1_sealer.preamble;
	const ac1_ct0      = ac1_sealer.finalize(ac1_pt);
	const ac1_header   = ac1_preamble.subarray(0, HEADER_SIZE);
	const ac1_commit   = ac1_preamble.subarray(HEADER_SIZE, HEADER_SIZE + AESGCMSIVCipher.commitmentSize);
	const ac1_expHeader = writeHeader(AESGCMSIVCipher.formatEnum, false, ac1_nonce, 1024);
	assert(hex(ac1_header) === hex(ac1_expHeader), 'AC1 header structure');
	const ac1_info  = concat(aesInfo, ac1_header);
	const ac1_okm   = hkdf.derive(ac1_key, ac1_nonce, ac1_info, 64);
	const ac1_aesKey = ac1_okm.subarray(0, 32);
	assert(hex(ac1_commit) === hex(ac1_okm.subarray(32, 64)), 'AC1 commitment');
	const ac1_cn0  = makeCounterNonce(0, TAG_FINAL);
	const ac1_enc  = sivAeadEncrypt(aesX, ac1_aesKey, ac1_cn0, ac1_pt, new Uint8Array(0));
	assert(hex(ac1_ct0) === hex(concat(ac1_enc.ciphertext, ac1_enc.tag)), 'AC1 chunk 0 verify');
	const ac1_opener = new OpenStream(AESGCMSIVCipher, ac1_key, ac1_preamble);
	assert(hex(ac1_opener.finalize(ac1_ct0)) === hex(ac1_pt), 'AC1 round-trip');
	console.log('AC1 (aes-gcm-siv v3): single-chunk verified');

	// AC3: multi-chunk
	const ac3_key   = new Uint8Array(32); for (let i = 0; i < 32; i++) ac3_key[i] = i + 0x40;
	const ac3_nonce = new Uint8Array(16); for (let i = 0; i < 16; i++) ac3_nonce[i] = 0x70 + i;
	const ac3_pts = [
		new Uint8Array(1024).fill(0x21),
		new Uint8Array(512).fill(0x32),
		new Uint8Array(256).fill(0x43),
		new Uint8Array(0),
	];

	const ac3_sealer   = SealStream._fromNonce(AESGCMSIVCipher, ac3_key, { chunkSize: 1024 }, ac3_nonce);
	const ac3_preamble = ac3_sealer.preamble;
	const ac3_header   = ac3_preamble.subarray(0, HEADER_SIZE);
	const ac3_commit   = ac3_preamble.subarray(HEADER_SIZE, HEADER_SIZE + AESGCMSIVCipher.commitmentSize);
	const ac3_cts: Uint8Array[] = [];
	for (let i = 0; i < 3; i++) ac3_cts.push(ac3_sealer.push(ac3_pts[i]));
	ac3_cts.push(ac3_sealer.finalize(ac3_pts[3]));
	const ac3_info = concat(aesInfo, ac3_header);
	const ac3_okm  = hkdf.derive(ac3_key, ac3_nonce, ac3_info, 64);
	const ac3_aesKey = ac3_okm.subarray(0, 32);
	assert(hex(ac3_commit) === hex(ac3_okm.subarray(32, 64)), 'AC3 commitment');
	for (let i = 0; i < 4; i++) {
		const flag = i === 3 ? TAG_FINAL : TAG_DATA;
		const cn = makeCounterNonce(i, flag);
		const enc = sivAeadEncrypt(aesX, ac3_aesKey, cn, ac3_pts[i], new Uint8Array(0));
		assert(hex(ac3_cts[i]) === hex(concat(enc.ciphertext, enc.tag)), `AC3 chunk ${i} verify`);
	}
	const ac3_opener = new OpenStream(AESGCMSIVCipher, ac3_key, ac3_preamble);
	for (let i = 0; i < 3; i++)
		assert(hex(ac3_opener.pull(ac3_cts[i])) === hex(ac3_pts[i]), `AC3 chunk ${i} round-trip`);
	assert(hex(ac3_opener.finalize(ac3_cts[3])) === hex(ac3_pts[3]), 'AC3 final round-trip');
	console.log('AC3 (aes-gcm-siv v3): multi-chunk verified');

	// ACF1: framed two-chunk
	const acf1_key   = new Uint8Array(32); acf1_key.fill(0x07);
	const acf1_nonce = new Uint8Array(16); acf1_nonce.fill(0x88);
	const acf1_pts = [new Uint8Array(200).fill(0x55), new Uint8Array(100).fill(0x66)];

	const acf1_unframed = SealStream._fromNonce(AESGCMSIVCipher, acf1_key, { chunkSize: 1024 }, acf1_nonce);
	const acf1_uf_cts = [acf1_unframed.push(acf1_pts[0]), acf1_unframed.finalize(acf1_pts[1])];

	const acf1_sealer   = SealStream._fromNonce(AESGCMSIVCipher, acf1_key, { chunkSize: 1024, framed: true }, acf1_nonce);
	const acf1_preamble = acf1_sealer.preamble;
	const acf1_header   = acf1_preamble.subarray(0, HEADER_SIZE);
	const acf1_commit   = acf1_preamble.subarray(HEADER_SIZE, HEADER_SIZE + AESGCMSIVCipher.commitmentSize);
	const acf1_cts = [acf1_sealer.push(acf1_pts[0]), acf1_sealer.finalize(acf1_pts[1])];

	// Framed differs from unframed because the framed flag bit changes the header,
	// which changes the HKDF info and therefore the derived keys + commitment.
	const acf1_info = concat(aesInfo, acf1_header);
	const acf1_okm  = hkdf.derive(acf1_key, acf1_nonce, acf1_info, 64);
	const acf1_aesKey = acf1_okm.subarray(0, 32);
	assert(hex(acf1_commit) === hex(acf1_okm.subarray(32, 64)), 'ACF1 commitment');
	for (let i = 0; i < 2; i++) {
		const flag = i === 1 ? TAG_FINAL : TAG_DATA;
		const cn = makeCounterNonce(i, flag);
		const enc = sivAeadEncrypt(aesX, acf1_aesKey, cn, acf1_pts[i], new Uint8Array(0));
		const expectedRaw = concat(enc.ciphertext, enc.tag);
		const expectedFramed = concat(u32be(expectedRaw.length), expectedRaw);
		assert(hex(acf1_cts[i]) === hex(expectedFramed), `ACF1 chunk ${i} framed verify`);
	}
	// Framed v3 ciphertexts differ from unframed because the framed flag enters
	// HKDF info, producing different aesKey and different ciphertexts. Assert
	// divergence so a future header-binding regression cannot silently collide.
	for (let i = 0; i < 2; i++) {
		assert(
			hex(acf1_cts[i].subarray(4)) !== hex(acf1_uf_cts[i]),
			`ACF1 framed chunk ${i} must differ from unframed (header binding regression check)`,
		);
	}
	const acf1_opener = new OpenStream(AESGCMSIVCipher, acf1_key, acf1_preamble);
	assert(hex(acf1_opener.pull(acf1_cts[0])) === hex(acf1_pts[0]), 'ACF1 chunk 0 round-trip');
	assert(hex(acf1_opener.finalize(acf1_cts[1])) === hex(acf1_pts[1]), 'ACF1 chunk 1 round-trip');
	console.log('ACF1 (aes-gcm-siv v3): framed verified');

	return `${asciiHeader}
// SealStream AES-GCM-SIV v3 KAT vectors — STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// AES-GCM-SIV v3 wire format: 20-byte header + 32-byte key commitment in
// the preamble (52 bytes total). HKDF info string is
// 'aes-gcm-siv-sealstream-v3' concatenated with the 20-byte header,
// binding formatEnum, framed flag, nonce, and chunkSize into the derived
// material. Generated with fixed nonce seams, then each chunk
// independently verified against the underlying primitives (HKDF-SHA-256
// and the raw AES-GCM-SIV WASM ops in src/ts/aes/ops.ts).
// Vectors serve as regression trip-wires for wire format stability.
// Audit status: SELF-VERIFIED

export interface SealStreamAesV3Vector {
\tdescription: string;
\tkey: string;
\tnonce: string;
\tchunkSize: number;
\tframed?: boolean;
\tpreamble: string;     // 52 bytes hex (20 header + 32 commitment)
\tchunks: { plaintext: string; ciphertext: string }[];
}

export const ac1: SealStreamAesV3Vector = {
\tdescription: 'AC1: aes-gcm-siv v3 single-chunk, 0x05 key, 0xee nonce, 100-byte 0x12 plaintext',
\tkey: '${hex(ac1_key)}',
\tnonce: '${hex(ac1_nonce)}',
\tchunkSize: 1024,
\tpreamble:
\t\t${splitHex(hex(ac1_preamble))},
\tchunks: [
\t\t{
\t\t\tplaintext: '${hex(ac1_pt)}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ac1_ct0), '\t\t\t\t')},
\t\t},
\t],
};

export const ac3: SealStreamAesV3Vector = {
\tdescription: 'AC3: aes-gcm-siv v3 multi-chunk, sequential key, 0x70+ nonce, varied plaintexts + empty finalize',
\tkey: '${hex(ac3_key)}',
\tnonce: '${hex(ac3_nonce)}',
\tchunkSize: 1024,
\tpreamble:
\t\t${splitHex(hex(ac3_preamble))},
\tchunks: [
${ac3_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(ac3_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};

export const acf1: SealStreamAesV3Vector = {
\tdescription: 'ACF1: aes-gcm-siv v3 framed, 2 chunks (push + finalize)',
\tkey: '${hex(acf1_key)}',
\tnonce: '${hex(acf1_nonce)}',
\tchunkSize: 1024,
\tframed: true,
\tpreamble:
\t\t${splitHex(hex(acf1_preamble))},
\tchunks: [
${acf1_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(acf1_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};
`;
}

if (cipher === 'xchacha' || cipher === 'all') {
	const file = buildXChacha();
	writeFileSync('test/vectors/sealstream_xchacha_v3.ts', file);
	console.log('Written test/vectors/sealstream_xchacha_v3.ts');
}
if (cipher === 'serpent' || cipher === 'all') {
	const file = buildSerpent();
	writeFileSync('test/vectors/sealstream_serpent_v3.ts', file);
	console.log('Written test/vectors/sealstream_serpent_v3.ts');
}
if (cipher === 'aes' || cipher === 'all') {
	const file = buildAes();
	writeFileSync('test/vectors/sealstream_aes_v3.ts', file);
	console.log('Written test/vectors/sealstream_aes_v3.ts');
}

hmac.dispose(); hkdf.dispose();
