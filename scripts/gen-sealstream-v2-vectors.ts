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
 * Generate SealStream v2 KAT vectors for both cipher families.
 *
 * Uses SealStream with deterministic _nonce seam, then independently verifies
 * each chunk against raw primitives. Verified vectors are pinned as hex KATs.
 *
 * usage: bunx tsx scripts/gen-sealstream-v2-vectors.ts
 * output: test/vectors/sealstream_v2.ts
 */
import {
	init, SerpentCbc, HMAC_SHA256, HKDF_SHA256,
	bytesToHex,
} from '../src/ts/index.js';
import { serpentWasm } from '../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../src/ts/sha2/embedded.js';
import { SealStream, OpenStream } from '../src/ts/stream/index.js';
import { SerpentCipher } from '../src/ts/serpent/cipher-suite.js';
import { XChaCha20Cipher } from '../src/ts/chacha20/cipher-suite.js';
import { makeCounterNonce } from '../src/ts/stream/header.js';
import { TAG_DATA, TAG_FINAL } from '../src/ts/stream/constants.js';
import { aeadEncrypt, deriveSubkey } from '../src/ts/chacha20/ops.js';
import { getInstance } from '../src/ts/init.js';
import type { ChaChaExports } from '../src/ts/chacha20/types.js';
import { writeFileSync } from 'fs';

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
const cbc = new SerpentCbc({ dangerUnauthenticated: true });

function concat(...arrays: Uint8Array[]): Uint8Array {
	let len = 0;
	for (const a of arrays) len += a.length;
	const out = new Uint8Array(len);
	let off = 0;
	for (const a of arrays) { out.set(a, off); off += a.length; }
	return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
// XChaCha20 vector: single-chunk
// ═══════════════════════════════════════════════════════════════════════════════

const xc1_key   = new Uint8Array(32); xc1_key.fill(0x01);
const xc1_nonce = new Uint8Array(16); xc1_nonce.fill(0xaa);
const xc1_pt    = new Uint8Array(100); xc1_pt.fill(0xcd);

const xc1_sealer = new SealStream(XChaCha20Cipher, xc1_key, { chunkSize: 1024 }, xc1_nonce);
const xc1_header = xc1_sealer.header;
const xc1_ct0    = xc1_sealer.finalize(xc1_pt);

// Verify independently: HKDF → HChaCha20 → ChaCha20-Poly1305
const xc1_info = new TextEncoder().encode('xchacha20-sealstream-v2');
const xc1_streamKey = hkdf.derive(xc1_key, xc1_nonce, xc1_info, 32);
const x = getInstance('chacha20').exports as unknown as ChaChaExports;
const xc1_padded = new Uint8Array(24); xc1_padded.set(xc1_nonce.subarray(0, 16));
const xc1_subkey = deriveSubkey(x, xc1_streamKey, xc1_padded);
const xc1_cn0 = makeCounterNonce(0, TAG_FINAL);
const xc1_enc = aeadEncrypt(x, xc1_subkey, xc1_cn0, xc1_pt, new Uint8Array(0));
const xc1_expected = concat(xc1_enc.ciphertext, xc1_enc.tag);
assert(hex(xc1_ct0) === hex(xc1_expected), 'XC1 chunk 0 verify');

// Round-trip
const xc1_opener = new OpenStream(XChaCha20Cipher, xc1_key, xc1_header);
const xc1_dec = xc1_opener.finalize(xc1_ct0);
assert(hex(xc1_dec) === hex(xc1_pt), 'XC1 round-trip');

console.log('XC1: single-chunk verified');

// ═══════════════════════════════════════════════════════════════════════════════
// XChaCha20 vector: multi-chunk (3 push + finalize)
// ═══════════════════════════════════════════════════════════════════════════════

const xc3_key   = new Uint8Array(32); for (let i = 0; i < 32; i++) xc3_key[i] = i;
const xc3_nonce = new Uint8Array(16); for (let i = 0; i < 16; i++) xc3_nonce[i] = 0xf0 + i;
const xc3_pts = [
	new Uint8Array(1024).fill(0x11),
	new Uint8Array(512).fill(0x22),
	new Uint8Array(256).fill(0x33),
	new Uint8Array(0),  // empty finalize
];

const xc3_sealer = new SealStream(XChaCha20Cipher, xc3_key, { chunkSize: 1024 }, xc3_nonce);
const xc3_header = xc3_sealer.header;
const xc3_cts: Uint8Array[] = [];
for (let i = 0; i < 3; i++) xc3_cts.push(xc3_sealer.push(xc3_pts[i]));
xc3_cts.push(xc3_sealer.finalize(xc3_pts[3]));

// Verify each chunk independently
const xc3_streamKey = hkdf.derive(xc3_key, xc3_nonce, xc1_info, 32);
const xc3_padded = new Uint8Array(24); xc3_padded.set(xc3_nonce.subarray(0, 16));
const xc3_subkey = deriveSubkey(x, xc3_streamKey, xc3_padded);
for (let i = 0; i < 4; i++) {
	const flag = i === 3 ? TAG_FINAL : TAG_DATA;
	const cn = makeCounterNonce(i, flag);
	const enc = aeadEncrypt(x, xc3_subkey, cn, xc3_pts[i], new Uint8Array(0));
	const expected = concat(enc.ciphertext, enc.tag);
	assert(hex(xc3_cts[i]) === hex(expected), `XC3 chunk ${i} verify`);
}

// Round-trip
const xc3_opener = new OpenStream(XChaCha20Cipher, xc3_key, xc3_header);
for (let i = 0; i < 3; i++) {
	const dec = xc3_opener.pull(xc3_cts[i]);
	assert(hex(dec) === hex(xc3_pts[i]), `XC3 chunk ${i} round-trip`);
}
const xc3_final = xc3_opener.finalize(xc3_cts[3]);
assert(hex(xc3_final) === hex(xc3_pts[3]), 'XC3 final round-trip');

console.log('XC3: multi-chunk verified');

// ═══════════════════════════════════════════════════════════════════════════════
// Serpent vector: single-chunk
// ═══════════════════════════════════════════════════════════════════════════════

const sc1_key   = new Uint8Array(32); sc1_key.fill(0x02);
const sc1_nonce = new Uint8Array(16); sc1_nonce.fill(0xbb);
const sc1_pt    = new Uint8Array(100); sc1_pt.fill(0xef);

const sc1_sealer = new SealStream(SerpentCipher, sc1_key, { chunkSize: 1024 }, sc1_nonce);
const sc1_header = sc1_sealer.header;
const sc1_ct0    = sc1_sealer.finalize(sc1_pt);

// Verify independently: HKDF → 96 bytes → enc/mac/iv keys → CBC + HMAC
const sc1_sinfo = new TextEncoder().encode('serpent-sealstream-v2');
const sc1_derived = hkdf.derive(sc1_key, sc1_nonce, sc1_sinfo, 96);
const sc1_encKey = sc1_derived.subarray(0, 32);
const sc1_macKey = sc1_derived.subarray(32, 64);
const sc1_ivKey  = sc1_derived.subarray(64, 96);
const sc1_cn0 = makeCounterNonce(0, TAG_FINAL);
const sc1_iv = hmac.hash(sc1_ivKey, sc1_cn0).subarray(0, 16);
const sc1_cbcCt = cbc.encrypt(sc1_encKey, sc1_iv, sc1_pt);
const sc1_aadLenBuf = new Uint8Array(4); // 0 AAD
const sc1_tagInput = concat(sc1_cn0, sc1_aadLenBuf, sc1_cbcCt);
const sc1_tag = hmac.hash(sc1_macKey, sc1_tagInput);
const sc1_expected = concat(sc1_cbcCt, sc1_tag);
assert(hex(sc1_ct0) === hex(sc1_expected), 'SC1 chunk 0 verify');

// Round-trip
const sc1_opener = new OpenStream(SerpentCipher, sc1_key, sc1_header);
const sc1_dec = sc1_opener.finalize(sc1_ct0);
assert(hex(sc1_dec) === hex(sc1_pt), 'SC1 round-trip');

console.log('SC1: single-chunk verified');

// ═══════════════════════════════════════════════════════════════════════════════
// Serpent vector: multi-chunk (3 push + finalize)
// ═══════════════════════════════════════════════════════════════════════════════

const sc3_key   = new Uint8Array(32); for (let i = 0; i < 32; i++) sc3_key[i] = i + 0x10;
const sc3_nonce = new Uint8Array(16); for (let i = 0; i < 16; i++) sc3_nonce[i] = 0xe0 + i;
const sc3_pts = [
	new Uint8Array(1024).fill(0x44),
	new Uint8Array(512).fill(0x55),
	new Uint8Array(256).fill(0x66),
	new Uint8Array(0),
];

const sc3_sealer = new SealStream(SerpentCipher, sc3_key, { chunkSize: 1024 }, sc3_nonce);
const sc3_header = sc3_sealer.header;
const sc3_cts: Uint8Array[] = [];
for (let i = 0; i < 3; i++) sc3_cts.push(sc3_sealer.push(sc3_pts[i]));
sc3_cts.push(sc3_sealer.finalize(sc3_pts[3]));

// Verify each chunk independently
const sc3_derived = hkdf.derive(sc3_key, sc3_nonce, sc1_sinfo, 96);
const sc3_encKey = sc3_derived.subarray(0, 32);
const sc3_macKey = sc3_derived.subarray(32, 64);
const sc3_ivKey  = sc3_derived.subarray(64, 96);

for (let i = 0; i < 4; i++) {
	const flag = i === 3 ? TAG_FINAL : TAG_DATA;
	const cn = makeCounterNonce(i, flag);
	const iv = hmac.hash(sc3_ivKey, cn).subarray(0, 16);
	const cbcCt = cbc.encrypt(sc3_encKey, iv, sc3_pts[i]);
	const aadLenBuf = new Uint8Array(4);
	const tagInput = concat(cn, aadLenBuf, cbcCt);
	const tag = hmac.hash(sc3_macKey, tagInput);
	const expected = concat(cbcCt, tag);
	assert(hex(sc3_cts[i]) === hex(expected), `SC3 chunk ${i} verify`);
}

// Round-trip
const sc3_opener = new OpenStream(SerpentCipher, sc3_key, sc3_header);
for (let i = 0; i < 3; i++) {
	const dec = sc3_opener.pull(sc3_cts[i]);
	assert(hex(dec) === hex(sc3_pts[i]), `SC3 chunk ${i} round-trip`);
}
const sc3_final = sc3_opener.finalize(sc3_cts[3]);
assert(hex(sc3_final) === hex(sc3_pts[3]), 'SC3 final round-trip');

console.log('SC3: multi-chunk verified');

// ═══════════════════════════════════════════════════════════════════════════════
// XChaCha20 framed vector: two chunks (push + finalize)
// ═══════════════════════════════════════════════════════════════════════════════

const xcf1_key   = new Uint8Array(32); xcf1_key.fill(0x03);
const xcf1_nonce = new Uint8Array(16); xcf1_nonce.fill(0xcc);
const xcf1_pts = [new Uint8Array(200).fill(0x77), new Uint8Array(100).fill(0x88)];

// Seal unframed with same nonce for comparison
const xcf1_unframed = new SealStream(XChaCha20Cipher, xcf1_key, { chunkSize: 1024 }, xcf1_nonce);
const xcf1_uf_cts = [xcf1_unframed.push(xcf1_pts[0]), xcf1_unframed.finalize(xcf1_pts[1])];

// Seal framed
const xcf1_sealer = new SealStream(XChaCha20Cipher, xcf1_key, { chunkSize: 1024, framed: true }, xcf1_nonce);
const xcf1_header = xcf1_sealer.header;
const xcf1_cts = [xcf1_sealer.push(xcf1_pts[0]), xcf1_sealer.finalize(xcf1_pts[1])];

// Verify framing is purely additive: framed = u32be(unframed.length) || unframed
function u32be(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, false);
	return b;
}
for (let i = 0; i < 2; i++) {
	const expected = concat(u32be(xcf1_uf_cts[i].length), xcf1_uf_cts[i]);
	assert(hex(xcf1_cts[i]) === hex(expected), `XCF1 chunk ${i} framing verify`);
}

// Round-trip
const xcf1_opener = new OpenStream(XChaCha20Cipher, xcf1_key, xcf1_header);
const xcf1_dec0 = xcf1_opener.pull(xcf1_cts[0]);
const xcf1_dec1 = xcf1_opener.finalize(xcf1_cts[1]);
assert(hex(xcf1_dec0) === hex(xcf1_pts[0]), 'XCF1 chunk 0 round-trip');
assert(hex(xcf1_dec1) === hex(xcf1_pts[1]), 'XCF1 chunk 1 round-trip');

console.log('XCF1: framed xchacha20 verified');

// ═══════════════════════════════════════════════════════════════════════════════
// Serpent framed vector: two chunks (push + finalize)
// ═══════════════════════════════════════════════════════════════════════════════

const scf1_key   = new Uint8Array(32); scf1_key.fill(0x04);
const scf1_nonce = new Uint8Array(16); scf1_nonce.fill(0xdd);
const scf1_pts = [new Uint8Array(200).fill(0x99), new Uint8Array(100).fill(0xaa)];

// Seal unframed with same nonce for comparison
const scf1_unframed = new SealStream(SerpentCipher, scf1_key, { chunkSize: 1024 }, scf1_nonce);
const scf1_uf_cts = [scf1_unframed.push(scf1_pts[0]), scf1_unframed.finalize(scf1_pts[1])];

// Seal framed
const scf1_sealer = new SealStream(SerpentCipher, scf1_key, { chunkSize: 1024, framed: true }, scf1_nonce);
const scf1_header = scf1_sealer.header;
const scf1_cts = [scf1_sealer.push(scf1_pts[0]), scf1_sealer.finalize(scf1_pts[1])];

// Verify framing is purely additive
for (let i = 0; i < 2; i++) {
	const expected = concat(u32be(scf1_uf_cts[i].length), scf1_uf_cts[i]);
	assert(hex(scf1_cts[i]) === hex(expected), `SCF1 chunk ${i} framing verify`);
}

// Round-trip
const scf1_opener = new OpenStream(SerpentCipher, scf1_key, scf1_header);
const scf1_dec0 = scf1_opener.pull(scf1_cts[0]);
const scf1_dec1 = scf1_opener.finalize(scf1_cts[1]);
assert(hex(scf1_dec0) === hex(scf1_pts[0]), 'SCF1 chunk 0 round-trip');
assert(hex(scf1_dec1) === hex(scf1_pts[1]), 'SCF1 chunk 1 round-trip');

console.log('SCF1: framed serpent verified');

// ═══════════════════════════════════════════════════════════════════════════════
// Write vector file
// ═══════════════════════════════════════════════════════════════════════════════

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
//
// SealStream v2 KAT vectors — STREAM construction.
//
// SELF-GENERATED — no external authority for these wire formats.
// Generated with fixed nonce seams, then each chunk independently verified
// against the underlying primitives (HKDF-SHA-256, HChaCha20, ChaCha20-Poly1305,
// SerpentCbc, HMAC-SHA-256). Vectors serve as regression trip-wires for wire
// format stability.
// Audit status: SELF-VERIFIED`;

const file = `${asciiHeader}

export interface SealStreamV2Vector {
\tdescription: string;
\tcipher: 'xchacha20' | 'serpent';
\tkey: string;
\tnonce: string;
\tchunkSize: number;
\tframed?: boolean;
\theader: string;
\tchunks: { plaintext: string; ciphertext: string }[];
}

export const xc1: SealStreamV2Vector = {
\tdescription: 'XC1: single-chunk, 0x01 key, 0xaa nonce, 100-byte 0xcd plaintext',
\tcipher: 'xchacha20',
\tkey: '${hex(xc1_key)}',
\tnonce: '${hex(xc1_nonce)}',
\tchunkSize: 1024,
\theader:
\t\t${splitHex(hex(xc1_header))},
\tchunks: [
\t\t{
\t\t\tplaintext: '${hex(xc1_pt)}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(xc1_ct0), '\t\t\t\t')},
\t\t},
\t],
};

export const xc3: SealStreamV2Vector = {
\tdescription: 'XC3: multi-chunk, sequential key, 0xf0+ nonce, varied plaintexts + empty finalize',
\tcipher: 'xchacha20',
\tkey: '${hex(xc3_key)}',
\tnonce: '${hex(xc3_nonce)}',
\tchunkSize: 1024,
\theader:
\t\t${splitHex(hex(xc3_header))},
\tchunks: [
${xc3_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(xc3_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};

export const sc1: SealStreamV2Vector = {
\tdescription: 'SC1: single-chunk, 0x02 key, 0xbb nonce, 100-byte 0xef plaintext',
\tcipher: 'serpent',
\tkey: '${hex(sc1_key)}',
\tnonce: '${hex(sc1_nonce)}',
\tchunkSize: 1024,
\theader:
\t\t${splitHex(hex(sc1_header))},
\tchunks: [
\t\t{
\t\t\tplaintext: '${hex(sc1_pt)}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(sc1_ct0), '\t\t\t\t')},
\t\t},
\t],
};

export const sc3: SealStreamV2Vector = {
\tdescription: 'SC3: multi-chunk, sequential key, 0xe0+ nonce, varied plaintexts + empty finalize',
\tcipher: 'serpent',
\tkey: '${hex(sc3_key)}',
\tnonce: '${hex(sc3_nonce)}',
\tchunkSize: 1024,
\theader:
\t\t${splitHex(hex(sc3_header))},
\tchunks: [
${sc3_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(sc3_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};

export const xcf1: SealStreamV2Vector = {
\tdescription: 'XCF1: framed xchacha20, 2 chunks (push + finalize)',
\tcipher: 'xchacha20',
\tkey: '${hex(xcf1_key)}',
\tnonce: '${hex(xcf1_nonce)}',
\tchunkSize: 1024,
\tframed: true,
\theader:
\t\t${splitHex(hex(xcf1_header))},
\tchunks: [
${xcf1_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(xcf1_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};

export const scf1: SealStreamV2Vector = {
\tdescription: 'SCF1: framed serpent, 2 chunks (push + finalize)',
\tcipher: 'serpent',
\tkey: '${hex(scf1_key)}',
\tnonce: '${hex(scf1_nonce)}',
\tchunkSize: 1024,
\tframed: true,
\theader:
\t\t${splitHex(hex(scf1_header))},
\tchunks: [
${scf1_cts.map((ct, i) => `\t\t{
\t\t\tplaintext: '${hex(scf1_pts[i])}',
\t\t\tciphertext:
\t\t\t\t${splitHex(hex(ct), '\t\t\t\t')},
\t\t},`).join('\n')}
\t],
};
`;

writeFileSync('test/vectors/sealstream_v2.ts', file);
console.log('Written test/vectors/sealstream_v2.ts');

hmac.dispose(); hkdf.dispose(); cbc.dispose();
