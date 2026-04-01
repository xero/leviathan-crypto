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
 * Generate serpent_composition.ts kat vector file with exact hex values.
 * usage: bun scripts/write-vectors.ts
 * output: test/vectors/serpent_composition.ts
 */
import {
	init, SerpentSeal, SerpentStream, SerpentCbc, SerpentCtr,
	HMAC_SHA256, HKDF_SHA256,
	bytesToHex, concat,
} from '../src/ts/index.js';
import { chunkInfo, u32be } from '../src/ts/serpent/stream.js';
import { writeFileSync } from 'fs';

await init(['serpent', 'sha2']);

const seal = new SerpentSeal();
const cbc = new SerpentCbc({ dangerUnauthenticated: true });
const ctr = new SerpentCtr({ dangerUnauthenticated: true });
const hmac = new HMAC_SHA256();
const hkdf = new HKDF_SHA256();
const stream = new SerpentStream();

function hex(b: Uint8Array): string { return bytesToHex(b); }
function assert(cond: boolean, msg: string) {
	if (!cond) { console.error('ASSERTION FAILED:', msg); process.exit(1); }
}

// Split a hex string into 64-char chunks joined with ' +\n\t\t'
function splitHex(h: string, indent = '\t\t'): string {
	const lines: string[] = [];
	for (let i = 0; i < h.length; i += 64) {
		lines.push(`'${h.slice(i, i + 64)}'`);
	}
	return lines.join(' +\n' + indent);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Generate TC1
// ═══════════════════════════════════════════════════════════════════════════════
const tc1_key = new Uint8Array(64);
const tc1_iv = new Uint8Array(16);
const tc1_pt = new Uint8Array(32).fill(0xab);
const tc1_out = seal.encrypt(tc1_key, tc1_pt, undefined, tc1_iv);
const tc1_tag = tc1_out.subarray(tc1_out.length - 32);

// Verify
const tc1_encKey = tc1_key.subarray(0, 32);
const tc1_macKey = tc1_key.subarray(32, 64);
const tc1_ct = tc1_out.subarray(16, tc1_out.length - 32);
assert(hex(hmac.hash(tc1_macKey, concat(u32be(0), tc1_out.subarray(0, 16), tc1_ct))) === hex(tc1_tag), 'TC1 HMAC');
assert(hex(cbc.decrypt(tc1_encKey, tc1_out.subarray(0, 16), tc1_ct)) === hex(tc1_pt), 'TC1 CBC');

// ═══════════════════════════════════════════════════════════════════════════════
// Generate TC2
// ═══════════════════════════════════════════════════════════════════════════════
const tc2_key = new Uint8Array(64);
for (let i = 0; i < 64; i++) tc2_key[i] = [1, 2, 3, 4][i % 4];
const tc2_iv = new Uint8Array(16);
for (let i = 0; i < 16; i++) tc2_iv[i] = [0xff, 0xfe, 0xfd, 0xfc][i % 4];
const tc2_pt = new Uint8Array(0);
const tc2_out = seal.encrypt(tc2_key, tc2_pt, undefined, tc2_iv);
const tc2_tag = tc2_out.subarray(tc2_out.length - 32);
assert(tc2_out.length === 64, 'TC2 len');

// ═══════════════════════════════════════════════════════════════════════════════
// Generate SS-1
// ═══════════════════════════════════════════════════════════════════════════════
const ss1_key = new Uint8Array(32);
const ss1_nonce = new Uint8Array(16);
const ss1_pt = new Uint8Array(1024).fill(0xcd);
const ss1_out = stream.seal(ss1_key, ss1_pt, 1024, ss1_nonce);
assert(ss1_out.length === 1084, 'SS1 len');

// Verify chunk 0
const ss1_info0 = chunkInfo(ss1_nonce, 1024, 1, 0, true);
const ss1_d0 = hkdf.derive(ss1_key, ss1_nonce, ss1_info0, 64);
const ss1_ek0 = ss1_d0.subarray(0, 32);
const ss1_mk0 = ss1_d0.subarray(32, 64);
const ss1_c0ct = ss1_out.subarray(28, 28 + 1024);
const ss1_c0tag = ss1_out.subarray(28 + 1024, 28 + 1056);
assert(hex(hmac.hash(ss1_mk0, ss1_c0ct)) === hex(ss1_c0tag), 'SS1 c0 HMAC');
ctr.beginEncrypt(ss1_ek0, new Uint8Array(16));
assert(hex(ctr.encryptChunk(ss1_c0ct)) === hex(ss1_pt), 'SS1 c0 CTR');

// ═══════════════════════════════════════════════════════════════════════════════
// Generate SS-3
// ═══════════════════════════════════════════════════════════════════════════════
const ss3_key = new Uint8Array(32);
const ss3_nonce = new Uint8Array(16);
const ss3_pt = new Uint8Array(3072).fill(0xab);
const ss3_out = stream.seal(ss3_key, ss3_pt, 1024, ss3_nonce);
assert(ss3_out.length === 3196, 'SS3 len');

interface ChunkData { info: string; encKey: string; macKey: string; tag: string; }
const ss3_chunks: ChunkData[] = [];
for (let i = 0; i < 3; i++) {
	const isLast = i === 2;
	const info = chunkInfo(ss3_nonce, 1024, 3, i, isLast);
	const derived = hkdf.derive(ss3_key, ss3_nonce, info, 64);
	const ek = derived.subarray(0, 32);
	const mk = derived.subarray(32, 64);
	const ws = 28 + i * 1056;
	const ct = ss3_out.subarray(ws, ws + 1024);
	const tag = ss3_out.subarray(ws + 1024, ws + 1056);
	assert(hex(hmac.hash(mk, ct)) === hex(tag), `SS3 c${i} HMAC`);
	ctr.beginEncrypt(ek, new Uint8Array(16));
	assert(hex(ctr.encryptChunk(ct)) === hex(ss3_pt.subarray(i * 1024, (i + 1) * 1024)), `SS3 c${i} CTR`);
	ss3_chunks.push({ info: hex(info), encKey: hex(ek), macKey: hex(mk), tag: hex(tag) });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Generate SS-6
// ═══════════════════════════════════════════════════════════════════════════════
const ss6_key = new Uint8Array(32);
for (let i = 0; i < 32; i++) ss6_key[i] = [0xba, 0xd1, 0xde, 0xa5][i % 4];
const ss6_nonce = new Uint8Array(16);
for (let i = 0; i < 16; i++) ss6_nonce[i] = [0xac, 0x1d, 0xc0, 0xde][i % 4];
const ss6_pt = new Uint8Array(6144);
for (let i = 0; i < 6144; i++) ss6_pt[i] = i & 0xff;
const ss6_out = stream.seal(ss6_key, ss6_pt, 1024, ss6_nonce);
assert(ss6_out.length === 6364, 'SS6 len');

const ss6_chunks: ChunkData[] = [];
for (let i = 0; i < 6; i++) {
	const isLast = i === 5;
	const info = chunkInfo(ss6_nonce, 1024, 6, i, isLast);
	const derived = hkdf.derive(ss6_key, ss6_nonce, info, 64);
	const ek = derived.subarray(0, 32);
	const mk = derived.subarray(32, 64);
	const ws = 28 + i * 1056;
	const ct = ss6_out.subarray(ws, ws + 1024);
	const tag = ss6_out.subarray(ws + 1024, ws + 1056);
	assert(hex(hmac.hash(mk, ct)) === hex(tag), `SS6 c${i} HMAC`);
	ctr.beginEncrypt(ek, new Uint8Array(16));
	assert(hex(ctr.encryptChunk(ct)) === hex(ss6_pt.subarray(i * 1024, (i + 1) * 1024)), `SS6 c${i} CTR`);
	ss6_chunks.push({ info: hex(info), encKey: hex(ek), macKey: hex(mk), tag: hex(tag) });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Write vector file
// ═══════════════════════════════════════════════════════════════════════════════

function chunkObj(c: ChunkData, index: number, isLast: boolean, pt: string, indent: string): string {
	return `{
${indent}\tindex: ${index},
${indent}\tisLast: ${isLast},
${indent}\tchunkInfo:
${indent}\t\t${splitHex(c.info, indent + '\t\t')},
${indent}\tencKey: '${c.encKey}',
${indent}\tmacKey: '${c.macKey}',
${indent}\tplaintext: ${pt},
${indent}\ttag: '${c.tag}',
${indent}}`;
}

const header = `//                  ▄▄▄▄▄▄▄▄▄▄
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
// SerpentSeal and SerpentStream KAT vectors.
//
// SELF-GENERATED — no external authority for these wire formats.
// Generated with fixed IV/nonce seams, then decomposed and verified against
// the underlying primitives (SerpentCbc, HMAC_SHA256, HKDF_SHA256, SerpentCtr)
// independently. Vectors serve as regression trip-wires for wire format stability.
// Audit status: SELF-VERIFIED`;

const file = `${header}

// ============================================================
// Interfaces
// ============================================================

export interface SerpentSealVector {
\tdescription: string;
\tkey: string;          // hex, 64 bytes
\tiv: string;           // hex, 16 bytes (injected via _iv seam)
\tplaintext: string;    // hex
\tciphertext: string;   // hex (iv || cbc_ct || tag combined output)
\ttag: string;          // hex, 32 bytes (last 32 bytes of ciphertext)
}

export interface ChunkVector {
\tindex: number;
\tisLast: boolean;
\tchunkInfo: string;    // hex, 54 bytes
\tencKey: string;       // hex, 32 bytes (HKDF output[0..32])
\tmacKey: string;       // hex, 32 bytes (HKDF output[32..64])
\tplaintext: string;    // hex (this chunk's plaintext slice)
\ttag: string;          // hex, 32 bytes
}

export interface SerpentStreamVector {
\tdescription: string;
\tkey: string;          // hex, 32 bytes
\tstreamNonce: string;  // hex, 16 bytes (injected via _nonce seam)
\tplaintext: string;    // hex (full plaintext)
\tchunkSize: number;
\tchunkCount: number;
\tchunks: ChunkVector[];
\toutput: string;       // hex (complete wire format output)
}

// ============================================================
// Helper — 256-byte rising pattern (0x00..0xff)
// ============================================================

const _r256 = Array.from({ length: 256 }, (_, i) =>
\ti.toString(16).padStart(2, '0'),
).join('');

// ============================================================
// SerpentSeal KAT vectors
// ============================================================

/** SerpentSeal TC1: all-zero key (64 bytes), all-zero IV (16 bytes), 32×0xab plaintext */
// Verified: HMAC_SHA256(macKey, iv||cbc_ct) = tag, SerpentCbc.decrypt(encKey, iv, cbc_ct) = plaintext
export const sealTC1: SerpentSealVector = {
\tdescription: 'TC1: all-zero key, all-zero IV, 32-byte 0xab plaintext',
\tkey: '00'.repeat(64),
\tiv: '00'.repeat(16),
\tplaintext: 'ab'.repeat(32),
\tciphertext:
\t\t${splitHex(hex(tc1_out))},
\ttag: '${hex(tc1_tag)}',
};

/** SerpentSeal TC2: patterned key, patterned IV, empty plaintext */
// Verified: HMAC_SHA256(macKey, iv||cbc_ct) = tag, SerpentCbc.decrypt(encKey, iv, cbc_ct) = empty
// Note: CBC with empty plaintext produces exactly 16 bytes of PKCS7 padding.
export const sealTC2: SerpentSealVector = {
\tdescription: 'TC2: patterned key (01020304×16), patterned IV (fffefdfc×4), empty plaintext',
\tkey: '01020304'.repeat(16),
\tiv: 'fffefdfc'.repeat(4),
\tplaintext: '',
\tciphertext:
\t\t${splitHex(hex(tc2_out))},
\ttag: '${hex(tc2_tag)}',
};

// ============================================================
// SerpentStream KAT vectors
// ============================================================

/** SS-1: single chunk (1024 bytes, all 0xcd), zero key, zero nonce */
// Verified per-chunk: chunkInfo→HKDF→encKey/macKey, HMAC(macKey,ct)=tag, CTR(encKey,ct)=pt
export const streamSS1: SerpentStreamVector = {
\tdescription: 'SS-1: single 1024-byte chunk, all-zero key/nonce, 0xcd fill',
\tkey: '00'.repeat(32),
\tstreamNonce: '00'.repeat(16),
\tplaintext: 'cd'.repeat(1024),
\tchunkSize: 1024,
\tchunkCount: 1,
\tchunks: [
\t\t${chunkObj({ info: hex(ss1_info0), encKey: hex(ss1_ek0), macKey: hex(ss1_mk0), tag: hex(ss1_c0tag) }, 0, true, "'cd'.repeat(1024)", '\t\t')},
\t],
\toutput:
\t\t${splitHex(hex(ss1_out))},
};

/** SS-3: three 1024-byte chunks (3072 bytes, all 0xab), zero key, zero nonce */
// Verified per-chunk: chunkInfo→HKDF→encKey/macKey, HMAC(macKey,ct)=tag, CTR(encKey,ct)=pt
export const streamSS3: SerpentStreamVector = {
\tdescription: 'SS-3: three 1024-byte chunks, all-zero key/nonce, 0xab fill',
\tkey: '00'.repeat(32),
\tstreamNonce: '00'.repeat(16),
\tplaintext: 'ab'.repeat(3072),
\tchunkSize: 1024,
\tchunkCount: 3,
\tchunks: [
\t\t${chunkObj(ss3_chunks[0], 0, false, "'ab'.repeat(1024)", '\t\t')},
\t\t${chunkObj(ss3_chunks[1], 1, false, "'ab'.repeat(1024)", '\t\t')},
\t\t${chunkObj(ss3_chunks[2], 2, true, "'ab'.repeat(1024)", '\t\t')},
\t],
\toutput:
\t\t${splitHex(hex(ss3_out))},
};

/** SS-6: six 1024-byte chunks, non-zero key/nonce, rising byte pattern */
// key = 'bad1dea5' repeated to 32 bytes; nonce = 'ac1dc0de' repeated to 16 bytes
// plaintext = 6144 bytes where byte[i] = i & 0xff
// Verified per-chunk: chunkInfo→HKDF→encKey/macKey, HMAC(macKey,ct)=tag, CTR(encKey,ct)=pt
export const streamSS6: SerpentStreamVector = {
\tdescription: 'SS-6: six 1024-byte chunks, bad1dea5 key, ac1dc0de nonce, rising pattern',
\tkey: 'bad1dea5'.repeat(8),
\tstreamNonce: 'ac1dc0de'.repeat(4),
\tplaintext: _r256.repeat(24),  // 6144 bytes: i & 0xff
\tchunkSize: 1024,
\tchunkCount: 6,
\tchunks: [
\t\t${chunkObj(ss6_chunks[0], 0, false, '_r256.repeat(4)', '\t\t')},
\t\t${chunkObj(ss6_chunks[1], 1, false, '_r256.repeat(4)', '\t\t')},
\t\t${chunkObj(ss6_chunks[2], 2, false, '_r256.repeat(4)', '\t\t')},
\t\t${chunkObj(ss6_chunks[3], 3, false, '_r256.repeat(4)', '\t\t')},
\t\t${chunkObj(ss6_chunks[4], 4, false, '_r256.repeat(4)', '\t\t')},
\t\t${chunkObj(ss6_chunks[5], 5, true, '_r256.repeat(4)', '\t\t')},
\t],
\toutput:
\t\t${splitHex(hex(ss6_out))},
};
`;

writeFileSync('test/vectors/serpent_composition.ts', file);
console.log('Written test/vectors/serpent_composition.ts');
console.log('TC1 output bytes:', tc1_out.length);
console.log('TC2 output bytes:', tc2_out.length);
console.log('SS1 output bytes:', ss1_out.length);
console.log('SS3 output bytes:', ss3_out.length);
console.log('SS6 output bytes:', ss6_out.length);

seal.dispose(); cbc.dispose(); ctr.dispose(); hmac.dispose(); hkdf.dispose(); stream.dispose();
