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
 * Generate serpent_stream_sealer.ts KAT vector file.
 * usage: bun scripts/gen-sealstream-vectors.ts
 * output: test/vectors/serpent_stream_sealer.ts
 */
import {
	init, SerpentStreamSealer, SerpentStreamOpener,
	SerpentCbc, HMAC_SHA256, HKDF_SHA256,
	bytesToHex, hexToBytes, concat,
} from '../src/ts/index.js';
import { u32be, u64be } from '../src/ts/serpent/stream.js';
import { writeFileSync } from 'fs';

await init(['serpent', 'sha2']);

const cbc  = new SerpentCbc({ dangerUnauthenticated: true });
const hmac = new HMAC_SHA256();
const hkdf = new HKDF_SHA256();

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

// HKDF chunkInfo for sealstream — 50 bytes
const DOMAIN = 'serpent-sealstream-v1';
const DOMAIN_BYTES = new TextEncoder().encode(DOMAIN); // 21 bytes

function sealstreamChunkInfo(
	streamNonce: Uint8Array,
	chunkSize:   number,
	index:       number,
	isLast:      boolean,
): Uint8Array {
	const info = new Uint8Array(50);
	let off = 0;
	info.set(DOMAIN_BYTES, off); off += 21;
	info.set(streamNonce,  off); off += 16;
	info.set(u32be(chunkSize), off); off += 4;
	info.set(u64be(index), off); off += 8;
	info[off] = isLast ? 0x01 : 0x00;
	return info;
}

interface VectorDef {
	name:        string;
	description: string;
	key:         Uint8Array;
	nonce:       Uint8Array;
	ivs:         Uint8Array[];   // one fixed IV per chunk (deterministic output)
	chunkSize:   number;
	plaintexts:  Uint8Array[];   // one per chunk; last is final()
}

interface GeneratedVector {
	def:          VectorDef;
	headerHex:    string;
	chunkHexes:   string[];
}

function generateVector(def: VectorDef): GeneratedVector {
	const sealer = new SerpentStreamSealer(def.key, def.chunkSize, undefined, def.nonce, def.ivs);
	const hdr    = sealer.header();

	const chunkHexes: string[] = [];
	for (let i = 0; i < def.plaintexts.length; i++) {
		const isLast = i === def.plaintexts.length - 1;
		const chunk  = isLast
			? sealer.final(def.plaintexts[i])
			: sealer.seal(def.plaintexts[i]);
		chunkHexes.push(hex(chunk));
	}

	// Verify each chunk independently
	for (let i = 0; i < def.plaintexts.length; i++) {
		const isLast = i === def.plaintexts.length - 1;
		const info   = sealstreamChunkInfo(def.nonce, def.chunkSize, i, isLast);
		const derived = hkdf.derive(def.key, new Uint8Array(0), info, 64);
		const encKey  = derived.subarray(0, 32);
		const macKey  = derived.subarray(32, 64);
		const chunkBytes = hexToBytes(chunkHexes[i]);
		// New format: isLast(1) || IV(16) || ciphertext || tag(32)
		const iv   = chunkBytes.subarray(1, 17);
		const ct   = chunkBytes.subarray(17, chunkBytes.length - 32);
		const tag  = chunkBytes.subarray(chunkBytes.length - 32);
		// Verify HMAC — empty AAD = u32be(0) prefix
		const expectedTag = hmac.hash(macKey, concat(u32be(0), iv, ct));
		assert(hex(tag) === hex(expectedTag), `${def.name} chunk ${i} HMAC mismatch`);
		// Verify CBC decrypt
		const pt = cbc.decrypt(encKey, iv, ct);
		assert(hex(pt) === hex(def.plaintexts[i]), `${def.name} chunk ${i} plaintext mismatch`);
	}

	// Verify opener round-trip
	const opener = new SerpentStreamOpener(def.key, hdr);
	for (let i = 0; i < chunkHexes.length; i++) {
		const pt = opener.open(hexToBytes(chunkHexes[i]));
		assert(hex(pt) === hex(def.plaintexts[i]), `${def.name} opener chunk ${i} mismatch`);
	}

	return { def, headerHex: hex(hdr), chunkHexes };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SS1: single final() chunk
// ═══════════════════════════════════════════════════════════════════════════════
// Deterministic IVs — simple patterns for reproducibility
function makeIv(fill: number): Uint8Array { return new Uint8Array(16).fill(fill); }

const ss1 = generateVector({
	name: 'SS1',
	description: 'SS1: all-zero key/nonce, chunkSize=1024, single final(ab×1024)',
	key: new Uint8Array(64),
	nonce: new Uint8Array(16),
	ivs: [makeIv(0x11)],
	chunkSize: 1024,
	plaintexts: [new Uint8Array(1024).fill(0xab)],
});

// ═══════════════════════════════════════════════════════════════════════════════
// SS2: three chunks — seal, seal, final(half)
// ═══════════════════════════════════════════════════════════════════════════════
const ss2 = generateVector({
	name: 'SS2',
	description: 'SS2: all-zero key/nonce, chunkSize=1024, seal(ab×1024)+seal(cd×1024)+final(ef×512)',
	key: new Uint8Array(64),
	nonce: new Uint8Array(16),
	ivs: [makeIv(0x22), makeIv(0x33), makeIv(0x44)],
	chunkSize: 1024,
	plaintexts: [
		new Uint8Array(1024).fill(0xab),
		new Uint8Array(1024).fill(0xcd),
		new Uint8Array(512).fill(0xef),
	],
});

// ═══════════════════════════════════════════════════════════════════════════════
// SS3: two chunks, non-zero key/nonce, rising pattern
// ═══════════════════════════════════════════════════════════════════════════════
const ss3_key = new Uint8Array(64);
for (let i = 0; i < 64; i++) ss3_key[i] = [0xde, 0xad, 0xbe, 0xef][i % 4];
const ss3_nonce = new Uint8Array(16);
for (let i = 0; i < 16; i++) ss3_nonce[i] = [0xca, 0xfe, 0xba, 0xbe][i % 4];
const ss3_pt0 = new Uint8Array(4096);
for (let i = 0; i < 4096; i++) ss3_pt0[i] = i & 0xff;
const ss3_pt1 = new Uint8Array(4096);
for (let i = 0; i < 4096; i++) ss3_pt1[i] = i & 0xff;

const ss3 = generateVector({
	name: 'SS3',
	description: 'SS3: deadbeef key, cafebabe nonce, chunkSize=4096, seal(i&0xff×4096)+final(i&0xff×4096)',
	key: ss3_key,
	nonce: ss3_nonce,
	ivs: [makeIv(0x55), makeIv(0x66)],
	chunkSize: 4096,
	plaintexts: [ss3_pt0, ss3_pt1],
});

// ═══════════════════════════════════════════════════════════════════════════════
// Write vector file
// ═══════════════════════════════════════════════════════════════════════════════

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
// SELF-GENERATED
// test/vectors/serpent_stream_sealer.ts
//
// Known-answer vectors for SerpentStreamSealer / SerpentStreamOpener.
// Generated via scripts/gen-sealstream-vectors.ts using the _nonce test seam.
// Verified by independent decomposition against SerpentCbc + HMAC_SHA256 + HKDF_SHA256.`;

function vectorBlock(v: GeneratedVector): string {
	const ptHexes = v.def.plaintexts.map(p => splitHex(hex(p)));
	const lines: string[] = [];
	lines.push(`\tdescription: '${v.def.description}',`);
	lines.push(`\tkey: '${hex(v.def.key)}',`);
	lines.push(`\tnonce: '${hex(v.def.nonce)}',`);
	lines.push(`\tivs: [${v.def.ivs.map(iv => `'${hex(iv)}'`).join(', ')}],`);
	lines.push(`\tchunkSize: ${v.def.chunkSize},`);
	lines.push(`\tplaintexts: [`);
	for (const p of ptHexes) {
		lines.push(`\t\t${p},`);
	}
	lines.push(`\t],`);
	lines.push(`\theader: '${v.headerHex}',`);
	lines.push(`\tcipherChunks: [`);
	for (const c of v.chunkHexes) {
		lines.push(`\t\t${splitHex(c)},`);
	}
	lines.push(`\t],`);
	return lines.join('\n');
}

const file = `${header}

export interface SealStreamVector {
\tdescription:  string;
\tkey:          string;   // hex, 64 bytes
\tnonce:        string;   // hex, 16 bytes (injected via _nonce seam)
\tivs:          string[]; // hex, 16 bytes each (injected via _ivs seam)
\tchunkSize:    number;
\tplaintexts:   string[]; // hex, one per chunk (last entry is the final chunk)
\theader:       string;   // hex, 20 bytes
\tcipherChunks: string[]; // hex, one per chunk
}

export const SS1: SealStreamVector = {
${vectorBlock(ss1)}
};

export const SS2: SealStreamVector = {
${vectorBlock(ss2)}
};

export const SS3: SealStreamVector = {
${vectorBlock(ss3)}
};
`;

writeFileSync('test/vectors/serpent_stream_sealer.ts', file);
console.log('Written test/vectors/serpent_stream_sealer.ts');
console.log('SS1 chunks:', ss1.chunkHexes.length, '  header:', ss1.headerHex);
console.log('SS2 chunks:', ss2.chunkHexes.length, '  header:', ss2.headerHex);
console.log('SS3 chunks:', ss3.chunkHexes.length, '  header:', ss3.headerHex);

cbc.dispose(); hmac.dispose(); hkdf.dispose();
