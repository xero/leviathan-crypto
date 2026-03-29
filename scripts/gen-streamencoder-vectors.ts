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
 * Generate serpent_stream_encoder.ts KAT vector file.
 * usage: bun scripts/gen-streamencoder-vectors.ts
 * output: test/vectors/serpent_stream_encoder.ts
 */
import {
	init, SerpentStreamSealer, SerpentStreamOpener,
	bytesToHex, hexToBytes,
} from '../src/ts/index.js';
import { writeFileSync } from 'fs';

await init(['serpent', 'sha2']);

function hex(b: Uint8Array): string { return bytesToHex(b); }
function assert(cond: boolean, msg: string) {
	if (!cond) { console.error('ASSERTION FAILED:', msg); process.exit(1); }
}

function splitHex(h: string, indent = '\t\t'): string {
	const lines: string[] = [];
	for (let i = 0; i < h.length; i += 64) {
		lines.push(`'${h.slice(i, i + 64)}'`);
	}
	return lines.join(' +\n' + indent);
}

function makeIv(fill: number): Uint8Array { return new Uint8Array(16).fill(fill); }

interface VectorDef {
	name:        string;
	description: string;
	key:         Uint8Array;
	nonce:       Uint8Array;
	ivs:         Uint8Array[];
	chunkSize:   number;
	plaintexts:  Uint8Array[];   // last is encodeFinal
}

interface GeneratedVector {
	def:           VectorDef;
	headerHex:     string;
	encodedHexes:  string[];     // u32be(len) || sealed per chunk
}

function generateVector(def: VectorDef): GeneratedVector {
	const sealer = new SerpentStreamSealer(def.key, def.chunkSize, { framed: true }, def.nonce, def.ivs);
	const hdr    = sealer.header();

	const encodedHexes: string[] = [];
	for (let i = 0; i < def.plaintexts.length; i++) {
		const isLast = i === def.plaintexts.length - 1;
		const encoded = isLast
			? sealer.final(def.plaintexts[i])
			: sealer.seal(def.plaintexts[i]);
		encodedHexes.push(hex(encoded));
	}

	// Verify round-trip: concatenate all encoded chunks, feed to opener at once
	const allEncoded = hexToBytes(encodedHexes.join(''));
	const opener1  = new SerpentStreamOpener(def.key, hdr, { framed: true });
	const results1 = opener1.feed(allEncoded);
	assert(results1.length === def.plaintexts.length,
		`${def.name} single-feed: expected ${def.plaintexts.length} results, got ${results1.length}`);
	for (let i = 0; i < results1.length; i++) {
		assert(hex(results1[i]) === hex(def.plaintexts[i]),
			`${def.name} single-feed chunk ${i} plaintext mismatch`);
	}

	// Verify byte-at-a-time feed
	const opener2  = new SerpentStreamOpener(def.key, hdr, { framed: true });
	const results2: Uint8Array[] = [];
	for (let i = 0; i < allEncoded.length; i++) {
		const out = opener2.feed(allEncoded.subarray(i, i + 1));
		results2.push(...out);
	}
	assert(results2.length === def.plaintexts.length,
		`${def.name} byte-at-a-time: expected ${def.plaintexts.length} results, got ${results2.length}`);
	for (let i = 0; i < results2.length; i++) {
		assert(hex(results2[i]) === hex(def.plaintexts[i]),
			`${def.name} byte-at-a-time chunk ${i} plaintext mismatch`);
	}

	// Verify each encoded chunk has correct u32be length prefix
	for (let i = 0; i < encodedHexes.length; i++) {
		const encoded = hexToBytes(encodedHexes[i]);
		const prefixLen = (encoded[0] << 24 | encoded[1] << 16 | encoded[2] << 8 | encoded[3]) >>> 0;
		assert(prefixLen === encoded.length - 4,
			`${def.name} chunk ${i} length prefix mismatch: ${prefixLen} vs ${encoded.length - 4}`);
	}

	return { def, headerHex: hex(hdr), encodedHexes };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SE1: single encodeFinal chunk
// ═══════════════════════════════════════════════════════════════════════════════

const se1 = generateVector({
	name: 'SE1',
	description: 'SE1: all-zero key/nonce, chunkSize=1024, single encodeFinal(ab×1024)',
	key: new Uint8Array(64),
	nonce: new Uint8Array(16),
	ivs: [makeIv(0xaa)],
	chunkSize: 1024,
	plaintexts: [new Uint8Array(1024).fill(0xab)],
});

// ═══════════════════════════════════════════════════════════════════════════════
// SE2: three chunks — encode, encode, encodeFinal(half)
// ═══════════════════════════════════════════════════════════════════════════════

const se2 = generateVector({
	name: 'SE2',
	description: 'SE2: all-zero key/nonce, chunkSize=1024, encode(ab×1024)+encode(cd×1024)+encodeFinal(ef×512)',
	key: new Uint8Array(64),
	nonce: new Uint8Array(16),
	ivs: [makeIv(0xbb), makeIv(0xcc), makeIv(0xdd)],
	chunkSize: 1024,
	plaintexts: [
		new Uint8Array(1024).fill(0xab),
		new Uint8Array(1024).fill(0xcd),
		new Uint8Array(512).fill(0xef),
	],
});

// ═══════════════════════════════════════════════════════════════════════════════
// SE3: two chunks, non-zero key/nonce, rising pattern
// ═══════════════════════════════════════════════════════════════════════════════

const se3_key = new Uint8Array(64);
for (let i = 0; i < 64; i++) se3_key[i] = [0xde, 0xad, 0xbe, 0xef][i % 4];
const se3_nonce = new Uint8Array(16);
for (let i = 0; i < 16; i++) se3_nonce[i] = [0xca, 0xfe, 0xba, 0xbe][i % 4];
const se3_pt0 = new Uint8Array(4096);
for (let i = 0; i < 4096; i++) se3_pt0[i] = i & 0xff;
const se3_pt1 = new Uint8Array(4096);
for (let i = 0; i < 4096; i++) se3_pt1[i] = i & 0xff;

const se3 = generateVector({
	name: 'SE3',
	description: 'SE3: deadbeef key, cafebabe nonce, chunkSize=4096, encode(i&0xff×4096)+encodeFinal(i&0xff×4096)',
	key: se3_key,
	nonce: se3_nonce,
	ivs: [makeIv(0xee), makeIv(0xff)],
	chunkSize: 4096,
	plaintexts: [se3_pt0, se3_pt1],
});

// ═══════════════════════════════════════════════════════════════════════════════
// Write vector file
// ═══════════════════════════════════════════════════════════════════════════════

const fileHeader = `//                  ▄▄▄▄▄▄▄▄▄▄
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
// test/vectors/serpent_stream_encoder.ts
//
// Known-answer vectors for SerpentStreamSealer({ framed: true }) / SerpentStreamOpener({ framed: true }).
// Generated via scripts/gen-streamencoder-vectors.ts using the _nonce/_ivs test seams.
// Verified by round-trip through SerpentStreamOpener.feed() (single feed + byte-at-a-time).`;

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
	lines.push(`\tencodedChunks: [`);
	for (const c of v.encodedHexes) {
		lines.push(`\t\t${splitHex(c)},`);
	}
	lines.push(`\t],`);
	return lines.join('\n');
}

const file = `${fileHeader}

export interface StreamEncoderVector {
\tdescription:    string;
\tkey:            string;    // hex, 64 bytes
\tnonce:          string;    // hex, 16 bytes
\tivs:            string[];  // hex, 16 bytes each
\tchunkSize:      number;
\tplaintexts:     string[];  // hex, one per chunk (last is encodeFinal)
\theader:         string;    // hex, 20 bytes
\tencodedChunks:  string[];  // hex — u32be(len) || sealed_chunk per entry
}

export const SE1: StreamEncoderVector = {
${vectorBlock(se1)}
};

export const SE2: StreamEncoderVector = {
${vectorBlock(se2)}
};

export const SE3: StreamEncoderVector = {
${vectorBlock(se3)}
};
`;

writeFileSync('test/vectors/serpent_stream_encoder.ts', file);
console.log('Written test/vectors/serpent_stream_encoder.ts');
console.log('SE1 chunks:', se1.encodedHexes.length, '  header:', se1.headerHex);
console.log('SE2 chunks:', se2.encodedHexes.length, '  header:', se2.headerHex);
console.log('SE3 chunks:', se3.encodedHexes.length, '  header:', se3.headerHex);
