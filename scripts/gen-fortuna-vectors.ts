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
 * Generate Fortuna pluggable-primitive KAT vectors.
 *
 * SELF-GENERATED — no external authority for these wire formats. Generated with
 * a deterministic entropy seed and msPerReseed: 0, then independently verified
 * against the underlying primitives. Vectors serve as regression trip-wires for
 * Fortuna's pluggable-primitive output stability.
 *
 * usage: bunx tsx scripts/gen-fortuna-vectors.ts
 * output: test/vectors/fortuna_kat.ts
 */
import { init, Fortuna, bytesToHex } from '../src/ts/index.js';
import { SerpentGenerator } from '../src/ts/serpent/index.js';
import { ChaCha20Generator } from '../src/ts/chacha20/index.js';
import { SHA256Hash } from '../src/ts/sha2/index.js';
import { SHA3_256Hash } from '../src/ts/sha3/index.js';
import { serpentWasm } from '../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../src/ts/sha3/embedded.js';
import type { Generator, HashFn } from '../src/ts/types.js';
import { writeFileSync } from 'fs';

await init({ serpent: serpentWasm, chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm });

function hex(b: Uint8Array): string { return bytesToHex(b); }

const combinations: {
	name: string;
	exportName: string;
	generator: Generator;
	generatorName: 'serpent' | 'chacha20';
	hash: HashFn;
	hashName: 'sha2' | 'sha3';
	index: number;
}[] = [
	{ name: 'Serpent + SHA-256',  exportName: 'serpent_sha2',  generator: SerpentGenerator,  generatorName: 'serpent',  hash: SHA256Hash,   hashName: 'sha2', index: 0 },
	{ name: 'Serpent + SHA3-256', exportName: 'serpent_sha3',  generator: SerpentGenerator,  generatorName: 'serpent',  hash: SHA3_256Hash, hashName: 'sha3', index: 1 },
	{ name: 'ChaCha20 + SHA-256', exportName: 'chacha20_sha2', generator: ChaCha20Generator, generatorName: 'chacha20', hash: SHA256Hash,   hashName: 'sha2', index: 2 },
	{ name: 'ChaCha20 + SHA3-256',exportName: 'chacha20_sha3', generator: ChaCha20Generator, generatorName: 'chacha20', hash: SHA3_256Hash, hashName: 'sha3', index: 3 },
];

interface Record {
	exportName: string;
	description: string;
	generator: 'serpent' | 'chacha20';
	hash: 'sha2' | 'sha3';
	entropySeed: string;
	genKeyAfterCreate: string;
	firstGet32: string;
}

const records: Record[] = [];

for (const combo of combinations) {
	// Deterministic entropy: 64 bytes of repeated (index + 1)
	const entropy = new Uint8Array(64).fill(combo.index + 1);

	const f = await Fortuna._createDeterministicForTesting({
		generator: combo.generator,
		hash: combo.hash,
		entropy,
	});

	const genKeyAfterCreate = hex(f._getGenKey());
	const firstGet32 = hex(f.get(32));
	f.stop();

	// Independent cross-verification — recompute the expected genKey and
	// firstGet32 directly from the underlying primitives, without going through
	// Fortuna. This converts the script from snapshot-writer to snapshot+verifier
	// so the SELF-VERIFIED label is honest. The construction follows
	// _createDeterministicForTesting + reseed + pseudoRandomData:
	//   pool0_after_addEvent = hash.digest(zeros(32) || u32_le(0) || entropy)
	//   genKey_after_reseed  = hash.digest(zeros(32) || pool0_after_addEvent)
	//   firstGet32           = generator.generate(genKey_after_reseed, counter=1, 32)
	const pool0Input = new Uint8Array(32 + 4 + entropy.length);
	// pool0Input layout: zeros(32) chain || u32_le(0) eventId || entropy
	pool0Input.set(entropy, 32 + 4);
	const pool0After = combo.hash.digest(pool0Input);

	const reseedInput = new Uint8Array(32 + pool0After.length);
	// reseedInput layout: zeros(32) prior genKey || pool0After seed
	reseedInput.set(pool0After, 32);
	const expectedGenKey = combo.hash.digest(reseedInput);

	const counter = new Uint8Array(combo.generator.counterSize);
	counter[0] = 1; // reseed() runs incrementCounter once
	const expectedFirstGet32 = combo.generator.generate(expectedGenKey, counter, 32);

	if (hex(expectedGenKey) !== genKeyAfterCreate)
		throw new Error(`${combo.name}: genKey mismatch — implementation diverges from primitive composition`);
	if (hex(expectedFirstGet32) !== firstGet32)
		throw new Error(`${combo.name}: firstGet32 mismatch — implementation diverges from primitive composition`);

	records.push({
		exportName: combo.exportName,
		description: combo.name,
		generator: combo.generatorName,
		hash: combo.hashName,
		entropySeed: hex(entropy),
		genKeyAfterCreate,
		firstGet32,
	});

	console.log(`${combo.name}: cross-verified ✓ genKey=${genKeyAfterCreate.slice(0, 16)}... firstGet32=${firstGet32.slice(0, 16)}...`);
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
//
// test/vectors/fortuna_kat.ts
//
// Fortuna pluggable-primitive KAT vectors.
//
// SELF-GENERATED — no external authority for these wire formats. Generated with
// a deterministic entropy seed and msPerReseed: 0, then independently verified
// against the underlying primitives. Vectors serve as regression trip-wires for
// Fortuna's pluggable-primitive output stability.
// Audit status: SELF-VERIFIED`;

const vectorBlocks = records.map(r => `export const ${r.exportName}: FortunaVector = {
\tdescription: '${r.description}',
\tgenerator: '${r.generator}',
\thash: '${r.hash}',
\tentropySeed: '${r.entropySeed}',
\tgenKeyAfterCreate: '${r.genKeyAfterCreate}',
\tfirstGet32: '${r.firstGet32}',
};`).join('\n\n');

const file = `${asciiHeader}

export interface FortunaVector {
\tdescription: string;
\tgenerator: 'serpent' | 'chacha20';
\thash: 'sha2' | 'sha3';
\tentropySeed: string;        // hex, 64 bytes of repeated byte pattern
\tgenKeyAfterCreate: string;  // hex, length matches generator.keySize
\tfirstGet32: string;         // hex, 32 bytes from get(32) after create
}

${vectorBlocks}
`;

writeFileSync('test/vectors/fortuna_kat.ts', file);
console.log('Written test/vectors/fortuna_kat.ts');
