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
// test/unit/aes/vector_parser.ts
//
// Parser for NIST CAVP AESVS ECB-mode `.rsp` files. Returns ENCRYPT and
// DECRYPT sections separately. Used by the KAT, MMT, and MCT gates: all
// three test types share the same record structure (COUNT / KEY /
// PLAINTEXT / CIPHERTEXT, blank-line separated, [ENCRYPT] / [DECRYPT]
// section markers); only the byte lengths differ.
//   • KAT — single-block PT/CT (16 bytes).
//   • MMT — variable-length PT/CT (1..10 blocks of 16 bytes).
//   • MCT — single-block PT/CT, 100 chains per direction; each row is
//          one chain's seed (cipher-derived per AESAVS §6.4.1).

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '../../vectors');

/** One row from a CAVP `.rsp` ENCRYPT or DECRYPT section. */
export interface KatVector {
	count: number;
	key:   string;  // hex
	pt:    string;  // hex
	ct:    string;  // hex
}

/**
 * Parse a NIST CAVP AESVS ECB-style `.rsp` file. Returns the ENCRYPT and
 * DECRYPT sections separately. Used by all three ECB gate types.
 *
 * Format (from CAVS 11.1 `.rsp` files in `test/vectors/`):
 *   # comment lines start with '#'
 *   blank lines separate records
 *   [ENCRYPT] / [DECRYPT] section markers
 *   COUNT = <decimal>
 *   KEY = <hex>
 *   PLAINTEXT = <hex>
 *   CIPHERTEXT = <hex>
 */
export function parseEcbKatFile(filename: string): {
	encrypt: KatVector[];
	decrypt: KatVector[];
} {
	const text = readFileSync(resolve(VECTORS_DIR, filename), 'utf8');
	const encrypt: KatVector[] = [];
	const decrypt: KatVector[] = [];

	let section: 'ENCRYPT' | 'DECRYPT' | null = null;
	let cur: Partial<KatVector> = {};

	const flush = () => {
		if (cur.count != null && cur.key != null && cur.pt != null && cur.ct != null) {
			const v = cur as KatVector;
			if (section === 'ENCRYPT') encrypt.push(v);
			else if (section === 'DECRYPT') decrypt.push(v);
		}
		cur = {};
	};

	for (const rawLine of text.split('\n')) {
		const line = rawLine.replace(/\r$/, '').trim();
		if (line === '') {
			flush();
			continue;
		}
		if (line.startsWith('#')) continue;
		if (line === '[ENCRYPT]') {
			flush();
			section = 'ENCRYPT';
			continue;
		}
		if (line === '[DECRYPT]') {
			flush();
			section = 'DECRYPT';
			continue;
		}
		const eq = line.indexOf('=');
		if (eq < 0) continue;
		const key = line.slice(0, eq).trim();
		const val = line.slice(eq + 1).trim();
		switch (key) {
		case 'COUNT':      cur.count = parseInt(val, 10); break;
		case 'KEY':        cur.key   = val.toLowerCase(); break;
		case 'PLAINTEXT':  cur.pt    = val.toLowerCase(); break;
		case 'CIPHERTEXT': cur.ct    = val.toLowerCase(); break;
		default: break;  // unrecognized field — ignore.
		}
	}
	flush();

	return { encrypt, decrypt };
}

/**
 * Parse an AESVS Multi-block Message Test (`aes_ECBMMT*.rsp`) file. Same
 * record structure as the KAT files; PT/CT are 1..10 blocks long
 * (i * 16 bytes for i ∈ [1, 10]).
 */
export function parseEcbMmtFile(filename: string): {
	encrypt: KatVector[];
	decrypt: KatVector[];
} {
	return parseEcbKatFile(filename);
}

/**
 * Parse an AESVS Monte Carlo Test (`aes_ECBMCT*.rsp`) file. Same record
 * structure as the KAT files. Each section contains 100 chain seeds; the
 * test runner re-derives KEY[i+1] / PT[i+1] per AESAVS §6.4.1 and asserts
 * each row's KEY / PLAINTEXT / CIPHERTEXT.
 */
export function parseEcbMctFile(filename: string): {
	encrypt: KatVector[];
	decrypt: KatVector[];
} {
	return parseEcbKatFile(filename);
}
