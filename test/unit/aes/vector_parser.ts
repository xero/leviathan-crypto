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
// Parser for NIST CAVP AES Known-Answer Test (.rsp) files.
// Phase 2a: encrypt-only consumption; phase 2b extends with decrypt + MMT/MCT.

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
 * DECRYPT sections separately. Phase 2a uses only ENCRYPT.
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
