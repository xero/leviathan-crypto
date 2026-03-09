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
// test/vitest/vector_parser.ts
//
// Parsers for AES submission vector file formats.
// Adapted from sources/leviathan/test/helpers/vectors.ts and
// sources/leviathan/test/helpers/nessie.ts — same logic, different paths.

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '../../vectors');

export function readVector(name: string): string {
	return readFileSync(resolve(VECTORS_DIR, name), 'utf8');
}

// ── Byte utilities ────────────────────────────────────────────────────────────

export function hex2bytes(hex: string): Uint8Array {
	const h = hex.replace(/\s/g, '').toLowerCase();
	const arr = new Uint8Array(h.length / 2);
	for (let i = 0; i < arr.length; i++) {
		arr[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
	}
	return arr;
}

export function bytes2hex(arr: Uint8Array): string {
	return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── KAT vector types ──────────────────────────────────────────────────────────

export interface KatVector {
  keysize: number
  key: string    // hex
  pt: string     // hex
  ct: string     // hex
}

// ── Parser: serpent_ecb_vt.txt — Variable Text KAT ───────────────────────────────
/**
 * parseVt — parse floppy4/serpent_ecb_vt.txt (and serpent_ecb_tbl.txt, same format)
 *
 * Format: AES submission variable-text KAT format
 *   KEYSIZE=<N>                — key size in bits (128, 192, or 256)
 *   KEY=<hex>                  — key value (shared for all I= entries in block)
 *   I=<n>                      — entry index
 *   PT=<hex>                   — plaintext
 *   CT=<hex>                   — expected ciphertext
 * Returns: Array of { keysize, key, pt, ct } (all hex strings, lowercase)
 */
// Format: KEYSIZE=N  KEY=hex  (per-entry: I=n  PT=hex  CT=hex)

export function parseVt(text: string): KatVector[] {
	const vectors: KatVector[] = [];
	const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
	let keysize = 0;
	let key = '';
	for (let li = 0; li < lines.length; li++) {
		const t = lines[li];
		if (t.startsWith('KEYSIZE=')) {
			keysize = parseInt(t.slice(8)); continue;
		}
		if (t.startsWith('KEY=')) {
			key = t.slice(4).toLowerCase(); continue;
		}
		if (t.startsWith('I=')) {
			let ptLine = '', ctLine = '';
			for (let j = li + 1; j < li + 5 && j < lines.length; j++) {
				if (!ptLine && lines[j].startsWith('PT=')) ptLine = lines[j];
				if (!ctLine && lines[j].startsWith('CT=')) ctLine = lines[j];
				if (ptLine && ctLine) break;
			}
			if (ptLine && ctLine) {
				vectors.push({ keysize, key, pt: ptLine.slice(3).toLowerCase(), ct: ctLine.slice(3).toLowerCase() });
			}
		}
	}
	return vectors;
}

// ── Parser: serpent_ecb_vk.txt — Variable Key KAT ────────────────────────────────
/**
 * parseVk — parse floppy4/serpent_ecb_vk.txt
 *
 * Format: AES submission variable-key KAT format
 *   KEYSIZE=<N>                — key size in bits
 *   PT=<hex>                   — plaintext (shared for all I= entries in block)
 *   I=<n>                      — entry index
 *   KEY=<hex>                  — key value
 *   CT=<hex>                   — expected ciphertext
 * Returns: Array of { keysize, key, pt, ct } (all hex strings, lowercase)
 */
// Format: KEYSIZE=N  PT=hex  (per-entry: I=n  KEY=hex  CT=hex)

export function parseVk(text: string): KatVector[] {
	const vectors: KatVector[] = [];
	const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
	let keysize = 0;
	let pt = '';
	for (let li = 0; li < lines.length; li++) {
		const t = lines[li];
		if (t.startsWith('KEYSIZE=')) {
			keysize = parseInt(t.slice(8)); continue;
		}
		if (t.startsWith('PT=')) {
			pt = t.slice(3).toLowerCase(); continue;
		}
		if (t.startsWith('I=')) {
			let keyLine = '', ctLine = '';
			for (let j = li + 1; j < li + 5 && j < lines.length; j++) {
				if (!keyLine && lines[j].startsWith('KEY=')) keyLine = lines[j];
				if (!ctLine && lines[j].startsWith('CT=')) ctLine = lines[j];
				if (keyLine && ctLine) break;
			}
			if (keyLine && ctLine) {
				vectors.push({ keysize, key: keyLine.slice(4).toLowerCase(), pt, ct: ctLine.slice(3).toLowerCase() });
			}
		}
	}
	return vectors;
}

// serpent_ecb_tbl.txt uses the same format as serpent_ecb_vt.txt
export const parseTblFile = (name: string) => parseVt(readVector(name));
export const parseVtFile  = (name: string) => parseVt(readVector(name));
export const parseVkFile  = (name: string) => parseVk(readVector(name));

// ── Parser: serpent_ecb_iv.txt — Intermediate Values ─────────────────────────────────
/**
 * parseIv — parse floppy4/serpent_ecb_iv.txt
 *
 * Format: AES submission intermediate value format
 *   KEYSIZE=<N>                — begins a new key-size block
 *   KEY=<hex>                  — key value
 *   LONG_KEY=<hex>             — padded 256-bit key used by cipher
 *   SK[<i>]=<hex>              — bitslice subkey i (i = 0..32)
 *   SK^[<i>]=<hex>             — conventional subkey i (IP-permuted, not used)
 *   PT=<hex>                   — plaintext
 *   R[<i>]=<hex>               — round output i (bitslice representation)
 *   CT=<hex>                   — final ciphertext
 * Returns: Array of IvTestCase (one per key size)
 * Note: SK[i] in file is printed word-reversed (X3|X2|X1|X0).
 *       See serpent_iv.test.ts extractSubkeyHex() for the reversal.
 */

export interface IvTestCase {
  keysize: number
  key: string
  longKey: string
  sk: string[]       // bitslice subkeys SK[0..32]
  skHat: string[]    // conventional subkeys SK^[0..32]
  pt: string
  r: string[]        // R[0..31] round outputs
  ct: string
}

export function parseIv(text: string): IvTestCase[] {
	const cases: IvTestCase[] = [];
	let keysize = 0;
	let current: Partial<IvTestCase> | null = null;
	const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));

	function flush() {
		if (current?.pt && current.ct && current.sk) {
			cases.push(current as IvTestCase);
		}
		current = null;
	}

	for (const t of lines) {
		if (t.startsWith('KEYSIZE=')) {
			flush();
			keysize = parseInt(t.slice(8));
		} else if (t.startsWith('KEY=') && !t.startsWith('KEYSIZE=')) {
			flush();
			current = { keysize, key: t.slice(4).toLowerCase(), sk: [], skHat: [], r: [], longKey: '' };
		} else if (current) {
			if (t.startsWith('LONG_KEY=')) {
				current.longKey = t.slice(9).toLowerCase();
			} else if (/^SK\[(\d+)\]=/.test(t)) {
				const m = t.match(/^SK\[(\d+)\]=(.+)$/);
				if (m) current.sk![parseInt(m[1])] = m[2].toLowerCase();
			} else if (/^SK\^\[(\d+)\]=/.test(t)) {
				const m = t.match(/^SK\^\[(\d+)\]=(.+)$/);
				if (m) current.skHat![parseInt(m[1])] = m[2].toLowerCase();
			} else if (t.startsWith('PT=')) {
				if (!current.pt) current.pt = t.slice(3).toLowerCase();
			} else if (/^R\[(\d+)\]=/.test(t)) {
				if (!current.ct) {
					const m = t.match(/^R\[(\d+)\]=(.+)$/);
					if (m) current.r![parseInt(m[1])] = m[2].toLowerCase();
				}
			} else if (t.startsWith('CT=') && !current.ct) {
				current.ct = t.slice(3).toLowerCase();
			}
		}
	}
	flush();
	return cases;
}

export const parseIvFile = (name: string) => parseIv(readVector(name));

// ── Parser: Monte Carlo ECB ───────────────────────────────────────────────────
/**
 * parseMcEcbEncrypt / parseMcEcbDecrypt — parse floppy4/serpent_ecb_e_m.txt, serpent_ecb_d_m.txt
 *
 * Format: AES submission Monte Carlo ECB format
 *   KEYSIZE=<N>                — key size block (128, 192, or 256)
 *   I=<n>                      — outer iteration index (0..399 per key size)
 *   KEY=<hex>                  — starting key for this outer iteration
 *   PT=<hex>                   — starting plaintext (encrypt) or CT=<hex> (decrypt)
 *   CT=<hex>                   — expected final ciphertext after 10,000 inner ops
 * Decrypt file (serpent_ecb_d_m.txt): CT appears before PT in each entry.
 * Returns: Array of { keysize, idx, key, pt, ct }
 */

export interface McEcbVector {
  keysize: number
  idx: number
  key: string
  pt: string
  ct: string
}

function parseMcEcbInner(text: string, ctBeforePt: boolean): McEcbVector[] {
	const vectors: McEcbVector[] = [];
	const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
	let keysize = 0;
	for (let li = 0; li < lines.length; li++) {
		const t = lines[li];
		if (t.startsWith('KEYSIZE=')) {
			keysize = parseInt(t.slice(8)); continue;
		}
		if (t.startsWith('I=')) {
			const idx = parseInt(t.slice(2));
			const fields: string[] = [];
			for (let j = li + 1; j < lines.length && fields.length < 3; j++) {
				if (lines[j]) fields.push(lines[j]);
			}
			if (fields.length < 3) continue;
			const keyLine = fields[0];
			const f1 = fields[ctBeforePt ? 2 : 1];
			const f2 = fields[ctBeforePt ? 1 : 2];
			if (keyLine.startsWith('KEY=') && f1.startsWith('PT=') && f2.startsWith('CT=')) {
				vectors.push({
					keysize, idx,
					key: keyLine.slice(4).toLowerCase(),
					pt: f1.slice(3).toLowerCase(),
					ct: f2.slice(3).toLowerCase(),
				});
			}
		}
	}
	return vectors;
}

export const parseMcEcbEncrypt = (text: string) => parseMcEcbInner(text, false);
export const parseMcEcbDecrypt = (text: string) => parseMcEcbInner(text, true);
export const parseMcEcbEncryptFile = (name: string) => parseMcEcbEncrypt(readVector(name));
export const parseMcEcbDecryptFile = (name: string) => parseMcEcbDecrypt(readVector(name));

// ── Parser: Monte Carlo CBC ───────────────────────────────────────────────────
/**
 * parseMcCbcEncrypt / parseMcCbcDecrypt — parse floppy4/serpent_cbc_e_m.txt, serpent_cbc_d_m.txt
 *
 * Format: AES submission Monte Carlo CBC format — same as ECB but with an IV field:
 *   KEYSIZE=<N>                — key size block (128, 192, or 256)
 *   I=<n>                      — outer iteration index
 *   KEY=<hex>                  — starting key
 *   IV=<hex>                   — starting IV
 *   PT=<hex>                   — starting plaintext (encrypt) or CT=<hex> (decrypt)
 *   CT=<hex>                   — expected final ciphertext (encrypt)
 * Decrypt file (serpent_cbc_d_m.txt): CT appears before PT.
 * Returns: Array of { keysize, idx, key, iv, pt, ct }
 */

export interface McCbcVector {
  keysize: number
  idx:     number
  key:     string
  iv:      string
  pt:      string
  ct:      string
}

function parseMcCbcInner(text: string, ctBeforePt: boolean): McCbcVector[] {
	const vectors: McCbcVector[] = [];
	const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
	let keysize = 0;
	for (let li = 0; li < lines.length; li++) {
		const t = lines[li];
		if (t.startsWith('KEYSIZE=')) {
			keysize = parseInt(t.slice(8)); continue;
		}
		if (t.startsWith('I=')) {
			const idx = parseInt(t.slice(2));
			const fields: string[] = [];
			for (let j = li + 1; j < lines.length && fields.length < 4; j++) {
				if (lines[j]) fields.push(lines[j]);
			}
			if (fields.length < 4) continue;
			const keyLine = fields[0];
			const ivLine  = fields[1];
			const f2 = fields[ctBeforePt ? 3 : 2];
			const f3 = fields[ctBeforePt ? 2 : 3];
			if (keyLine.startsWith('KEY=') && ivLine.startsWith('IV=') &&
          f2.startsWith('PT=') && f3.startsWith('CT=')) {
				vectors.push({
					keysize, idx,
					key: keyLine.slice(4).toLowerCase(),
					iv: ivLine.slice(3).toLowerCase(),
					pt: f2.slice(3).toLowerCase(),
					ct: f3.slice(3).toLowerCase(),
				});
			}
		}
	}
	return vectors;
}

export const parseMcCbcEncrypt = (text: string) => parseMcCbcInner(text, false);
export const parseMcCbcDecrypt = (text: string) => parseMcCbcInner(text, true);
export const parseMcCbcEncryptFile = (name: string) => parseMcCbcEncrypt(readVector(name));
export const parseMcCbcDecryptFile = (name: string) => parseMcCbcDecrypt(readVector(name));

// ── NESSIE parser ─────────────────────────────────────────────────────────────
/**
 * parseNessieVectors — parse NESSIE Serpent test vector files
 *
 * Format: NESSIE project format
 *   Set <N>, vector#  <i>:     — begins a vector entry
 *   key=<hex>                  — key (may span 2 lines for 256-bit keys)
 *   plain=<hex>                — plaintext
 *   cipher=<hex>               — ciphertext
 *   decrypted=<hex>            — round-trip plaintext (Sets 1-4, from decrypt)
 *   encrypted=<hex>            — round-trip ciphertext (Sets 5-8, from encrypt)
 *   Iterated N times=<hex>     — iterated output (ignored by parser)
 * Note: 256-bit keys are split across two lines in the file. The parser
 *   handles this via the awaitingKeyLine2 state flag.
 * Returns: Array of NessieVector
 *
 * Preprocessing: NESSIE uses big-endian byte order. Use prepareNessieKey /
 *   prepareNessiePlaintext / prepareNessieCiphertext to convert before use.
 */

export interface NessieVector {
  set: string
  num: number
  key: string     // 64 uppercase hex chars (256-bit)
  plain: string   // 32 uppercase hex chars
  cipher: string  // 32 uppercase hex chars
  roundTrip: string
  hasEncryptedField: boolean
}

export function parseNessieVectors(text: string): NessieVector[] {
	const vectors: NessieVector[] = [];
	const lines = text.split(/\r?\n/);
	let current: Partial<NessieVector> | null = null;
	let keyPart1: string | null = null;
	let awaitingKeyLine2 = false;

	const finalize = () => {
		if (current && current.key && current.plain && current.cipher && current.roundTrip !== undefined) {
			vectors.push(current as NessieVector);
		}
		current = null;
		keyPart1 = null;
		awaitingKeyLine2 = false;
	};

	for (const line of lines) {
		const trimmed = line.trim();
		const setMatch = trimmed.match(/^(Set \d+), vector#\s*(\d+):$/);
		if (setMatch) {
			finalize();
			current = { set: setMatch[1], num: parseInt(setMatch[2], 10), hasEncryptedField: false };
			continue;
		}
		if (!current) continue;
		if (trimmed.startsWith('key=')) {
			keyPart1 = trimmed.slice(4).replace(/\s/g, '').toUpperCase();
			awaitingKeyLine2 = true;
			continue;
		}
		if (awaitingKeyLine2) {
			if (trimmed.length > 0 && /^[0-9A-Fa-f]+$/.test(trimmed)) {
				current.key = keyPart1! + trimmed.toUpperCase();
				awaitingKeyLine2 = false;
				continue;
			} else {
				current.key = keyPart1!;
				awaitingKeyLine2 = false;
			}
		}
		if (trimmed.startsWith('plain='))     {
			current.plain = trimmed.slice(6).toUpperCase(); continue;
		}
		if (trimmed.startsWith('cipher='))    {
			current.cipher = trimmed.slice(7).toUpperCase(); continue;
		}
		if (trimmed.startsWith('decrypted=')) {
			current.roundTrip = trimmed.slice(10).toUpperCase(); current.hasEncryptedField = false; continue;
		}
		if (trimmed.startsWith('encrypted=')) {
			current.roundTrip = trimmed.slice(10).toUpperCase(); current.hasEncryptedField = true; continue;
		}
	}
	finalize();
	return vectors;
}

export const parseNessieFile = (name: string) => parseNessieVectors(readVector(name));

// ── NESSIE preprocessing ──────────────────────────────────────────────────────
// The correct leviathan-specific preprocessing is: REVERSE ALL BYTES.
// Same transform works for key, plaintext, and ciphertext (it is its own inverse).
// Source: sources/leviathan/test/helpers/nessie.ts

function reverseAll(bytes: Uint8Array): Uint8Array {
	const out = new Uint8Array(bytes.length);
	for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
	return out;
}

export const prepareNessieKey        = (hexKey: string): Uint8Array => reverseAll(hex2bytes(hexKey));
export const prepareNessiePlaintext  = (hexPT: string): Uint8Array  => reverseAll(hex2bytes(hexPT));
export const prepareNessieCiphertext = (hexCT: string): Uint8Array  => reverseAll(hex2bytes(hexCT));
