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

// ── CBC parsers (KAT, MMT, MCT — same record format with an extra IV) ──────

/** One row from a CAVP CBC `.rsp` ENCRYPT or DECRYPT section. */
export interface CbcKatVector {
	count: number;
	key:   string;  // hex
	iv:    string;  // hex (16 bytes)
	pt:    string;  // hex
	ct:    string;  // hex
}

/**
 * Parse a NIST CAVP AESVS CBC-style `.rsp` file. Same shape as the ECB
 * parser, but every record carries a 16-byte IV between KEY and PLAINTEXT.
 * Used by the CBC KAT, MMT, and MCT gates.
 */
export function parseCbcKatFile(filename: string): {
	encrypt: CbcKatVector[];
	decrypt: CbcKatVector[];
} {
	const text = readFileSync(resolve(VECTORS_DIR, filename), 'utf8');
	const encrypt: CbcKatVector[] = [];
	const decrypt: CbcKatVector[] = [];

	let section: 'ENCRYPT' | 'DECRYPT' | null = null;
	let cur: Partial<CbcKatVector> = {};

	const flush = () => {
		if (cur.count != null && cur.key != null && cur.iv != null && cur.pt != null && cur.ct != null) {
			const v = cur as CbcKatVector;
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
		case 'IV':         cur.iv    = val.toLowerCase(); break;
		case 'PLAINTEXT':  cur.pt    = val.toLowerCase(); break;
		case 'CIPHERTEXT': cur.ct    = val.toLowerCase(); break;
		default: break;
		}
	}
	flush();

	return { encrypt, decrypt };
}

/** Parse a CBC MMT file. Same format as KAT but PT/CT are multi-block (16..160 bytes). */
export function parseCbcMmtFile(filename: string): {
	encrypt: CbcKatVector[];
	decrypt: CbcKatVector[];
} {
	return parseCbcKatFile(filename);
}

/**
 * Parse a CBC MCT file. Each record is one chain seed; the runner re-
 * derives the inner-loop chain per AESAVS §6.4.2 and asserts the final
 * KEY / IV / PLAINTEXT / CIPHERTEXT against the next row.
 */
export function parseCbcMctFile(filename: string): {
	encrypt: CbcKatVector[];
	decrypt: CbcKatVector[];
} {
	return parseCbcKatFile(filename);
}

// ── GCMVS parser ────────────────────────────────────────────────────────────

/** One GCMVS record (encrypt direction). */
export interface GcmvsEncryptVector {
	count: number;
	keylen: number;
	ivlen: number;
	ptlen: number;
	aadlen: number;
	taglen: number;
	key:   string;
	iv:    string;
	pt:    string;
	aad:   string;
	ct:    string;
	tag:   string;
}

/** One GCMVS record (decrypt direction); `pt` is null on a FAIL vector. */
export interface GcmvsDecryptVector {
	count: number;
	keylen: number;
	ivlen: number;
	ptlen: number;
	aadlen: number;
	taglen: number;
	key:   string;
	iv:    string;
	ct:    string;
	aad:   string;
	tag:   string;
	fail:  boolean;
	pt:    string | null;
}

/**
 * Parse a GCMVS encrypt `.rsp` file (`aes_gcmEncryptExtIV{128,192,256}.rsp`).
 * Section headers are `[Keylen=N]` `[IVlen=N]` `[PTlen=N]` `[AADlen=N]`
 * `[Taglen=N]` blocks; each record is COUNT/Key/IV/PT/AAD/CT/Tag.
 */
export function parseGcmvsEncrypt(filename: string): GcmvsEncryptVector[] {
	const text = readFileSync(resolve(VECTORS_DIR, filename), 'utf8');
	const out: GcmvsEncryptVector[] = [];

	const section: { keylen: number; ivlen: number; ptlen: number; aadlen: number; taglen: number } = {
		keylen: 0, ivlen: 0, ptlen: 0, aadlen: 0, taglen: 0,
	};
	let cur: Partial<GcmvsEncryptVector> = {};

	const flush = () => {
		if (cur.count != null && cur.key != null && cur.iv != null && cur.tag != null) {
			out.push({
				count: cur.count!,
				keylen: section.keylen,
				ivlen: section.ivlen,
				ptlen: section.ptlen,
				aadlen: section.aadlen,
				taglen: section.taglen,
				key: cur.key!,
				iv: cur.iv!,
				pt: cur.pt ?? '',
				aad: cur.aad ?? '',
				ct: cur.ct ?? '',
				tag: cur.tag!,
			});
		}
		cur = {};
	};

	for (const rawLine of text.split('\n')) {
		const line = rawLine.replace(/\r$/, '').trim();
		if (line === '') {
			flush(); continue;
		}
		if (line.startsWith('#')) continue;
		if (line.startsWith('[') && line.endsWith(']')) {
			flush();
			const inner = line.slice(1, -1);
			const eq = inner.indexOf('=');
			if (eq < 0) continue;
			const k = inner.slice(0, eq).trim();
			const v = parseInt(inner.slice(eq + 1).trim(), 10);
			switch (k) {
			case 'Keylen': section.keylen = v; break;
			case 'IVlen':  section.ivlen  = v; break;
			case 'PTlen':  section.ptlen  = v; break;
			case 'AADlen': section.aadlen = v; break;
			case 'Taglen': section.taglen = v; break;
			}
			continue;
		}
		const eq = line.indexOf('=');
		if (eq < 0) continue;
		const k = line.slice(0, eq).trim();
		const v = line.slice(eq + 1).trim().toLowerCase();
		switch (k) {
		case 'Count': cur.count = parseInt(v, 10); break;
		case 'Key':   cur.key   = v; break;
		case 'IV':    cur.iv    = v; break;
		case 'PT':    cur.pt    = v; break;
		case 'AAD':   cur.aad   = v; break;
		case 'CT':    cur.ct    = v; break;
		case 'Tag':   cur.tag   = v; break;
		}
	}
	flush();

	return out;
}

/**
 * Parse a GCMVS decrypt `.rsp` file. Same record structure as the encrypt
 * parser, but a record may end with `FAIL` instead of a `PT = ...` line —
 * those vectors are negative tests where `open` must throw.
 *
 * Detection rule: when the next non-empty line after the last data field
 * (Tag) is the bare token `FAIL`, mark the vector as failing.
 */
export function parseGcmvsDecrypt(filename: string): GcmvsDecryptVector[] {
	const text = readFileSync(resolve(VECTORS_DIR, filename), 'utf8');
	const out: GcmvsDecryptVector[] = [];

	const section: { keylen: number; ivlen: number; ptlen: number; aadlen: number; taglen: number } = {
		keylen: 0, ivlen: 0, ptlen: 0, aadlen: 0, taglen: 0,
	};
	let cur: Partial<GcmvsDecryptVector> & { _fail?: boolean } = {};

	const flush = () => {
		if (cur.count != null && cur.key != null && cur.iv != null && cur.tag != null) {
			out.push({
				count: cur.count!,
				keylen: section.keylen,
				ivlen: section.ivlen,
				ptlen: section.ptlen,
				aadlen: section.aadlen,
				taglen: section.taglen,
				key: cur.key!,
				iv: cur.iv!,
				ct: cur.ct ?? '',
				aad: cur.aad ?? '',
				tag: cur.tag!,
				fail: !!cur._fail,
				pt: cur._fail ? null : (cur.pt ?? ''),
			});
		}
		cur = {};
	};

	for (const rawLine of text.split('\n')) {
		const line = rawLine.replace(/\r$/, '').trim();
		if (line === '') {
			flush(); continue;
		}
		if (line.startsWith('#')) continue;
		if (line.startsWith('[') && line.endsWith(']')) {
			flush();
			const inner = line.slice(1, -1);
			const eq = inner.indexOf('=');
			if (eq < 0) continue;
			const k = inner.slice(0, eq).trim();
			const v = parseInt(inner.slice(eq + 1).trim(), 10);
			switch (k) {
			case 'Keylen': section.keylen = v; break;
			case 'IVlen':  section.ivlen  = v; break;
			case 'PTlen':  section.ptlen  = v; break;
			case 'AADlen': section.aadlen = v; break;
			case 'Taglen': section.taglen = v; break;
			}
			continue;
		}
		if (line === 'FAIL') {
			cur._fail = true;
			continue;
		}
		const eq = line.indexOf('=');
		if (eq < 0) continue;
		const k = line.slice(0, eq).trim();
		const v = line.slice(eq + 1).trim().toLowerCase();
		switch (k) {
		case 'Count': cur.count = parseInt(v, 10); break;
		case 'Key':   cur.key   = v; break;
		case 'IV':    cur.iv    = v; break;
		case 'CT':    cur.ct    = v; break;
		case 'AAD':   cur.aad   = v; break;
		case 'Tag':   cur.tag   = v; break;
		case 'PT':    cur.pt    = v; break;
		}
	}
	flush();

	return out;
}
