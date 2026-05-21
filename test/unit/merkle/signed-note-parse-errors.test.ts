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
// Rejection paths for `parseSignedNote`. The codec splits errors into
// two layers per c2sp.org/signed-note (Note) §Format and §Signatures:
//
//  - Whole-envelope structural defects (no blank separator, body missing
//    trailing newline, ASCII control bytes) throw RangeError. The
//    envelope is unrecoverable.
//  - Per-line malformations (no em-dash prefix, missing name, malformed
//    base64, base64 payload < 4 bytes) are counted in `ignoredCount`
//    and discarded per the §Signatures rule that "unknown signatures
//    MUST be ignored" rather than escalated to envelope-level rejection.
//
// This file covers the throw cases; signed-note-unknown-sig.test.ts
// covers the ignore-and-continue cases.

import { describe, it, expect } from 'vitest';
import {
	parseSignedNote,
	utf8ToBytes,
} from '../../../src/ts/index.js';

const VALID_BODY =
	'example.com/log\n'
	+ '1\n'
	+ 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n';

// Build a structurally valid signed-note envelope with a single
// signature line and an arbitrary 8-byte signature payload after the
// 4-byte key ID. `b64Payload` is the full base64 chunk (key ID +
// signature) appended after `— name `.
function envelope(body: string, name: string, b64Payload: string): Uint8Array {
	return utf8ToBytes(`${body}\n— ${name} ${b64Payload}\n`);
}

describe('parseSignedNote whole-envelope rejection paths', () => {
	it('throws on empty input', () => {
		expect(() => parseSignedNote(new Uint8Array(0))).toThrow(/empty input/);
	});

	it('throws on non-newline ASCII control byte (TAB inside body)', () => {
		const bad = new Uint8Array([
			0x61, 0x09, 0x0a,        // "a\t\n"
			0x0a,                    // blank separator
			0xe2, 0x80, 0x94, 0x20,  // em dash + space
			0x6b, 0x20, 0x41, 0x41, 0x41, 0x41, 0x0a,
		]);
		expect(() => parseSignedNote(bad)).toThrow(/control/);
	});

	it('throws on DEL (0x7F) inside envelope', () => {
		const bad = new Uint8Array([0x61, 0x7f, 0x0a, 0x0a, 0xe2, 0x80, 0x94, 0x20, 0x6b, 0x20, 0x41, 0x41, 0x41, 0x41, 0x0a]);
		expect(() => parseSignedNote(bad)).toThrow(/DEL|control/);
	});

	it('throws when no blank-line separator is present', () => {
		// Body without the empty separator line.
		const bad = utf8ToBytes(VALID_BODY + '— k AAAAAAAA\n');
		expect(() => parseSignedNote(bad)).toThrow(/blank-line separator|signature line/);
	});

	it('throws when no signature line follows the blank separator', () => {
		const bad = utf8ToBytes(VALID_BODY + '\n');
		expect(() => parseSignedNote(bad)).toThrow(/signature region is empty/);
	});

	it('throws when signature region does not end with a newline', () => {
		const bad = utf8ToBytes(VALID_BODY + '\n— k AAAAAAAA');
		expect(() => parseSignedNote(bad)).toThrow(/end with U\+000A|signature line/);
	});

	it('a blank line inside the signatures block re-anchors the separator (last blank wins)', () => {
		// Per c2sp.org/signed-note §Format: "the text is separated from
		// the signatures by the last empty line in the note." A blank
		// line that appears AFTER what looks like a signature line is
		// the real separator, so everything before it (including the
		// first em-dash line) is part of the body. Round-trip parse
		// returns the second signature and the body now contains what
		// the writer probably intended as the first signature.
		const bad = utf8ToBytes(VALID_BODY + '\n— k AAAAAAAA\n\n— k2 AAAAAAAA\n');
		const parsed = parseSignedNote(bad);
		expect(parsed.signatures.length).toBe(1);
		expect(parsed.signatures[0].name).toBe('k2');
	});
});

describe('parseSignedNote per-line ignored paths', () => {
	it('ignores a line missing the em-dash prefix', () => {
		// Line uses a hyphen-minus instead of U+2014 em dash.
		const env = utf8ToBytes(VALID_BODY + '\n- k AAAAAAAA\n');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line whose base64 payload decodes to fewer than 4 bytes', () => {
		// Base64 "AAA=" is 2 bytes decoded; no room for the 4-byte key ID.
		const env = envelope(VALID_BODY, 'k', 'AAA=');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line with malformed base64 (truncated, missing padding)', () => {
		const env = envelope(VALID_BODY, 'k', 'AAAAA');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line with invalid base64 characters', () => {
		const env = envelope(VALID_BODY, 'k', 'AAA!!!!!');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line with URL-safe base64 (uses - or _)', () => {
		// Per c2sp.org/signed-note §Conventions the base64 is the
		// RFC 4648 §4 standard alphabet; URL-safe is not a signed-note
		// payload and lines using it are spec-malformed.
		const env = envelope(VALID_BODY, 'k', 'AAA-AAA_AAAA');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line with an empty key name', () => {
		// The em-dash + space is immediately followed by a space,
		// leaving zero bytes for the name.
		const env = utf8ToBytes(VALID_BODY + '\n—  AAAAAAAA\n');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line with no space between name and base64', () => {
		const env = utf8ToBytes(VALID_BODY + '\n— kAAAAAAAA\n');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});

	it('ignores a line with plus in the name (signed-note grammar collision)', () => {
		const env = envelope(VALID_BODY, 'name+oops', 'AAAAAAAA');
		const parsed = parseSignedNote(env);
		expect(parsed.signatures.length).toBe(0);
		expect(parsed.ignoredCount).toBe(1);
	});
});
