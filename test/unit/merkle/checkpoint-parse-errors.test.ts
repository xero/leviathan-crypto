//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒ ▄▀▄ █▀▄
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
// Rejection paths for `parseCheckpointBody` and `serializeCheckpointBody`,
// covering the MUST-level structural constraints from
// c2sp.org/tlog-checkpoint (Transparency Log Checkpoints) §Note text:
// non-empty origin, no whitespace or plus in origin, exactly three
// newline-terminated lines, decimal tree size with no leading zeroes,
// standard-alphabet base64 root hash of the expected length.

import { describe, it, expect } from 'vitest';
import {
	serializeCheckpointBody,
	parseCheckpointBody,
	utf8ToBytes,
	base64ToBytes,
} from '../../../src/ts/index.js';

const validRootB64 = 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=';
const validRoot    = base64ToBytes(validRootB64);

describe('serializeCheckpointBody rejection paths', () => {
	it('throws on empty origin', () => {
		expect(() => serializeCheckpointBody({
			origin: '', treeSize: 1, rootHash: validRoot,
		})).toThrow(/non-empty/);
	});

	it('throws on origin with embedded newline', () => {
		expect(() => serializeCheckpointBody({
			origin: 'example.com/log\nwithnewline', treeSize: 1, rootHash: validRoot,
		})).toThrow(/whitespace|plus/);
	});

	it('throws on origin with ASCII space', () => {
		expect(() => serializeCheckpointBody({
			origin: 'example.com/log with space', treeSize: 1, rootHash: validRoot,
		})).toThrow(/whitespace|plus/);
	});

	it('throws on origin with plus character', () => {
		// Plus is the field separator in verifier-key encoding per
		// c2sp.org/signed-note §Verifier keys; reusing it inside an
		// origin would collide with that grammar.
		expect(() => serializeCheckpointBody({
			origin: 'example.com/log+oops', treeSize: 1, rootHash: validRoot,
		})).toThrow(/plus/);
	});

	it('throws on negative tree size', () => {
		expect(() => serializeCheckpointBody({
			origin: 'example.com/log', treeSize: -1, rootHash: validRoot,
		})).toThrow(/non-negative/);
	});

	it('throws on non-integer tree size', () => {
		expect(() => serializeCheckpointBody({
			origin: 'example.com/log', treeSize: 1.5, rootHash: validRoot,
		})).toThrow(/non-negative/);
	});

	it('throws on tree size above MAX_SAFE_INTEGER', () => {
		expect(() => serializeCheckpointBody({
			origin: 'example.com/log', treeSize: Number.MAX_SAFE_INTEGER + 1, rootHash: validRoot,
		})).toThrow(/non-negative/);
	});
});

describe('parseCheckpointBody rejection paths', () => {
	it('throws on empty input', () => {
		expect(() => parseCheckpointBody(new Uint8Array(0))).toThrow(/empty/);
	});

	it('throws when body does not end with U+000A', () => {
		const bad = utf8ToBytes('example.com/log\n1\n' + validRootB64);
		expect(() => parseCheckpointBody(bad)).toThrow(/must end with U\+000A/);
	});

	it('throws on extension lines (4 newline-terminated lines)', () => {
		const bad = utf8ToBytes(
			'example.com/log\n'
			+ '1\n'
			+ validRootB64 + '\n'
			+ 'extension-line-not-allowed\n',
		);
		expect(() => parseCheckpointBody(bad)).toThrow(/exactly 3 lines/);
	});

	it('throws on fewer than 3 lines', () => {
		const bad = utf8ToBytes('example.com/log\n1\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/exactly 3 lines/);
	});

	it('throws on empty origin line', () => {
		const bad = utf8ToBytes('\n1\n' + validRootB64 + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/empty origin/);
	});

	it('throws on origin with embedded space', () => {
		const bad = utf8ToBytes('example.com/log with space\n1\n' + validRootB64 + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/whitespace|space or plus/);
	});

	it('throws on tree size with leading zero', () => {
		const bad = utf8ToBytes('example.com/log\n01\n' + validRootB64 + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/leading zero/);
	});

	it('throws on tree size with non-digit characters', () => {
		const bad = utf8ToBytes('example.com/log\n1a\n' + validRootB64 + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/not ASCII decimal/);
	});

	it('throws on URL-safe base64 root hash', () => {
		// Use URL-safe variant (- and _) which the codec rejects per
		// c2sp.org/tlog-checkpoint §Conventions (standard alphabet only).
		const url = 'CsUYapGGPo4dkMgIAUqom_Xajj7h2fB2MPA3j2jxq2I=';
		const bad = utf8ToBytes('example.com/log\n1\n' + url + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/URL-safe base64/);
	});

	it('throws on padding-stripped base64 root hash', () => {
		// Standard alphabet but no padding; not RFC 4648 §4 compliant
		// when total length is not a multiple of 4.
		const noPad = 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I';
		const bad = utf8ToBytes('example.com/log\n1\n' + noPad + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/padding missing/);
	});

	it('throws on base64 root hash of wrong decoded length', () => {
		// 31 bytes base64, will not match expectedHashLen=32.
		const shortB64 = 'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxqw==';
		const bad = utf8ToBytes('example.com/log\n1\n' + shortB64 + '\n');
		expect(() => parseCheckpointBody(bad)).toThrow(/root hash length/);
	});

	it('throws on non-newline ASCII control byte inside body', () => {
		// Insert a tab inside the origin line.
		const bytes = new Uint8Array([
			...utf8ToBytes('example.com/log'),
			0x09, // TAB
			...utf8ToBytes('rest\n1\n' + validRootB64 + '\n'),
		]);
		expect(() => parseCheckpointBody(bytes)).toThrow(/control/);
	});

	it('accepts a tree-size 0 body, matching the spec literal-zero clause', () => {
		const ok = utf8ToBytes('example.com/log\n0\n' + validRootB64 + '\n');
		const parsed = parseCheckpointBody(ok);
		expect(parsed.treeSize).toBe(0);
	});
});
