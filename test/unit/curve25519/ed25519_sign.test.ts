//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒█▀▄ ▒█▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓ ▓ ▓ ▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ █ ▒ █
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
 * Pure-mode Ed25519 sign (RFC 8032 §5.1.6). Sign vectors must produce
 * the spec-stated signature byte-for-byte; verify cross-check confirms
 * the WASM verify path agrees with the WASM sign path.
 *
 * RFC 8032 §7.1 (4 pure records) runs first as the GATE. ACVP siggen
 * pure records (preHash === null) follow.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { ed25519Vectors } from '../../vectors/ed25519.js';
import { ed25519_siggen_all } from '../../vectors/ed25519_siggen.js';
import {
	loadCurve25519, hexToBytes, bytesToHex, readBytes, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

const SEED_OFF = testSlot(0);
const PK_OFF   = testSlot(64);
const SIG_OFF  = testSlot(128);
const MSG_OFF  = testSlot(256);

function runSignAndVerify(skHex: string, pkHex: string, msgHex: string, sigHex: string): void {
	const msg = hexToBytes(msgHex);
	wasm.wipeBuffers();
	writeBytes(wasm.memory, SEED_OFF, hexToBytes(skHex));
	writeBytes(wasm.memory, PK_OFF,   hexToBytes(pkHex));
	writeBytes(wasm.memory, MSG_OFF,  msg);

	wasm.ed25519Sign(SEED_OFF, PK_OFF, MSG_OFF, msg.length, SIG_OFF);
	expect(bytesToHex(readBytes(wasm.memory, SIG_OFF, 64)).toUpperCase())
		.toBe(sigHex.toUpperCase());

	// Cross-check: the just-produced signature must verify under the same pk.
	// Re-write pk + msg + sig in case the sign wiped any temp memory we'd
	// reuse (it doesn't touch caller buffers, but be explicit).
	writeBytes(wasm.memory, PK_OFF,  hexToBytes(pkHex));
	writeBytes(wasm.memory, MSG_OFF, msg);
	expect(wasm.ed25519Verify(PK_OFF, MSG_OFF, msg.length, SIG_OFF)).toBe(1);
}

describe('ed25519 sign (pure)', () => {
	// GATE: RFC 8032 §7.1 (4 pure records).
	describe('RFC 8032 §7.1 pure vectors', () => {
		for (let i = 0; i < ed25519Vectors.length; i++) {
			const v = ed25519Vectors[i];
			if (v.mode !== 'pure') continue;
			it(`record ${i}: sign + self-verify`, () => {
				runSignAndVerify(v.skHex, v.pkHex, v.msgHex, v.sigHex);
			});
		}
	});

	// ACVP EDDSA-SigGen-1.0 pure subset (preHash === null).
	describe('ACVP EDDSA sigGen (pure)', () => {
		const pureRecords = ed25519_siggen_all.filter(r => r.preHash === null);
		// Ed25519ctx (pure + non-empty ctx) is NOT a WASM export.
		// ACVP pure-mode corpus has uniformly-empty context, but
		// guard explicitly in case a record slipped in.
		for (const r of pureRecords) {
			it(`tcId ${r.tcId} (tgId ${r.tgId}): sign + self-verify`, () => {
				expect(r.context).toBe('');
				runSignAndVerify(r.sk, r.pk, r.message, r.signature);
			});
		}
	});
});
