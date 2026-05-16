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
 * Pure-mode Ed25519 strict verify (RFC 8032 §5.1.7 / FIPS 186-5 §7.6.4).
 * Two corpora are exercised:
 *
 * 1. RFC 8032 §7.1 pure records (4 records). Acts as the gate. Each
 *    record's `(pk, msg, sig)` must verify successfully.
 *
 * 2. ACVP EDDSA-SigVer-1.0 pure subset (5 records). Mixed pass / fail by
 *    the `testPassed` field. The WASM verify return value must match
 *    `testPassed` byte-for-byte; failure records exercise the strict-S
 *    check, the non-canonical-pk path, and other rejection conditions.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { ed25519Vectors } from '../../vectors/ed25519.js';
import { ed25519_sigver_all } from '../../vectors/ed25519_sigver.js';
import {
	loadCurve25519, hexToBytes, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

const PK_OFF  = testSlot(0);
const SIG_OFF = testSlot(64);
const MSG_OFF = testSlot(192);

function runVerify(pkHex: string, msgHex: string, sigHex: string): number {
	const msg = hexToBytes(msgHex);
	wasm.wipeBuffers();
	writeBytes(wasm.memory, PK_OFF,  hexToBytes(pkHex));
	writeBytes(wasm.memory, SIG_OFF, hexToBytes(sigHex));
	writeBytes(wasm.memory, MSG_OFF, msg);
	return wasm.ed25519Verify(PK_OFF, MSG_OFF, msg.length, SIG_OFF);
}

describe('ed25519 verify (pure)', () => {
	// GATE: RFC 8032 §7.1 pure records.
	describe('RFC 8032 §7.1 pure vectors', () => {
		for (let i = 0; i < ed25519Vectors.length; i++) {
			const v = ed25519Vectors[i];
			if (v.mode !== 'pure') continue;
			it(`record ${i}: verify returns 1`, () => {
				expect(runVerify(v.pkHex, v.msgHex, v.sigHex)).toBe(1);
			});
		}
	});

	// ACVP sigVer pure subset (preHash === null). Mixed pass/fail per testPassed.
	describe('ACVP EDDSA sigVer (pure)', () => {
		const pureRecords = ed25519_sigver_all.filter(r => r.preHash === null);
		for (const r of pureRecords) {
			it(`tcId ${r.tcId} (tgId ${r.tgId}, expect ${r.testPassed}, reason "${r.reason}")`, () => {
				const got = runVerify(r.pk, r.message, r.signature);
				expect(got === 1).toBe(r.testPassed);
			});
		}
	});
});
