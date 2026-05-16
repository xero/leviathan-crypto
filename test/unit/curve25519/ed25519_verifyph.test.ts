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
 * Ed25519ph strict verify (RFC 8032 §5.1.7 prehash, FIPS 186-5 §7.6.4).
 *
 * SHA-512 of the message is computed in the TS test layer; the WASM
 * function takes the pre-computed digest. RFC 8032 §7.3 (TEST abc, 1
 * record) is the gate; ACVP sigVer prehash records (preHash === 'SHA-512')
 * follow with mixed pass / fail per testPassed.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
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

const PK_OFF     = testSlot(0);
const DIGEST_OFF = testSlot(64);
const CTX_OFF    = testSlot(192);
const SIG_OFF    = testSlot(448);

function runVerifyPh(pkHex: string, msgHex: string, ctxHex: string, sigHex: string): number {
	const msg = hexToBytes(msgHex);
	const ctx = hexToBytes(ctxHex);
	const digest = new Uint8Array(createHash('sha512').update(msg).digest());

	wasm.wipeBuffers();
	writeBytes(wasm.memory, PK_OFF,     hexToBytes(pkHex));
	writeBytes(wasm.memory, DIGEST_OFF, digest);
	writeBytes(wasm.memory, CTX_OFF,    ctx);
	writeBytes(wasm.memory, SIG_OFF,    hexToBytes(sigHex));

	return wasm.ed25519VerifyPrehashed(PK_OFF, DIGEST_OFF, CTX_OFF, ctx.length, SIG_OFF);
}

describe('ed25519 verify (prehash, Ed25519ph)', () => {
	// GATE: RFC 8032 §7.3 TEST abc must verify successfully.
	describe('RFC 8032 §7.3 prehash vector', () => {
		for (let i = 0; i < ed25519Vectors.length; i++) {
			const v = ed25519Vectors[i];
			if (v.mode !== 'ph') continue;
			it(`record ${i} (ph): verifyPrehashed returns 1`, () => {
				expect(runVerifyPh(v.pkHex, v.msgHex, v.ctxHex ?? '', v.sigHex)).toBe(1);
			});
		}
	});

	// ACVP sigVer prehash subset.
	describe('ACVP EDDSA sigVer (prehash)', () => {
		const phRecords = ed25519_sigver_all.filter(r => r.preHash === 'SHA-512');
		for (const r of phRecords) {
			it(`tcId ${r.tcId} (tgId ${r.tgId}, expect ${r.testPassed}, reason "${r.reason}")`, () => {
				const got = runVerifyPh(r.pk, r.message, r.context, r.signature);
				expect(got === 1).toBe(r.testPassed);
			});
		}
	});
});
