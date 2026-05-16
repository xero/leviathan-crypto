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
 * Ed25519ph sign (RFC 8032 §5.1.7 with dom2 phflag=1).
 *
 * SHA-512 of the message is computed OUTSIDE the WASM (Node `crypto`
 * module) since the WASM ABI accepts a pre-computed digest. RFC 8032
 * §7.3 (TEST abc, 1 record) is the gate; ACVP sigGen prehash records
 * (preHash === 'SHA-512') follow.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
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

const SEED_OFF   = testSlot(0);
const PK_OFF     = testSlot(64);
const DIGEST_OFF = testSlot(128);
const CTX_OFF    = testSlot(256);
const SIG_OFF    = testSlot(512);

function runSignPh(skHex: string, pkHex: string, msgHex: string, ctxHex: string, sigHex: string): void {
	const msg = hexToBytes(msgHex);
	const ctx = hexToBytes(ctxHex);
	const digest = new Uint8Array(createHash('sha512').update(msg).digest());

	wasm.wipeBuffers();
	writeBytes(wasm.memory, SEED_OFF,   hexToBytes(skHex));
	writeBytes(wasm.memory, PK_OFF,     hexToBytes(pkHex));
	writeBytes(wasm.memory, DIGEST_OFF, digest);
	writeBytes(wasm.memory, CTX_OFF,    ctx);

	wasm.ed25519SignPrehashed(SEED_OFF, PK_OFF, DIGEST_OFF, CTX_OFF, ctx.length, SIG_OFF);
	expect(bytesToHex(readBytes(wasm.memory, SIG_OFF, 64)).toUpperCase())
		.toBe(sigHex.toUpperCase());
}

describe('ed25519 sign (prehash, Ed25519ph)', () => {
	// GATE: RFC 8032 §7.3 TEST abc.
	describe('RFC 8032 §7.3 prehash vector', () => {
		for (let i = 0; i < ed25519Vectors.length; i++) {
			const v = ed25519Vectors[i];
			if (v.mode !== 'ph') continue;
			it(`record ${i} (ph): sign prehash`, () => {
				runSignPh(v.skHex, v.pkHex, v.msgHex, v.ctxHex ?? '', v.sigHex);
			});
		}
	});

	// ACVP sigGen prehash subset.
	describe('ACVP EDDSA sigGen (prehash)', () => {
		const phRecords = ed25519_siggen_all.filter(r => r.preHash === 'SHA-512');
		for (const r of phRecords) {
			it(`tcId ${r.tcId} (tgId ${r.tgId}, ctx ${r.context.length / 2} bytes): sign prehash`, () => {
				runSignPh(r.sk, r.pk, r.message, r.context, r.signature);
			});
		}
	});
});
