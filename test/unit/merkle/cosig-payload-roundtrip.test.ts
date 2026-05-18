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
// Round-trip coverage for the c2sp.org/tlog-cosignature §Format
// `timestamped_signature` payload codec
// (`emitCosigSignaturePayload` / `parseCosigSignaturePayload`).
// Every record asserts that `parse(emit(ts, sig))` recovers the
// input `(ts, sig)` byte-for-byte and that `emit` produces the
// exact recorded `payloadHex` bytes. Sigsizes 64 (Ed25519) and
// 2420 (ML-DSA-44) both ride through unchanged because the codec
// only handles the 8-byte BE timestamp prefix and is content-
// agnostic over the signature suffix.

import { describe, it, expect } from 'vitest';
import {
	emitCosigSignaturePayload,
	parseCosigSignaturePayload,
	hexToBytes,
	bytesToHex,
} from '../../../src/ts/index.js';
import { COSIG_PAYLOAD_RECORDS } from '../../vectors/cosig_payload.js';

describe('Cosig signature payload codec, c2sp.org/tlog-cosignature §Format', () => {
	for (const rec of COSIG_PAYLOAD_RECORDS) {
		const sigSize = rec.suite === 'ed25519' ? 64 : 2420;

		it(`emit produces the recorded payload bytes: ${rec.desc}`, () => {
			const sig = hexToBytes(rec.sigHex);
			expect(sig.length).toBe(sigSize);
			const payload = emitCosigSignaturePayload(rec.timestamp, sig);
			expect(bytesToHex(payload)).toBe(rec.payloadHex);
			expect(payload.length).toBe(8 + sigSize);
		});

		it(`parse recovers the (timestamp, sig) pair: ${rec.desc}`, () => {
			const payload = hexToBytes(rec.payloadHex);
			const parsed = parseCosigSignaturePayload(payload, sigSize);
			expect(parsed.timestamp).toBe(rec.timestamp);
			expect(bytesToHex(parsed.signature)).toBe(rec.sigHex);
			expect(parsed.signature.length).toBe(sigSize);
		});

		it(`round-trip emit then parse: ${rec.desc}`, () => {
			const sig = hexToBytes(rec.sigHex);
			const payload = emitCosigSignaturePayload(rec.timestamp, sig);
			const parsed = parseCosigSignaturePayload(payload, sigSize);
			expect(parsed.timestamp).toBe(rec.timestamp);
			expect(parsed.signature).toEqual(sig);
		});

		it(`round-trip parse then emit: ${rec.desc}`, () => {
			const original = hexToBytes(rec.payloadHex);
			const parsed = parseCosigSignaturePayload(original, sigSize);
			// Materialize the parsed signature into an owned buffer; subarray
			// would share storage with `original` and make the equality check
			// trivially true.
			const sigOwned = new Uint8Array(parsed.signature);
			const reemitted = emitCosigSignaturePayload(parsed.timestamp, sigOwned);
			expect(reemitted).toEqual(original);
		});
	}
});
