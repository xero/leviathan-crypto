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
// Verify-failure paths for `SignedLog.verifyCheckpoint`. Each case
// is the explicit security property the cosignature wire format
// defends: forged-key signatures don't validate, tampered bodies
// don't validate, tampered timestamps don't validate (timestamp is
// signed alongside the body), tampered sigs don't validate,
// cross-log envelopes don't validate (origin mismatch), and
// non-matching keyIds suppress the line entirely so the verifier
// doesn't even reach the signature check.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	hexToBytes,
	utf8ToBytes,
	SignedLog,
	Sha256Tree,
	MemoryStorage,
	Ed25519Suite,
	parseSignedNote,
	emitSignedNote,
	parseCosigSignaturePayload,
	emitCosigSignaturePayload,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { Ed25519 } from '../../../src/ts/ed25519/index.js';
import { signSthEd25519Vectors } from '../../vectors/sign_sth_ed25519.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const sha2 = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	const ed25519 = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	await init({ sha2, ed25519 });
});

function buildLog(
	v: typeof signSthEd25519Vectors[number],
	overrides?: { origin?: string; sk?: Uint8Array; pk?: Uint8Array },
): SignedLog<typeof Ed25519Suite> {
	const tree = new Sha256Tree(new MemoryStorage());
	for (const leaf of v.leaves) tree.append(utf8ToBytes(leaf));
	return new SignedLog({
		tree,
		suite: Ed25519Suite,
		origin: overrides?.origin ?? v.origin,
		signingKey: overrides?.sk ?? hexToBytes(v.skHex),
		pubkey: overrides?.pk ?? hexToBytes(v.pkHex),
	});
}

function tamperBit(bytes: Uint8Array, byteIndex: number, bitMask: number): Uint8Array {
	const out = bytes.slice();
	out[byteIndex] ^= bitMask;
	return out;
}

describe('SignedLog.verifyCheckpoint failure paths', () => {
	it('returns false on a forged signature from a different key (sig invalid for our pubkey)', () => {
		// Security property: a third party who can produce envelopes
		// with a valid timestamped_signature struct under their OWN
		// key cannot pass them off as ours, because deriveKeyId
		// commits to our origin || algoByte || pubkey.
		const v = signSthEd25519Vectors[0];

		// Build a SignedLog for our (origin, pk_v).
		const ourLog = buildLog(v);
		// Fake attacker key: a fresh Ed25519 keypair under our origin.
		const ed = new Ed25519();
		let forgedPk: Uint8Array;
		let forgedSk: Uint8Array;
		try {
			const kp = ed.keygenDerand(new Uint8Array(32).fill(0xab));
			forgedPk = kp.publicKey;
			forgedSk = kp.secretKey;
		} finally {
			ed.dispose();
		}
		// Attacker builds a SignedLog with the SAME origin but their key.
		const attackerLog = buildLog(v, { sk: forgedSk, pk: forgedPk });
		try {
			const forgedEnv = attackerLog.signCheckpoint({ timestamp: v.timestamp });
			// Our verifier matches keyIds against our pubkey-derived
			// keyId; the attacker's keyId is different (different
			// pubkey input to SHA-256), so the line never matches.
			expect(ourLog.verifyCheckpoint(forgedEnv)).toBe(false);
		} finally {
			attackerLog.dispose();
			ourLog.dispose();
		}
	});

	it('returns false on a flipped body byte (signed message reconstructs differently)', () => {
		// Security property: the cosignature signed-message includes
		// the full checkpoint body, so any tamper in the body bytes
		// produces a different signed message that the recorded sig
		// no longer matches.
		const v = signSthEd25519Vectors[0];
		const log = buildLog(v);
		try {
			const env = hexToBytes(v.envelopeHex);
			// Flip a bit inside the body region. Pick a byte from the
			// origin line (e.g. byte 0, 'l' in "leviathan").
			const tampered = tamperBit(env, 0, 0x01);
			// `tamperBit` may produce an envelope whose body is no
			// longer well-formed UTF-8 / per-spec. parseSignedNote /
			// parseCheckpointBody might throw on it; verifyCheckpoint
			// catches and returns false either way.
			expect(log.verifyCheckpoint(tampered)).toBe(false);
		} finally {
			log.dispose();
		}
	});

	it('returns false on a tampered timestamp inside the cosig payload', () => {
		// Security property: the timestamp goes through both the
		// cosignature signed-message construction AND the
		// timestamped_signature payload. Re-emitting the envelope
		// with a different timestamp prefix (but the original sig
		// bytes) produces a verify-false because the verifier
		// reconstructs the signed-message with the new timestamp and
		// the sig was over the original signed-message.
		const v = signSthEd25519Vectors[0];
		const log = buildLog(v);
		try {
			const env = parseSignedNote(hexToBytes(v.envelopeHex));
			const sig = env.signatures[0];
			const parsed = parseCosigSignaturePayload(sig.signature, 64);
			// Tamper: bump the timestamp by 1 second; re-emit.
			const newPayload = emitCosigSignaturePayload(parsed.timestamp + 1, parsed.signature);
			const newEnv = emitSignedNote(env.body, [{
				name: sig.name,
				keyId: sig.keyId,
				signature: newPayload,
			}]);
			expect(log.verifyCheckpoint(newEnv)).toBe(false);
		} finally {
			log.dispose();
		}
	});

	it('returns false on a flipped signature byte', () => {
		// Security property: the raw signature bytes are part of the
		// timestamped_signature payload; any tamper there fails the
		// suite.verify call.
		const v = signSthEd25519Vectors[0];
		const log = buildLog(v);
		try {
			const env = parseSignedNote(hexToBytes(v.envelopeHex));
			const sig = env.signatures[0];
			const parsed = parseCosigSignaturePayload(sig.signature, 64);
			const tamperedSig = parsed.signature.slice();
			// Flip a bit in the last raw-sig byte.
			tamperedSig[tamperedSig.length - 1] ^= 0x01;
			const newPayload = emitCosigSignaturePayload(parsed.timestamp, tamperedSig);
			const newEnv = emitSignedNote(env.body, [{
				name: sig.name,
				keyId: sig.keyId,
				signature: newPayload,
			}]);
			expect(log.verifyCheckpoint(newEnv)).toBe(false);
		} finally {
			log.dispose();
		}
	});

	it('returns false on a wrong-origin verifier (logA envelope verified by logB)', () => {
		// Security property: origin binds via the checkpoint body's
		// first line. A SignedLog with origin B refuses an envelope
		// whose body origin is A.
		const v = signSthEd25519Vectors[0];
		const otherLog = buildLog(v, { origin: 'leviathan.test/different-origin' });
		try {
			expect(otherLog.verifyCheckpoint(hexToBytes(v.envelopeHex))).toBe(false);
		} finally {
			otherLog.dispose();
		}
	});

	it('returns false when the verifier holds the wrong pubkey (key-ID derivation mismatch)', () => {
		// Security property: keyId binds to (origin, algoByte,
		// pubkey). A different pubkey under the same origin produces
		// a different keyId, so no signature line matches.
		const v = signSthEd25519Vectors[0];
		const ed = new Ed25519();
		let otherPk: Uint8Array;
		let otherSk: Uint8Array;
		try {
			const kp = ed.keygenDerand(new Uint8Array(32).fill(0xcd));
			otherPk = kp.publicKey;
			otherSk = kp.secretKey;
		} finally {
			ed.dispose();
		}
		const otherLog = buildLog(v, { sk: otherSk, pk: otherPk });
		try {
			expect(otherLog.verifyCheckpoint(hexToBytes(v.envelopeHex))).toBe(false);
		} finally {
			otherLog.dispose();
		}
	});

	it('returns false on a wholly malformed envelope (parse fails)', () => {
		// Security property: malformed input is rejected silently
		// rather than crashing the verifier.
		const v = signSthEd25519Vectors[0];
		const log = buildLog(v);
		try {
			expect(log.verifyCheckpoint(new Uint8Array(0))).toBe(false);
			expect(log.verifyCheckpoint(new Uint8Array([0x00, 0x01, 0x02]))).toBe(false);
			expect(log.verifyCheckpoint(utf8ToBytes('not a signed note\n'))).toBe(false);
		} finally {
			log.dispose();
		}
	});
});
