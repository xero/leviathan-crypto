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
/**
 * EcdsaP256 TypeScript-class smoke tests.
 *
 * Validates the public surface of `EcdsaP256` against the RFC 6979
 * §A.2.5 deterministic-K corpus plus API-edge tests (length / type
 * validation, the fault-injection pk-mismatch trap, uncompressed pk
 * acceptance, concurrency assertion). The full RFC 6979 / ACVP corpus
 * runs at the WASM layer in `test/unit/p256/ecdsa_*.test.ts`; this
 * file gates only the wrapper API and the p256 init plumbing.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, EcdsaP256, isInitialized, SigningError,
	hexToBytes, bytesToHex,
} from '../../../src/ts/index.js';
import { _resetForTesting, _acquireModule, _releaseModule } from '../../../src/ts/init.js';
import {
	RFC6979_P256_KEY, ecdsa_p256_rfc6979,
} from '../../vectors/ecdsa_p256.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

// RFC 6979 §A.2.5 records; 'test' is low-S as published, 'sample' is
// high-S so the library's low-S output differs from the published s.
const testVec   = ecdsa_p256_rfc6979.find(v => v.id === 'test')!;
const sampleVec = ecdsa_p256_rfc6979.find(v => v.id === 'sample')!;

const N_HEX = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

function sha256(msg: Uint8Array): Uint8Array {
	return new Uint8Array(createHash('sha256').update(msg).digest());
}

// 'test' record's compressed pk (SEC 1 §2.3.3): prefix is 0x03 because
// the y coordinate `7903...2299` ends in 0x99 (LSB = 1, odd).
const RFC_PK_COMPRESSED_HEX =
	'03' + RFC6979_P256_KEY.uxHex.toLowerCase();
const RFC_PK_UNCOMPRESSED_HEX =
	'04' + RFC6979_P256_KEY.uxHex.toLowerCase() + RFC6979_P256_KEY.uyHex.toLowerCase();

beforeAll(async () => {
	_resetForTesting();
	expect(() => new EcdsaP256()).toThrow(/init\(\{ p256:/);
	const wasmBytes = readFileSync(join(__dirname, '../../../build/p256.wasm'));
	await init({ p256: wasmBytes });
});

describe('EcdsaP256 init plumbing', () => {
	it('ecdsaP256Init initialises the p256 module', () => {
		expect(isInitialized('p256')).toBe(true);
	});

	it('EcdsaP256 constructor succeeds after init', () => {
		const ec = new EcdsaP256();
		expect(ec).toBeInstanceOf(EcdsaP256);
		ec.dispose();
	});
});

describe('EcdsaP256 keygen', () => {
	it('keygenDerand reproduces RFC 6979 §A.2.5 compressed pk', () => {
		const ec = new EcdsaP256();
		try {
			const { publicKey, secretKey } = ec.keygenDerand(hexToBytes(RFC6979_P256_KEY.xHex));
			expect(publicKey.length).toBe(33);
			expect(bytesToHex(publicKey)).toBe(RFC_PK_COMPRESSED_HEX);
			expect(bytesToHex(secretKey)).toBe(RFC6979_P256_KEY.xHex.toLowerCase());
		} finally {
			ec.dispose();
		}
	});

	it('keygenDerand is deterministic across calls', () => {
		const ec = new EcdsaP256();
		try {
			const seed = hexToBytes(RFC6979_P256_KEY.xHex);
			const a = ec.keygenDerand(seed);
			const b = ec.keygenDerand(seed);
			expect(bytesToHex(a.publicKey)).toBe(bytesToHex(b.publicKey));
			expect(bytesToHex(a.secretKey)).toBe(bytesToHex(b.secretKey));
		} finally {
			ec.dispose();
		}
	});

	it('keygen returns a fresh 33-byte pk and 32-byte sk', () => {
		const ec = new EcdsaP256();
		try {
			const a = ec.keygen();
			const b = ec.keygen();
			expect(a.publicKey).toBeInstanceOf(Uint8Array);
			expect(a.secretKey).toBeInstanceOf(Uint8Array);
			expect(a.publicKey.length).toBe(33);
			expect(a.secretKey.length).toBe(32);
			// The leading prefix byte is 0x02 or 0x03 per SEC 1 §2.3.3.
			expect([0x02, 0x03]).toContain(a.publicKey[0]);
			// Two random keygens must differ (catches a constant-seed bug).
			expect(bytesToHex(a.secretKey)).not.toBe(bytesToHex(b.secretKey));
		} finally {
			ec.dispose();
		}
	});
});

describe('EcdsaP256 sign / verify', () => {
	it('sign with deterministic rnd reproduces RFC 6979 §A.2.5 "test" (r, s) byte-for-byte', () => {
		const ec = new EcdsaP256();
		try {
			const sk      = hexToBytes(RFC6979_P256_KEY.xHex);
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig     = ec.sign(sk, pk, msgHash, new Uint8Array(32));
			// The 'test' record is low-S as published, so the library's
			// strict-S output equals RFC §A.2.5's (r, s) verbatim.
			expect(bytesToHex(sig.subarray(0, 32))).toBe(testVec.rHex.toLowerCase());
			expect(bytesToHex(sig.subarray(32, 64))).toBe(testVec.sHex.toLowerCase());
		} finally {
			ec.dispose();
		}
	});

	it('sign self-verify round-trip with hedged rnd', () => {
		const ec = new EcdsaP256();
		try {
			const { publicKey, secretKey } = ec.keygen();
			const msgHash = sha256(new TextEncoder().encode('round-trip-hedged'));
			const rnd = new Uint8Array(32);
			rnd.fill(0xa5);
			const sig = ec.sign(secretKey, publicKey, msgHash, rnd);
			expect(sig.length).toBe(64);
			expect(ec.verify(publicKey, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});

	it('sign self-verify round-trip with deterministic rnd', () => {
		const ec = new EcdsaP256();
		try {
			const { publicKey, secretKey } = ec.keygen();
			const msgHash = sha256(new TextEncoder().encode('round-trip-deterministic'));
			const sig = ec.sign(secretKey, publicKey, msgHash, new Uint8Array(32));
			expect(ec.verify(publicKey, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});

	it('sign with a 65-byte uncompressed pk works and round-trips', () => {
		const ec = new EcdsaP256();
		try {
			const sk      = hexToBytes(RFC6979_P256_KEY.xHex);
			const pk      = hexToBytes(RFC_PK_UNCOMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig     = ec.sign(sk, pk, msgHash, new Uint8Array(32));
			expect(bytesToHex(sig.subarray(0, 32))).toBe(testVec.rHex.toLowerCase());
			// Verify accepts the uncompressed form too.
			expect(ec.verify(pk, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});

	it('sign with a mismatched pk throws SigningError (fault-injection trap)', () => {
		const ec = new EcdsaP256();
		try {
			const sk      = hexToBytes(RFC6979_P256_KEY.xHex);
			const other   = ec.keygen();
			const msgHash = sha256(new TextEncoder().encode(sampleVec.msgUtf8));
			expect(() => ec.sign(sk, other.publicKey, msgHash, new Uint8Array(32)))
				.toThrow(SigningError);
		} finally {
			ec.dispose();
		}
	});

	it('verify returns true on the §A.2.5 "test" record', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			sig.set(hexToBytes(testVec.sHex), 32);
			expect(ec.verify(pk, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});

	it('verify returns false on a tampered message hash, never throws', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			msgHash[0] ^= 0x01;
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			sig.set(hexToBytes(testVec.sHex), 32);
			expect(ec.verify(pk, msgHash, sig)).toBe(false);
		} finally {
			ec.dispose();
		}
	});

	it('verify returns false on a tampered signature, never throws', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			sig.set(hexToBytes(testVec.sHex), 32);
			sig[0] ^= 0x01;
			expect(ec.verify(pk, msgHash, sig)).toBe(false);
		} finally {
			ec.dispose();
		}
	});

	it('verify returns false on a high-S signature (strict-S posture)', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			// Replace low-S with its high-S counterpart: s' = n - s.
			const n = BigInt('0x' + N_HEX);
			const s = BigInt('0x' + testVec.sHex);
			const sHigh = (n - s).toString(16).padStart(64, '0');
			sig.set(hexToBytes(sHigh), 32);
			expect(ec.verify(pk, msgHash, sig)).toBe(false);
		} finally {
			ec.dispose();
		}
	});

	it('verify returns false when r = 0', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			// r = 0; s = published s.
			sig.set(hexToBytes(testVec.sHex), 32);
			expect(ec.verify(pk, msgHash, sig)).toBe(false);
		} finally {
			ec.dispose();
		}
	});

	it('verify returns false when s = 0', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			// s = 0 already.
			expect(ec.verify(pk, msgHash, sig)).toBe(false);
		} finally {
			ec.dispose();
		}
	});
});

describe('EcdsaP256 _signInternalPk (suite helper)', () => {
	it('_signInternalPk output equals sign(sk, derivedPk, hash, rnd) for matching inputs', () => {
		const ec = new EcdsaP256();
		try {
			const { publicKey, secretKey } = ec.keygen();
			const msgHash = sha256(new TextEncoder().encode('internal-pk equivalence'));
			// Use deterministic rnd so both paths produce the same K.
			const rnd = new Uint8Array(32);
			const sigInternal = ec._signInternalPk(secretKey, msgHash, rnd);
			const sigExternal = ec.sign(secretKey, publicKey, msgHash, rnd);
			expect(bytesToHex(sigInternal)).toBe(bytesToHex(sigExternal));
		} finally {
			ec.dispose();
		}
	});

	it('_signInternalPk with deterministic rnd reproduces §A.2.5 "test" signature', () => {
		const ec = new EcdsaP256();
		try {
			const sk      = hexToBytes(RFC6979_P256_KEY.xHex);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig     = ec._signInternalPk(sk, msgHash, new Uint8Array(32));
			expect(bytesToHex(sig.subarray(0, 32))).toBe(testVec.rHex.toLowerCase());
			expect(bytesToHex(sig.subarray(32, 64))).toBe(testVec.sHex.toLowerCase());
		} finally {
			ec.dispose();
		}
	});
});

describe('EcdsaP256 input validation', () => {
	it('validatePublicKey accepts a 33-byte compressed pk', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_COMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			sig.set(hexToBytes(testVec.sHex), 32);
			expect(ec.verify(pk, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});

	it('validatePublicKey accepts a 65-byte uncompressed pk', () => {
		const ec = new EcdsaP256();
		try {
			const pk      = hexToBytes(RFC_PK_UNCOMPRESSED_HEX);
			const msgHash = sha256(new TextEncoder().encode(testVec.msgUtf8));
			const sig = new Uint8Array(64);
			sig.set(hexToBytes(testVec.rHex), 0);
			sig.set(hexToBytes(testVec.sHex), 32);
			expect(ec.verify(pk, msgHash, sig)).toBe(true);
		} finally {
			ec.dispose();
		}
	});

	it('validatePublicKey rejects 32-, 64-, and 66-byte inputs with RangeError', () => {
		const ec = new EcdsaP256();
		try {
			for (const n of [32, 64, 66]) {
				expect(() => ec.verify(new Uint8Array(n), new Uint8Array(32), new Uint8Array(64)))
					.toThrow(RangeError);
			}
		} finally {
			ec.dispose();
		}
	});

	it('validateMessageHash rejects wrong-length inputs (sign + verify)', () => {
		const ec = new EcdsaP256();
		try {
			const sk = new Uint8Array(32); sk[31] = 1;
			const pk = hexToBytes(RFC_PK_COMPRESSED_HEX);
			expect(() => ec.sign(sk, pk, new Uint8Array(31), new Uint8Array(32))).toThrow(RangeError);
			expect(() => ec.sign(sk, pk, new Uint8Array(33), new Uint8Array(32))).toThrow(RangeError);
			expect(() => ec.verify(pk, new Uint8Array(31), new Uint8Array(64))).toThrow(RangeError);
			expect(() => ec.verify(pk, new Uint8Array(33), new Uint8Array(64))).toThrow(RangeError);
		} finally {
			ec.dispose();
		}
	});

	it('validateSignature rejects 63- and 65-byte inputs with RangeError', () => {
		const ec = new EcdsaP256();
		try {
			const pk = hexToBytes(RFC_PK_COMPRESSED_HEX);
			expect(() => ec.verify(pk, new Uint8Array(32), new Uint8Array(63))).toThrow(RangeError);
			expect(() => ec.verify(pk, new Uint8Array(32), new Uint8Array(65))).toThrow(RangeError);
		} finally {
			ec.dispose();
		}
	});

	it('sign throws TypeError on a non-Uint8Array sk', () => {
		const ec = new EcdsaP256();
		try {
			expect(() => ec.sign(
				'not bytes' as unknown as Uint8Array,
				new Uint8Array(33),
				new Uint8Array(32),
				new Uint8Array(32),
			)).toThrow(TypeError);
		} finally {
			ec.dispose();
		}
	});

	it('validateEntropy rejects wrong-length rnd inputs', () => {
		const ec = new EcdsaP256();
		try {
			const sk = new Uint8Array(32); sk[31] = 1;
			const pk = hexToBytes(RFC_PK_COMPRESSED_HEX);
			expect(() => ec.sign(sk, pk, new Uint8Array(32), new Uint8Array(31))).toThrow(RangeError);
			expect(() => ec.sign(sk, pk, new Uint8Array(32), new Uint8Array(33))).toThrow(RangeError);
		} finally {
			ec.dispose();
		}
	});
});

describe('EcdsaP256 dispose', () => {
	it('dispose is idempotent', () => {
		const ec = new EcdsaP256();
		ec.dispose();
		expect(() => ec.dispose()).not.toThrow();
		expect(() => ec.dispose()).not.toThrow();
	});
});

describe('EcdsaP256 concurrency assertion', () => {
	it('sign throws when the p256 module is held by another stateful instance', () => {
		const ec  = new EcdsaP256();
		const tok = _acquireModule('p256');
		try {
			const sk = new Uint8Array(32); sk[31] = 1;
			expect(() => ec.sign(sk, new Uint8Array(33), new Uint8Array(32), new Uint8Array(32)))
				.toThrow(/another stateful instance/);
		} finally {
			_releaseModule('p256', tok);
			ec.dispose();
		}
	});
});
