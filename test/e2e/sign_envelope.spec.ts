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
import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:1337';

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

test.describe('Sign envelope, e2e', () => {
	test('Ed25519Suite, RFC 8032 §7.1 TEST 1 deterministic envelope bytes', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ ed25519: ed25519Wasm });
			// RFC 8032 §7.1 TEST 1, wrapped in the v3 attached envelope:
			//   [0x01 suite, 0x00 ctxLen, 0x00000000 payloadLen, 64-byte sig].
			const sk = lib.hexToBytes(
				'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
			const expected = lib.hexToBytes(
				'010000000000e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873'
				+ 'e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe246551'
				+ '41438e7a100b');
			const blob = lib.Sign.sign(lib.Ed25519Suite, sk, new Uint8Array(0), new Uint8Array(0));
			return blob.length === expected.length
				&& (blob as Uint8Array).every((b: number, i: number) => b === expected[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('Ed25519Suite, round-trip + tamper', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ ed25519: ed25519Wasm });
			const { pk, sk } = lib.Ed25519Suite.keygen();
			const msg = lib.randomBytes(128);
			const blob = lib.Sign.sign(lib.Ed25519Suite, sk, msg, new Uint8Array(0));
			const out = lib.Sign.verify(lib.Ed25519Suite, pk, blob, new Uint8Array(0));
			const rtOk = out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
			const tampered = blob.slice();
			// Flip a byte inside the trailing sig (last 64 bytes).
			tampered[tampered.length - 1] ^= 0x40;
			let tamperOk = false;
			try {
				lib.Sign.verify(lib.Ed25519Suite, pk, tampered, new Uint8Array(0));
			} catch (e) {
				tamperOk = e instanceof lib.SigningError
					&& (e as { discriminator: string }).discriminator === 'verify-failed';
			}
			return rtOk && tamperOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('Ed25519PreHashSuite, round-trip with non-empty ctx, wrong-ctx rejection', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ ed25519: ed25519Wasm, sha2: sha2Wasm });
			const { pk, sk } = lib.Ed25519PreHashSuite.keygen();
			const msg = lib.randomBytes(256);
			const ctx = lib.utf8ToBytes('user-ctx-1');
			const blob = lib.Sign.sign(lib.Ed25519PreHashSuite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.Ed25519PreHashSuite, pk, blob, ctx);
			const rtOk = out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
			let wrongCtxOk = false;
			try {
				lib.Sign.verify(lib.Ed25519PreHashSuite, pk, blob, lib.utf8ToBytes('user-ctx-2'));
			} catch (e) {
				wrongCtxOk = e instanceof lib.SigningError
					&& (e as { discriminator: string }).discriminator === 'sig-ctx-mismatch';
			}
			return rtOk && wrongCtxOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('EcdsaP256Suite, round-trip + two signs differ (hedged via crypto.getRandomValues)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { p256Wasm } = await import(`${base}/dist/ecdsa/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ p256: p256Wasm, sha2: sha2Wasm });
			const { pk, sk } = lib.EcdsaP256Suite.keygen();
			const msg = lib.randomBytes(64);
			const ctx = new Uint8Array(0);
			const blob1 = lib.Sign.sign(lib.EcdsaP256Suite, sk, msg, ctx);
			const blob2 = lib.Sign.sign(lib.EcdsaP256Suite, sk, msg, ctx);
			const v1 = lib.Sign.verify(lib.EcdsaP256Suite, pk, blob1, ctx);
			const v2 = lib.Sign.verify(lib.EcdsaP256Suite, pk, blob2, ctx);
			const rtOk = v1.length === msg.length
				&& (v1 as Uint8Array).every((b: number, i: number) => b === msg[i])
				&& v2.length === msg.length;
			// Hedged ECDSA: two signs of the same (sk, msg) must differ in the
			// trailing 64-byte sig.
			let differ = false;
			if (blob1.length === blob2.length) {
				for (let i = 0; i < blob1.length; i++) {
					if (blob1[i] !== blob2[i]) {
						differ = true; break;
					}
				}
			} else differ = true;
			return rtOk && differ;
		}, BASE);
		expect(result).toBe(true);
	});

	test('EcdsaP256Suite, signDetached / verifyDetached raw round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { p256Wasm } = await import(`${base}/dist/ecdsa/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ p256: p256Wasm, sha2: sha2Wasm });
			const { pk, sk } = lib.EcdsaP256Suite.keygen();
			const msg = lib.randomBytes(64);
			const ctx = new Uint8Array(0);
			const sig = lib.Sign.signDetached(lib.EcdsaP256Suite, sk, msg, ctx);
			return sig.length === 64
				&& lib.Sign.verifyDetached(lib.EcdsaP256Suite, pk, msg, sig, ctx) === true;
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44Suite, hedged round-trip + ctx', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { mldsaWasm } = await import(`${base}/dist/mldsa/embedded.js`);
			const { sha3Wasm }  = await import(`${base}/dist/sha3/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ mldsa: mldsaWasm, sha3: sha3Wasm });
			const { pk, sk } = lib.MlDsa44Suite.keygen();
			const msg = lib.randomBytes(128);
			const ctx = lib.utf8ToBytes('mldsa-ctx');
			const blob = lib.Sign.sign(lib.MlDsa44Suite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.MlDsa44Suite, pk, blob, ctx);
			const rtOk = out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
			let wrongCtxOk = false;
			try {
				lib.Sign.verify(lib.MlDsa44Suite, pk, blob, lib.utf8ToBytes('wrong-ctx'));
			} catch (e) {
				wrongCtxOk = e instanceof lib.SigningError
					&& (e as { discriminator: string }).discriminator === 'sig-ctx-mismatch';
			}
			return rtOk && wrongCtxOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44PreHashSuite, signPrehashed / verifyPrehashed round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { mldsaWasm } = await import(`${base}/dist/mldsa/embedded.js`);
			const { sha3Wasm }  = await import(`${base}/dist/sha3/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ mldsa: mldsaWasm, sha3: sha3Wasm });
			const { pk, sk } = lib.MlDsa44PreHashSuite.keygen();
			const msg = lib.randomBytes(256);
			const ctx = new Uint8Array(0);
			const blob = lib.Sign.sign(lib.MlDsa44PreHashSuite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.MlDsa44PreHashSuite, pk, blob, ctx);
			return out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('SlhDsa128fSuite, hedged round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { slhdsaWasm } = await import(`${base}/dist/slhdsa/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ slhdsa: slhdsaWasm });
			const { pk, sk } = lib.SlhDsa128fSuite.keygen();
			const msg = lib.randomBytes(64);
			const ctx = new Uint8Array(0);
			const blob = lib.Sign.sign(lib.SlhDsa128fSuite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.SlhDsa128fSuite, pk, blob, ctx);
			return out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44SlhDsa128fSuite, PQ hybrid round-trip + half-tamper rejection', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { mldsaWasm }  = await import(`${base}/dist/mldsa/embedded.js`);
			const { sha3Wasm }   = await import(`${base}/dist/sha3/embedded.js`);
			const { slhdsaWasm } = await import(`${base}/dist/slhdsa/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ mldsa: mldsaWasm, sha3: sha3Wasm, slhdsa: slhdsaWasm });
			const { pk, sk } = lib.MlDsa44SlhDsa128fSuite.keygen();
			const msg = lib.randomBytes(64);
			const ctx = new Uint8Array(0);
			const blob = lib.Sign.sign(lib.MlDsa44SlhDsa128fSuite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.MlDsa44SlhDsa128fSuite, pk, blob, ctx);
			const rtOk = out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
			// Tamper the trailing sig (one byte inside the SLH-DSA half).
			const tampered = blob.slice();
			tampered[tampered.length - 1] ^= 0x01;
			let tamperOk = false;
			try {
				lib.Sign.verify(lib.MlDsa44SlhDsa128fSuite, pk, tampered, ctx);
			} catch (e) {
				tamperOk = e instanceof lib.SigningError
					&& (e as { discriminator: string }).discriminator === 'verify-failed';
			}
			return rtOk && tamperOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44Ed25519Suite, classical hybrid round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { mldsaWasm }   = await import(`${base}/dist/mldsa/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({
				mldsa: mldsaWasm, sha3: sha3Wasm, ed25519: ed25519Wasm, sha2: sha2Wasm,
			});
			const { pk, sk } = lib.MlDsa44Ed25519Suite.keygen();
			const msg = lib.randomBytes(128);
			const ctx = new Uint8Array(0);
			const blob = lib.Sign.sign(lib.MlDsa44Ed25519Suite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.MlDsa44Ed25519Suite, pk, blob, ctx);
			return out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44EcdsaP256Suite, classical hybrid round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { mldsaWasm } = await import(`${base}/dist/mldsa/embedded.js`);
			const { sha3Wasm }  = await import(`${base}/dist/sha3/embedded.js`);
			const { p256Wasm }  = await import(`${base}/dist/ecdsa/embedded.js`);
			const { sha2Wasm }  = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({
				mldsa: mldsaWasm, sha3: sha3Wasm, p256: p256Wasm, sha2: sha2Wasm,
			});
			const { pk, sk } = lib.MlDsa44EcdsaP256Suite.keygen();
			const msg = lib.randomBytes(128);
			const ctx = new Uint8Array(0);
			const blob = lib.Sign.sign(lib.MlDsa44EcdsaP256Suite, sk, msg, ctx);
			const out = lib.Sign.verify(lib.MlDsa44EcdsaP256Suite, pk, blob, ctx);
			return out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('cross-suite tamper, Ed25519 blob flipped to EcdsaP256 suite_byte', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			const { p256Wasm }    = await import(`${base}/dist/ecdsa/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ ed25519: ed25519Wasm, p256: p256Wasm, sha2: sha2Wasm });
			const { sk } = lib.Ed25519Suite.keygen();
			const msg = lib.randomBytes(32);
			const blob = lib.Sign.sign(lib.Ed25519Suite, sk, msg, new Uint8Array(0));
			// Flip suite_byte from 0x01 (Ed25519) to 0x02 (EcdsaP256).
			const tampered = blob.slice();
			tampered[0] = lib.EcdsaP256Suite.formatEnum;
			const { pk: pkEc } = lib.EcdsaP256Suite.keygen();
			let caughtOk = false;
			try {
				lib.Sign.verify(lib.EcdsaP256Suite, pkEc, tampered, new Uint8Array(0));
			} catch (e) {
				// We expect an error from header parsing or sig-suite consistency.
				// The wire suite byte (0x02) now matches the suite passed in, so
				// the check we're really asserting is that the underlying
				// sig-verify fails because the Ed25519 sig is not a valid
				// ECDSA sig over msg. This proves a suite-byte swap cannot
				// cause a cross-suite cryptographic forgery.
				caughtOk = e instanceof lib.SigningError;
			}
			// Also verify the same blob WITHOUT the flip fails against
			// EcdsaP256Suite because of sig-suite-mismatch.
			let sigSuiteMismatchOk = false;
			try {
				lib.Sign.verify(lib.EcdsaP256Suite, pkEc, blob, new Uint8Array(0));
			} catch (e) {
				sigSuiteMismatchOk = e instanceof lib.SigningError
					&& (e as { discriminator: string }).discriminator === 'sig-suite-mismatch';
			}
			return caughtOk && sigSuiteMismatchOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('Sign.peek returns wire offsets matching the envelope layout', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ ed25519: ed25519Wasm });
			const { sk } = lib.Ed25519Suite.keygen();
			const msg = lib.randomBytes(50);
			const blob = lib.Sign.sign(lib.Ed25519Suite, sk, msg, new Uint8Array(0));
			const peek = lib.Sign.peek(blob, lib.Ed25519Suite);
			// Layout: [suite(1), ctxLen(1)=0, payloadLen(4)=50, payload(50), sig(64)]
			return peek.suiteByte === 0x01
				&& peek.ctx.length === 0
				&& peek.payloadLength === msg.length
				&& peek.payloadOffset === 6
				&& peek.sigOffset === 6 + msg.length
				&& blob.length === peek.sigOffset + 64;
		}, BASE);
		expect(result).toBe(true);
	});
});
