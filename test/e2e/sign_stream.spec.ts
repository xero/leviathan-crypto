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

test.describe('SignStream / VerifyStream, e2e', () => {
	test('Ed25519PreHashSuite, chunked SignStream byte-equivalent to Sign.sign', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ ed25519: ed25519Wasm, sha2: sha2Wasm });
			const { sk } = lib.Ed25519PreHashSuite.keygen();
			const msg = lib.randomBytes(523);
			const ctx = lib.utf8ToBytes('e2e-stream');

			const blobOneShot = lib.Sign.sign(lib.Ed25519PreHashSuite, sk, msg, ctx);
			const s = new lib.SignStream(lib.Ed25519PreHashSuite, sk, ctx);
			let blobStream: Uint8Array;
			try {
				s.update(msg.subarray(0, 7));
				s.update(msg.subarray(7, 99));
				s.update(msg.subarray(99, 250));
				s.update(msg.subarray(250));
				const sig = s.finalize();
				blobStream = lib.concat(s.buildPreamble(msg.length), msg, sig);
			} finally {
				s.dispose();
			}
			if (blobStream.length !== blobOneShot.length) return false;
			for (let i = 0; i < blobOneShot.length; i++) {
				if (blobStream[i] !== blobOneShot[i]) return false;
			}
			return true;
		}, BASE);
		expect(result).toBe(true);
	});

	test('EcdsaP256Suite, header+payload equivalence, sig differs', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { p256Wasm } = await import(`${base}/dist/ecdsa/embedded.js`);
			const { sha2Wasm } = await import(`${base}/dist/sha2/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ p256: p256Wasm, sha2: sha2Wasm });
			const { pk, sk } = lib.EcdsaP256Suite.keygen();
			const msg = lib.randomBytes(400);
			const ctx = new Uint8Array(0);

			const blobOneShot = lib.Sign.sign(lib.EcdsaP256Suite, sk, msg, ctx);
			const s = new lib.SignStream(lib.EcdsaP256Suite, sk, ctx);
			let blobStream: Uint8Array;
			try {
				s.update(msg.subarray(0, 128));
				s.update(msg.subarray(128, 300));
				s.update(msg.subarray(300));
				const sig = s.finalize();
				blobStream = lib.concat(s.buildPreamble(msg.length), msg, sig);
			} finally {
				s.dispose();
			}
			if (blobStream.length !== blobOneShot.length) return false;
			// Header + payload (everything but the trailing 64-byte sig) must match.
			const payloadEnd = blobStream.length - 64;
			for (let i = 0; i < payloadEnd; i++) {
				if (blobStream[i] !== blobOneShot[i]) return false;
			}
			// Sigs MUST differ (hedged re-rolls rnd per call).
			let differ = false;
			for (let i = payloadEnd; i < blobStream.length; i++) {
				if (blobStream[i] !== blobOneShot[i]) {
					differ = true; break;
				}
			}
			// Both blobs must verify under the same pk.
			const oneShot = lib.Sign.verify(lib.EcdsaP256Suite, pk, blobOneShot, ctx);
			const streamed = lib.Sign.verify(lib.EcdsaP256Suite, pk, blobStream, ctx);
			const verifyOk = oneShot.length === msg.length && streamed.length === msg.length;
			return differ && verifyOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44PreHashSuite, VerifyStream accepts Sign.sign output', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { mldsaWasm } = await import(`${base}/dist/mldsa/embedded.js`);
			const { sha3Wasm }  = await import(`${base}/dist/sha3/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ mldsa: mldsaWasm, sha3: sha3Wasm });
			const { pk, sk } = lib.MlDsa44PreHashSuite.keygen();
			const msg = lib.randomBytes(256);
			const ctx = lib.utf8ToBytes('e2e-vs');
			const blob = lib.Sign.sign(lib.MlDsa44PreHashSuite, sk, msg, ctx);
			const v = new lib.VerifyStream(lib.MlDsa44PreHashSuite, pk, ctx);
			let out: Uint8Array;
			try {
				// Feed the blob in two chunks to exercise the streaming parser.
				v.update(blob.subarray(0, Math.floor(blob.length / 2)));
				v.update(blob.subarray(Math.floor(blob.length / 2)));
				out = v.finalize();
			} finally {
				v.dispose();
			}
			return out.length === msg.length
				&& (out as Uint8Array).every((b: number, i: number) => b === msg[i]);
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44PreHashSuite, VerifyStream rejects a mid-payload byte flip', async ({ page }) => {
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
			const tampered = blob.slice();
			// Header is [suite(1), ctxLen(1), payloadLen(4)] = 6 bytes when ctx is empty.
			tampered[6 + 10] ^= 0x80;

			const v = new lib.VerifyStream(lib.MlDsa44PreHashSuite, pk, ctx);
			let caughtOk = false;
			try {
				v.update(tampered);
				v.finalize();
			} catch (e) {
				caughtOk = e instanceof lib.SigningError
					&& (e as { discriminator: string }).discriminator === 'verify-failed';
			} finally {
				v.dispose();
			}
			return caughtOk;
		}, BASE);
		expect(result).toBe(true);
	});
});
