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

test.describe('MerkleLog + MerkleVerifier, e2e', () => {
	test('Ed25519 + SHA-256: full lifecycle (append, head, inclusion, consistency)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { sha2Wasm }     = await import(`${base}/dist/sha2/embedded.js`);
			const { ed25519Wasm }  = await import(`${base}/dist/ed25519/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ sha2: sha2Wasm, ed25519: ed25519Wasm });

			const origin = 'leviathan.example/v1/e2e/log';
			const leaves = ['alpha', 'bravo', 'charlie', 'delta'];

			const { log, pubkey } = await lib.MerkleLog.generate({
				origin, suite: lib.Ed25519Suite,
			});
			let envelopeAtSize2: Uint8Array;
			let envelopeFinal: Uint8Array;
			let inclusionProof2: Uint8Array[];
			let consistencyProof: Uint8Array[];
			try {
				log.append(lib.utf8ToBytes(leaves[0]));
				log.append(lib.utf8ToBytes(leaves[1]));
				envelopeAtSize2 = log.head({ timestamp: 1740000000 });
				const oldSize = log.size();
				log.append(lib.utf8ToBytes(leaves[2]));
				log.append(lib.utf8ToBytes(leaves[3]));
				envelopeFinal = log.head({ timestamp: 1740000001 });
				inclusionProof2 = log.inclusionProof(2, log.size());
				consistencyProof = log.consistencyProof(oldSize, log.size());
			} finally {
				log.dispose();
			}

			const verifier = new lib.MerkleVerifier({
				origin, pubkey, hashing: 'sha256', suite: lib.Ed25519Suite,
			});

			const checkpointOk = verifier.verifyCheckpoint(envelopeFinal);
			const inclusionOk  = verifier.verifyInclusion({
				envelopeBytes: envelopeFinal,
				leafBytes: lib.utf8ToBytes(leaves[2]),
				leafIndex: 2,
				proof: inclusionProof2,
			});
			const consistencyOk = verifier.verifyConsistency({
				oldEnvelopeBytes: envelopeAtSize2,
				newEnvelopeBytes: envelopeFinal,
				proof: consistencyProof,
			});

			return checkpointOk && inclusionOk && consistencyOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('MlDsa44 + SHA-256: full lifecycle (cosigned-message PQ path)', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { sha2Wasm }  = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }  = await import(`${base}/dist/sha3/embedded.js`);
			const { mldsaWasm } = await import(`${base}/dist/mldsa/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ sha2: sha2Wasm, sha3: sha3Wasm, mldsa: mldsaWasm });

			const origin = 'leviathan.example/v1/e2e/log-mldsa44';
			const leaves = ['alpha', 'bravo', 'charlie', 'delta'];

			const { log, pubkey } = await lib.MerkleLog.generate({
				origin, suite: lib.MlDsa44Suite,
			});
			let envelopeAtSize2: Uint8Array;
			let envelopeFinal: Uint8Array;
			let inclusionProof2: Uint8Array[];
			let consistencyProof: Uint8Array[];
			try {
				log.append(lib.utf8ToBytes(leaves[0]));
				log.append(lib.utf8ToBytes(leaves[1]));
				envelopeAtSize2 = log.head({ timestamp: 1740000000 });
				const oldSize = log.size();
				log.append(lib.utf8ToBytes(leaves[2]));
				log.append(lib.utf8ToBytes(leaves[3]));
				envelopeFinal = log.head({ timestamp: 1740000001 });
				inclusionProof2 = log.inclusionProof(2, log.size());
				consistencyProof = log.consistencyProof(oldSize, log.size());
			} finally {
				log.dispose();
			}

			const verifier = new lib.MerkleVerifier({
				origin, pubkey, hashing: 'sha256', suite: lib.MlDsa44Suite,
			});

			const checkpointOk = verifier.verifyCheckpoint(envelopeFinal);
			const inclusionOk  = verifier.verifyInclusion({
				envelopeBytes: envelopeFinal,
				leafBytes: lib.utf8ToBytes(leaves[2]),
				leafIndex: 2,
				proof: inclusionProof2,
			});
			const consistencyOk = verifier.verifyConsistency({
				oldEnvelopeBytes: envelopeAtSize2,
				newEnvelopeBytes: envelopeFinal,
				proof: consistencyProof,
			});

			return checkpointOk && inclusionOk && consistencyOk;
		}, BASE);
		expect(result).toBe(true);
	});

	test('MerkleVerifier rejects a tampered envelope', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { ed25519Wasm } = await import(`${base}/dist/ed25519/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ sha2: sha2Wasm, ed25519: ed25519Wasm });

			const origin = 'leviathan.example/v1/e2e/tamper';
			const { log, pubkey } = await lib.MerkleLog.generate({
				origin, suite: lib.Ed25519Suite,
			});
			let env: Uint8Array;
			try {
				log.append(lib.utf8ToBytes('leaf-zero'));
				env = log.head({ timestamp: 1740000000 });
			} finally {
				log.dispose();
			}

			const verifier = new lib.MerkleVerifier({
				origin, pubkey, hashing: 'sha256', suite: lib.Ed25519Suite,
			});
			// Sanity: clean envelope verifies.
			if (!verifier.verifyCheckpoint(env)) return false;
			// Tamper a single byte inside the body region.
			const tampered = env.slice();
			tampered[0] ^= 0x01;
			return verifier.verifyCheckpoint(tampered) === false;
		}, BASE);
		expect(result).toBe(true);
	});
});
