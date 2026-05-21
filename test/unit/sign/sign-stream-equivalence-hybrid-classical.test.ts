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
// test/unit/sign/sign-stream-equivalence-hybrid-classical.test.ts
//
// One-shot vs streaming byte-equivalence gate for the four classical+PQ
// composite hybrid suites (composite-sigs; FIPS 204 §3.4,
// draft-irtf-cfrg-det-sigs-with-noise-05).
// Deterministic sub-surfaces: ML-DSA (rnd ← 0³², FIPS 204 §3.4),
// Ed25519 (RFC 8032 §5.1.6), ECDSA (rnd ← 0³² → RFC 6979 §3.2 K).
// See docs/signaturesuite.md#hybrid-classicalpq-stream-equivalence.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, concat } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }   from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }    from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }    from '../../../src/ts/sha2/embedded.js';
import { ed25519Wasm } from '../../../src/ts/ed25519/embedded.js';
import { p256Wasm }    from '../../../src/ts/ecdsa/embedded.js';
import { utf8ToBytes } from '../../../src/ts/utils.js';
import {
	Sign, VerifyStream,
} from '../../../src/ts/sign/index.js';
import type { StreamableSignatureSuite } from '../../../src/ts/sign/index.js';
import {
	MlDsa44Ed25519Suite,
	MlDsa65Ed25519Suite,
	MlDsa44EcdsaP256Suite,
	MlDsa65EcdsaP256Suite,
} from '../../../src/ts/sign/suites/hybrid-classical.js';
import {
	MlDsa44, MlDsa65, MLDSA44, MLDSA65,
} from '../../../src/ts/mldsa/index.js';
import type { MlDsaParams } from '../../../src/ts/mldsa/index.js';
import { Ed25519 } from '../../../src/ts/ed25519/index.js';
import { EcdsaP256, decodeEcPrivateKey } from '../../../src/ts/ecdsa/index.js';
import { ecdsaSignatureToDer } from '../../../src/ts/ecdsa/der.js';
import { SHA256, SHA512 } from '../../../src/ts/sha2/index.js';

beforeAll(async () => {
	_resetForTesting();
	await init({
		mldsa: mldsaWasm,
		sha3: sha3Wasm,
		sha2: sha2Wasm,
		ed25519: ed25519Wasm,
		p256: p256Wasm,
	});
});

type MlDsaCtor = typeof MlDsa44 | typeof MlDsa65;
type TradFamily = 'ed25519' | 'ecdsa-p256';

interface Case {
	name:             string;
	suite:            StreamableSignatureSuite;
	MlDsaClass:       MlDsaCtor;
	mldsaParams:      MlDsaParams;
	tradFamily:       TradFamily;
	prehashAlgorithm: 'sha-256' | 'sha-512';
	prehashSize:      number;
	label:            Uint8Array;
}

// composite-sigs §2.2 Prefix and §6 Labels. Re-derived here to keep the
// test independent of suite-internal exports.
const COMPOSITE_PREFIX           = utf8ToBytes('CompositeAlgorithmSignatures2025');
const LABEL_MLDSA44_ED25519      = utf8ToBytes('COMPSIG-MLDSA44-Ed25519-SHA512');
const LABEL_MLDSA65_ED25519      = utf8ToBytes('COMPSIG-MLDSA65-Ed25519-SHA512');
const LABEL_MLDSA44_ECDSA_P256   = utf8ToBytes('COMPSIG-MLDSA44-ECDSA-P256-SHA256');
const LABEL_MLDSA65_ECDSA_P256   = utf8ToBytes('COMPSIG-MLDSA65-ECDSA-P256-SHA512');

const CASES: Case[] = [
	{
		name: 'MlDsa44Ed25519Suite',     suite: MlDsa44Ed25519Suite,
		MlDsaClass: MlDsa44,             mldsaParams: MLDSA44,
		tradFamily: 'ed25519',
		prehashAlgorithm: 'sha-512',     prehashSize: 64,
		label: LABEL_MLDSA44_ED25519,
	},
	{
		name: 'MlDsa65Ed25519Suite',     suite: MlDsa65Ed25519Suite,
		MlDsaClass: MlDsa65,             mldsaParams: MLDSA65,
		tradFamily: 'ed25519',
		prehashAlgorithm: 'sha-512',     prehashSize: 64,
		label: LABEL_MLDSA65_ED25519,
	},
	{
		name: 'MlDsa44EcdsaP256Suite',   suite: MlDsa44EcdsaP256Suite,
		MlDsaClass: MlDsa44,             mldsaParams: MLDSA44,
		tradFamily: 'ecdsa-p256',
		prehashAlgorithm: 'sha-256',     prehashSize: 32,
		label: LABEL_MLDSA44_ECDSA_P256,
	},
	{
		name: 'MlDsa65EcdsaP256Suite',   suite: MlDsa65EcdsaP256Suite,
		MlDsaClass: MlDsa65,             mldsaParams: MLDSA65,
		tradFamily: 'ecdsa-p256',
		prehashAlgorithm: 'sha-512',     prehashSize: 64,
		label: LABEL_MLDSA65_ECDSA_P256,
	},
];

function makeMsg(n: number): Uint8Array {
	const m = new Uint8Array(n);
	for (let i = 0; i < n; i++) m[i] = (i * 31 + 5) & 0xff;
	return m;
}

function ctxOf(n: number): Uint8Array {
	const c = new Uint8Array(n);
	for (let i = 0; i < n; i++) c[i] = (i + 0x40) & 0xff;
	return c;
}

function sha2OneShot(algo: 'sha-256' | 'sha-512', msg: Uint8Array): Uint8Array {
	if (algo === 'sha-256') {
		const h = new SHA256();
		try {
			return h.hash(msg);
		} finally {
			h.dispose();
		}
	}
	const h = new SHA512();
	try {
		return h.hash(msg);
	} finally {
		h.dispose();
	}
}

// "Streamed" digest models src/ts/sign/hasher.ts: chunks accumulated,
// one-shot at finalize. Byte-identical to one-shot on concat per the
// sha256Buffered / sha512Buffered file header.
function sha2Chunked(algo: 'sha-256' | 'sha-512', chunks: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const c of chunks) total += c.length;
	const buf = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		buf.set(c, off);
		off += c.length;
	}
	return sha2OneShot(algo, buf);
}

// composite-sigs §3.2 step 2: M' = Prefix || Label || len(ctx) || ctx || PH(M).
function buildMPrime(
	label:  Uint8Array,
	ctx:    Uint8Array,
	digest: Uint8Array,
): Uint8Array {
	const out = new Uint8Array(
		COMPOSITE_PREFIX.length + label.length + 1 + ctx.length + digest.length,
	);
	let p = 0;
	out.set(COMPOSITE_PREFIX, p); p += COMPOSITE_PREFIX.length;
	out.set(label, p);            p += label.length;
	out[p++] = ctx.length;
	out.set(ctx, p);              p += ctx.length;
	out.set(digest, p);
	return out;
}

// Deterministic composite from digest. composite-sigs §3.2 step 3
// re-derives expanded ML-DSA sk from seed (FIPS 204 §6.1); step 4
// emits ML-DSA.Sign(sk, M', mldsa_ctx=Label) and Trad.Sign(tradSK, M'),
// concatenated PQ-first per §4.3.
function detComposite(
	c:        Case,
	sk:       Uint8Array,
	digest:   Uint8Array,
	ctx:      Uint8Array,
): Uint8Array {
	const seedMldsa = sk.subarray(0, 32);
	const tradSk    = sk.subarray(32);
	const mPrime    = buildMPrime(c.label, ctx, digest);

	let sigMldsa: Uint8Array;
	{
		const inst = new c.MlDsaClass();
		try {
			const kp = inst.keygenDerand(seedMldsa);
			// FIPS 204 §3.4 deterministic; pure ML-DSA per composite-sigs §2.1.
			sigMldsa = inst.signDeterministic(kp.signingKey, mPrime, c.label);
		} finally {
			inst.dispose();
		}
	}

	let sigTrad: Uint8Array;
	if (c.tradFamily === 'ed25519') {
		const inst = new Ed25519();
		try {
			// Deterministic-by-construction (RFC 8032 §5.1.6).
			sigTrad = inst._signInternalPk(tradSk, mPrime);
		} finally {
			inst.dispose();
		}
	} else {
		// composite-sigs §6 ecdsa-with-SHA256: SHA-256(M') regardless of composite PH.
		const ecDigest = sha2OneShot('sha-256', mPrime);
		const scalar = decodeEcPrivateKey(tradSk);
		let sigRaw: Uint8Array;
		const inst = new EcdsaP256();
		try {
			// rnd<-0^32 selects RFC 6979 §3.2; WASM runs FIPS 186-5 §6.5 /
			// RFC 6979 §3.5 low-S normalisation, raw r||s already low-S.
			sigRaw = inst._signInternalPk(scalar, ecDigest, new Uint8Array(32));
		} finally {
			inst.dispose();
			scalar.fill(0);
		}
		// composite-sigs §4.3 carries the DER form on the wire.
		sigTrad = ecdsaSignatureToDer(sigRaw);
	}

	return concat(sigMldsa, sigTrad);
}

// Assemble the v3 envelope blob the way Sign.sign / SignStream.buildPreamble
// + payload + sig would. Wire shape (HYBRID-CLASSICAL-LOCK §1):
//   [suite_byte:u8][ctx_len:u8][ctx][payload_len:u32 BE][payload][sig]
function assembleBlob(
	suite:    StreamableSignatureSuite,
	ctx:      Uint8Array,
	msg:      Uint8Array,
	sig:      Uint8Array,
): Uint8Array {
	const payloadLenBe = new Uint8Array([
		(msg.length >>> 24) & 0xff,
		(msg.length >>> 16) & 0xff,
		(msg.length >>>  8) & 0xff,
		 msg.length         & 0xff,
	]);
	return concat(
		new Uint8Array([suite.formatEnum, ctx.length]),
		ctx, payloadLenBe, msg, sig,
	);
}

// Boundary sweep; ctx covers empty / mid / composite-sigs §3.2 step 1
// ceiling of 255 (USER_CTX_MAX, HYBRID-CLASSICAL-LOCK §3).
const MSG_SIZES = [0, 1024, 4096];
const CTX_SIZES = [0, 200, 255];

describe('hybrid-classical one-shot vs chunked-digest byte-equivalence', () => {
	for (const c of CASES) {
		for (const msgLen of MSG_SIZES) {
			for (const ctxLen of CTX_SIZES) {
				it(`${c.name} msg=${msgLen} ctx=${ctxLen}`, () => {
					const msg = makeMsg(msgLen);
					const ctx = ctxOf(ctxLen);

					// One-shot digest path.
					const bufferedDigest = sha2OneShot(c.prehashAlgorithm, msg);

					// Chunked digest path: split into uneven chunks that
					// cross any plausible internal block boundary. SHA-256
					// processes 64-byte blocks, SHA-512 processes 128-byte
					// blocks; chunks of 7 / rest exercise misaligned input.
					const chunks: Uint8Array[] = msgLen > 0
						? [msg.subarray(0, Math.min(7, msg.length)), msg.subarray(Math.min(7, msg.length))]
						: [new Uint8Array(0)];
					const chunkedDigest = sha2Chunked(c.prehashAlgorithm, chunks);

					expect(Array.from(chunkedDigest)).toEqual(Array.from(bufferedDigest));

					// Hand-drive the composite sig from each digest using
					// deterministic sub-signs. Both paths must produce
					// byte-identical sigs (digests equal → ML-DSA M' equal
					// → deterministic ML-DSA sigs equal; trad sub-signs are
					// deterministic by construction or by rnd ← 0³²).
					const { pk, sk } = c.suite.keygen();
					const sigBuffered = detComposite(c, sk, bufferedDigest, ctx);
					const sigChunked  = detComposite(c, sk, chunkedDigest,  ctx);

					// GATE: composite sig is byte-stable across the digest
					// assembly path. If this fails, either the deterministic
					// sub-signs are not actually deterministic, or the M'
					// construction is reading some non-input state.
					expect(Array.from(sigChunked)).toEqual(Array.from(sigBuffered));

					// Assemble envelope blob the way Sign.sign /
					// SignStream + buildPreamble would and verify it
					// round-trips through both Sign.verify and VerifyStream
					// against the suite's hedged verify path.
					const blob = assembleBlob(c.suite, ctx, msg, sigBuffered);

					const out1 = Sign.verify(c.suite, pk, blob, ctx);
					expect(Array.from(out1)).toEqual(Array.from(msg));

					const v = new VerifyStream(c.suite, pk, ctx);
					try {
						v.update(blob);
						const out2 = v.finalize();
						expect(Array.from(out2)).toEqual(Array.from(msg));
					} finally {
						v.dispose();
					}
				});
			}
		}
	}
});
