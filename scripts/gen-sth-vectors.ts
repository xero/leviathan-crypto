// scripts/gen-sth-vectors.ts
//
// One-shot generator for the two STH wire-format vector files:
//   test/vectors/sign_sth_ed25519.ts
//   test/vectors/sign_sth_mldsa44.ts
//
// Each record locks the c2sp.org/signed-note envelope bytes produced
// by `SignedLog.signCheckpoint({ timestamp })` for a fixed
// (origin, leaves, signing key, timestamp) tuple over a Sha256Tree.
// Byte-stability is provided by:
//
//   - Ed25519: RFC 8032 §5.1.6 is deterministic by construction, so
//     `SignedLog<Ed25519Suite>.signCheckpoint` already produces
//     byte-stable bytes.
//   - ML-DSA-44: the suite's production sign is hedged per FIPS 204
//     §3.4, so we drop down to `MlDsa44.signDeterministic` on the
//     cosigned_message bytes and assemble the envelope by hand. The
//     resulting envelope verifies via
//     `SignedLog<MlDsa44Suite>.verifyCheckpoint` (verify is
//     deterministic given the recorded sig). Production code that
//     calls `SignedLog.signCheckpoint` still goes through the hedged
//     path and produces a different (also valid) envelope on each
//     call; only the wire-format lock here uses the deterministic
//     primitive entry point.
//
// Run as:
//   bun scripts/gen-sth-vectors.ts
// then commit the two regenerated vector files.

import { writeFileSync } from 'node:fs';
import {
	init,
	bytesToHex,
} from '../src/ts/index.js';
import { ed25519Wasm } from '../src/ts/ed25519/embedded.js';
import { mldsaWasm } from '../src/ts/mldsa/embedded.js';
import { sha3Wasm } from '../src/ts/sha3/embedded.js';
import { sha2Wasm } from '../src/ts/sha2/embedded.js';
import { Ed25519 } from '../src/ts/ed25519/index.js';
import { MlDsa44 } from '../src/ts/mldsa/index.js';
import {
	Ed25519Suite,
	MlDsa44Suite,
} from '../src/ts/sign/index.js';
import {
	SignedLog,
	Sha256Tree,
	MemoryStorage,
	serializeCheckpointBody,
	buildCosignedMessage,
	emitCosigSignaturePayload,
	emitSignedNote,
	deriveKeyId,
	ALGO_BYTE_MLDSA44_COSIG,
} from '../src/ts/merkle/index.js';
import { buildEffectiveCtx } from '../src/ts/sign/ctx.js';
import { utf8ToBytes } from '../src/ts/utils.js';

await init({
	ed25519: ed25519Wasm,
	mldsa:   mldsaWasm,
	sha3:    sha3Wasm,
	sha2:    sha2Wasm,
});

// ── Shared header ───────────────────────────────────────────────────────────

const ASCII_HEADER = `//                  ▄▄▄▄▄▄▄▄▄▄
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
`;

interface RecordSpec {
	id: string;
	desc: string;
	origin: string;
	/** UTF-8 leaves appended to a fresh Sha256Tree; test reproduces by replay. */
	leaves: string[];
	/** 32-byte seed for keygenDerand; test reproduces by replay. */
	seedHex: string;
	timestamp: number;
}

const SPECS: RecordSpec[] = [
	{
		id: 'V1',
		desc: 'V1, single-leaf log, timestamp = c2sp.org/tlog-cosignature §"Ed25519 signed message" example value',
		origin: 'leviathan.test/log1',
		leaves: ['leaf-0-leviathan-crypto'],
		seedHex: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
		timestamp: 1679315147,
	},
	{
		id: 'V2',
		desc: 'V2, three-leaf log, timestamp 1700000000',
		origin: 'leviathan.test/log2',
		leaves: ['leaf-A', 'leaf-B', 'leaf-C'],
		seedHex: '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
		timestamp: 1700000000,
	},
	{
		id: 'V3',
		desc: 'V3, seven-leaf log, larger timestamp covering the BE u64 high-byte boundary',
		origin: 'sigsum.example.org/v1/transparency-log',
		leaves: ['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6'],
		seedHex: '4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60',
		timestamp: 9999999999,
	},
];

function hexToBytes(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length >>> 1);
	for (let i = 0; i < out.length; i++)
		out[i] = parseInt(hex.substring(i << 1, (i << 1) + 2), 16);
	return out;
}

function chunkHex(hex: string, perLine = 64): string {
	const parts: string[] = [];
	for (let i = 0; i < hex.length; i += perLine) parts.push(hex.slice(i, i + perLine));
	return parts.map((p, i) => `\t\t\t'${p}'${i === parts.length - 1 ? '' : ' +'}`).join('\n');
}

function recordHexLine(label: string, hex: string): string {
	if (hex.length <= 64) return `\t\t${label}: '${hex}',`;
	return `\t\t${label}:\n${chunkHex(hex)},`;
}

function recordLeaves(label: string, leaves: string[]): string {
	const items = leaves.map(l => `\t\t\t${JSON.stringify(l)},`).join('\n');
	return `\t\t${label}: [\n${items}\n\t\t],`;
}

// Build a fresh Sha256Tree backed by MemoryStorage, append leaves,
// return (tree, size, root). Replayed in tests.
function buildTree(leaves: string[]): { tree: Sha256Tree; treeSize: number; rootHash: Uint8Array } {
	const tree = new Sha256Tree(new MemoryStorage());
	for (const l of leaves) tree.append(utf8ToBytes(l));
	return { tree, treeSize: tree.size(), rootHash: tree.rootHash() };
}

// ── Ed25519 records ─────────────────────────────────────────────────────────

interface BuiltRecord {
	id: string;
	desc: string;
	origin: string;
	leaves: string[];
	treeSize: number;
	rootHashHex: string;
	seedHex: string;
	skHex: string;
	pkHex: string;
	timestamp: number;
	bodyHex: string;
	signedMessageHex: string;
	keyIdHex: string;
	sigHex: string;
	cosigPayloadHex: string;
	envelopeHex: string;
}

function buildEd25519Records(): BuiltRecord[] {
	return SPECS.map(s => {
		const seed = hexToBytes(s.seedHex);
		const inst = new Ed25519();
		let pk: Uint8Array;
		let sk: Uint8Array;
		try {
			const kp = inst.keygenDerand(seed);
			pk = kp.publicKey;
			sk = kp.secretKey;
		} finally {
			inst.dispose();
		}

		const { tree, treeSize, rootHash } = buildTree(s.leaves);
		const log = new SignedLog({
			tree,
			suite: Ed25519Suite,
			origin: s.origin,
			signingKey: sk,
			pubkey: pk,
		});
		try {
			const envelope = log.signCheckpoint({ timestamp: s.timestamp });
			// Sanity check: round-trip verify.
			if (!log.verifyCheckpoint(envelope))
				throw new Error(`${s.id}: SignedLog.verifyCheckpoint rejected freshly-generated envelope`);

			// Recompute the intermediate values for the vector record.
			const body = serializeCheckpointBody({
				origin: s.origin, treeSize, rootHash,
			});
			const signedMessage =
				new TextEncoder().encode(`cosignature/v1\ntime ${s.timestamp}\n`);
			const signedMessageFull = new Uint8Array(signedMessage.length + body.length);
			signedMessageFull.set(signedMessage, 0);
			signedMessageFull.set(body, signedMessage.length);
			// Detached signature is the last 64 bytes of the
			// timestamped_signature payload inside the envelope.
			const ed = new Ed25519();
			let sigBytes: Uint8Array;
			try {
				sigBytes = ed._signInternalPk(sk, signedMessageFull);
			} finally {
				ed.dispose();
			}
			const cosigPayload = emitCosigSignaturePayload(s.timestamp, sigBytes);
			const keyId = deriveKeyId(s.origin, 0x04, pk);

			return {
				id: s.id,
				desc: s.desc,
				origin: s.origin,
				leaves: s.leaves,
				treeSize,
				rootHashHex: bytesToHex(rootHash),
				seedHex: s.seedHex,
				skHex: bytesToHex(sk),
				pkHex: bytesToHex(pk),
				timestamp: s.timestamp,
				bodyHex: bytesToHex(body),
				signedMessageHex: bytesToHex(signedMessageFull),
				keyIdHex: bytesToHex(keyId),
				sigHex: bytesToHex(sigBytes),
				cosigPayloadHex: bytesToHex(cosigPayload),
				envelopeHex: bytesToHex(envelope),
			};
		} finally {
			log.dispose();
		}
	});
}

// ── ML-DSA-44 records ───────────────────────────────────────────────────────

function buildMlDsa44Records(): BuiltRecord[] {
	return SPECS.map(s => {
		const seed = hexToBytes(s.seedHex);
		const inst = new MlDsa44();
		let pk: Uint8Array;
		let sk: Uint8Array;
		const { tree, treeSize, rootHash } = buildTree(s.leaves);
		const body = serializeCheckpointBody({
			origin: s.origin, treeSize, rootHash,
		});
		const cosignedMessage = buildCosignedMessage({
			cosignerName: s.origin,
			timestamp: s.timestamp,
			logOrigin: s.origin,
			start: 0,
			end: treeSize,
			hash: rootHash,
		});
		let sigBytes: Uint8Array;
		try {
			const kp = inst.keygenDerand(seed);
			pk = kp.verificationKey;
			sk = kp.signingKey;
			// Match what MlDsa44Suite.sign would feed to inst.sign,
			// but route through signDeterministic for byte stability.
			// The suite binds ctxDomain = 'mldsa44-envelope-v3' into
			// the effective ctx; SignedLog passes EMPTY_CTX to
			// suite.sign so the user-side ctx is empty.
			const effectiveCtx = buildEffectiveCtx(MlDsa44Suite.ctxDomain, new Uint8Array(0));
			sigBytes = inst.signDeterministic(sk, cosignedMessage, effectiveCtx);
		} finally {
			inst.dispose();
		}

		// Hand-assemble the envelope with the deterministic sig.
		const cosigPayload = emitCosigSignaturePayload(s.timestamp, sigBytes);
		const keyId = deriveKeyId(s.origin, ALGO_BYTE_MLDSA44_COSIG, pk);
		const envelope = emitSignedNote(body, [{
			name: s.origin,
			keyId,
			signature: cosigPayload,
		}]);

		// Sanity check via SignedLog.verifyCheckpoint: a hedged-
		// production verifier holding this deterministic envelope
		// must accept it.
		const log2 = new SignedLog({
			tree,
			suite: MlDsa44Suite,
			origin: s.origin,
			signingKey: sk,
			pubkey: pk,
		});
		try {
			if (!log2.verifyCheckpoint(envelope))
				throw new Error(`${s.id}: SignedLog<MlDsa44>.verifyCheckpoint rejected deterministic envelope`);
		} finally {
			log2.dispose();
		}

		return {
			id: s.id,
			desc: s.desc,
			origin: s.origin,
			leaves: s.leaves,
			treeSize,
			rootHashHex: bytesToHex(rootHash),
			seedHex: s.seedHex,
			skHex: bytesToHex(sk),
			pkHex: bytesToHex(pk),
			timestamp: s.timestamp,
			bodyHex: bytesToHex(body),
			signedMessageHex: bytesToHex(cosignedMessage),
			keyIdHex: bytesToHex(keyId),
			sigHex: bytesToHex(sigBytes),
			cosigPayloadHex: bytesToHex(cosigPayload),
			envelopeHex: bytesToHex(envelope),
		};
	});
}

// ── Emit files ──────────────────────────────────────────────────────────────

function emitVectorFile(
	path: string,
	suiteHeader: string,
	typeName: string,
	exportName: string,
	records: BuiltRecord[],
): void {
	const body = records.map(r => `\t{
\t\tid: '${r.id}',
\t\tdesc: ${JSON.stringify(r.desc)},
\t\torigin: ${JSON.stringify(r.origin)},
${recordLeaves('leaves', r.leaves)}
\t\ttreeSize: ${r.treeSize},
${recordHexLine('rootHashHex', r.rootHashHex)}
${recordHexLine('seedHex', r.seedHex)}
${recordHexLine('skHex', r.skHex)}
${recordHexLine('pkHex', r.pkHex)}
\t\ttimestamp: ${r.timestamp},
${recordHexLine('bodyHex', r.bodyHex)}
${recordHexLine('signedMessageHex', r.signedMessageHex)}
${recordHexLine('keyIdHex', r.keyIdHex)}
${recordHexLine('sigHex', r.sigHex)}
${recordHexLine('cosigPayloadHex', r.cosigPayloadHex)}
${recordHexLine('envelopeHex', r.envelopeHex)}
\t},`).join('\n');

	const file = ASCII_HEADER + suiteHeader + `
export interface ${typeName} {
\tid:               string;
\tdesc:             string;
\torigin:           string;
\tleaves:           string[];
\ttreeSize:         number;
\trootHashHex:      string;
\tseedHex:          string;
\tskHex:            string;
\tpkHex:            string;
\ttimestamp:        number;
\tbodyHex:          string;
\tsignedMessageHex: string;
\tkeyIdHex:         string;
\tsigHex:           string;
\tcosigPayloadHex:  string;
\tenvelopeHex:      string;
}

export const ${exportName}: ${typeName}[] = [
${body}
];
`;
	writeFileSync(path, file);
	console.log(`Wrote ${path} with ${records.length} records`);
}

const ED25519_HEADER = `// test/vectors/sign_sth_ed25519.ts
//
// SignedLog<Ed25519Suite> wire-format KAT vectors per
// c2sp.org/tlog-cosignature §Format and §"Ed25519 signed message".
//
// Each record carries a fixed (origin, leaves, seed, timestamp)
// tuple. The leaves are appended to a fresh Sha256Tree to derive
// the recorded treeSize and rootHash; the seed feeds Ed25519
// keygenDerand to derive (sk, pk). The envelope is the byte-stable
// output of \`SignedLog.signCheckpoint({ timestamp })\` for this
// configuration; byte stability is provided by RFC 8032 §5.1.6
// (Ed25519 sign is deterministic).
//
// Audit status: SELF-GENERATED. Cross-checked by
// scripts/verify-vectors/src/sign_sth.rs against ed25519-dalek.
//
// C2SP commit pinned for this corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).
`;

const MLDSA44_HEADER = `// test/vectors/sign_sth_mldsa44.ts
//
// SignedLog<MlDsa44Suite> wire-format KAT vectors per
// c2sp.org/tlog-cosignature §Format and §"ML-DSA-44 signed message".
//
// Each record carries a fixed (origin, leaves, seed, timestamp)
// tuple. The leaves are appended to a fresh Sha256Tree to derive
// the recorded treeSize and rootHash; the seed feeds ML-DSA-44
// keygenDerand to derive (sk, pk). The recorded envelope is
// byte-stable: it is generated via the deterministic primitive
// entry point \`MlDsa44.signDeterministic\` over the
// cosigned_message struct from §"ML-DSA-44 signed message", because
// the production hedged path (\`MlDsa44Suite.sign\` -> \`inst.sign\`)
// would produce a different (also valid) envelope on each call.
//
// Verifying these envelopes through \`SignedLog<MlDsa44Suite>.verifyCheckpoint\`
// is the actual roundtrip gate (verify is deterministic given the
// recorded sig). The production sign path is exercised by a
// roundtrip test that signs, then verifies, with no byte-equality
// expectation.
//
// Audit status: SELF-GENERATED. Cross-checked by
// scripts/verify-vectors/src/sign_sth.rs against the RustCrypto
// \`ml-dsa\` crate.
//
// C2SP commit pinned for this corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).
`;

emitVectorFile(
	'test/vectors/sign_sth_ed25519.ts',
	ED25519_HEADER,
	'SignSthEd25519Vector',
	'signSthEd25519Vectors',
	buildEd25519Records(),
);

emitVectorFile(
	'test/vectors/sign_sth_mldsa44.ts',
	MLDSA44_HEADER,
	'SignSthMldsa44Vector',
	'signSthMldsa44Vectors',
	buildMlDsa44Records(),
);
