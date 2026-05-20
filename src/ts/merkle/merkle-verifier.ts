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
// src/ts/merkle/merkle-verifier.ts
//
// `MerkleVerifier`, verify-only normie surface. Wire format per
// c2sp.org/signed-note §Format, c2sp.org/tlog-checkpoint §Note text,
// and c2sp.org/tlog-cosignature §Format.

import { isInitialized } from '../init.js';
import type { Module } from '../init.js';
import { MerkleLogError, MerkleCodecError } from '../errors.js';
import { constantTimeEqual } from '../utils.js';
import {
	parseSignedNote,
	lookupAlgoEntryByFormatEnum,
	deriveKeyId,
	buildCosigSignedMessage,
	buildCosignedMessage,
	parseCosigSignaturePayload,
} from './signed-note.js';
import { parseCheckpointBody } from './checkpoint.js';
import { verifyInclusionProof, verifyConsistencyProof } from './proof.js';
import { Sha256Hasher } from './sha256-tree.js';
import { Blake3Hasher } from './blake3-tree.js';
import type { AlgoEntry } from './signed-note.js';
import type { Hasher } from './tree.js';
import type { Checkpoint } from './checkpoint.js';
import type { SignatureSuite } from '../sign/types.js';

// Empty ctx for suite.verify; domain separation lives in the
// cosignature signed-message construction (cosignature/v1 prefix for
// Ed25519, cosigned_message label for ML-DSA-44) per
// c2sp.org/tlog-cosignature §Format.
const EMPTY_CTX = new Uint8Array(0);

const SHA2_MODULE = 'sha2';

/**
 * Construction options for `MerkleVerifier`.
 */
export interface MerkleVerifierOpts {
	/**
	 * Log identity, the first line of every checkpoint body. Validated
	 * at construction (non-empty, no whitespace, no plus characters)
	 * per c2sp.org/tlog-checkpoint §Note text.
	 */
	readonly origin: string;
	/**
	 * Trusted public key for the log's primary cosignature line. Length
	 * must equal `suite.pkSize`; a constructor-time mismatch raises
	 * `MerkleLogError('pubkey-size')`.
	 */
	readonly pubkey: Uint8Array;
	/**
	 * Hash function the log's tree uses. `'sha256'` resolves to
	 * `Sha256Hasher`, `'blake3'` resolves to `Blake3Hasher`. The
	 * verifier hashes leaf bytes with this function before calling
	 * `verifyInclusionProof`.
	 */
	readonly hashing: 'sha256' | 'blake3';
	/**
	 * Signature suite the log signs cosignatures with. Must be a suite
	 * whose `formatEnum` is registered in the c2sp.org/tlog-cosignature
	 * §Format algorithm-byte registry; today that is `Ed25519Suite`
	 * and `MlDsa44Suite`. Other suites raise
	 * `MerkleLogError('unsupported-suite')`.
	 */
	readonly suite: SignatureSuite;
}

/**
 * Trust-anchored verifier for c2sp.org/tlog-checkpoint envelopes.
 * Takes a fixed log identity at construction and exposes three verify
 * methods (`verifyCheckpoint`, `verifyInclusion`, `verifyConsistency`)
 * that return `boolean`.
 *
 * Construction is the only place this class throws; every verify path
 * returns `false` on any failure mode including malformed bytes,
 * tampered envelopes, wrong origin, wrong leaf, and signature failure.
 * The convention matches `SignatureSuite.verify` and lets normie
 * callers write a single `if (!verifier.verifyX(...)) reject()` line
 * per check without a try / catch.
 */
export class MerkleVerifier {
	readonly origin: string;
	readonly pubkey: Uint8Array;
	readonly hasher: Hasher;
	readonly suite: SignatureSuite;

	private readonly _algoEntry: AlgoEntry;
	private readonly _keyId: Uint8Array;

	constructor(opts: MerkleVerifierOpts) {
		const { origin, pubkey, hashing, suite } = opts;

		if (typeof origin !== 'string' || origin.length === 0)
			throw new MerkleLogError(
				'origin-invalid',
				'MerkleVerifier: origin must be a non-empty string',
			);
		// c2sp.org/tlog-checkpoint §Note text MUSTs, mirrored from
		// `SignedLog`'s constructor: the origin is the first body line
		// and may not contain whitespace or plus characters.
		if (/\s/.test(origin) || origin.includes('+'))
			throw new MerkleLogError(
				'origin-invalid',
				'MerkleVerifier: origin must not contain whitespace or plus characters',
			);

		if (!(pubkey instanceof Uint8Array))
			throw new MerkleLogError(
				'pubkey-size',
				'MerkleVerifier: pubkey must be a Uint8Array',
			);

		const hasher = resolveHasher(hashing);

		const algoEntry = lookupAlgoEntryByFormatEnum(suite.formatEnum);
		if (algoEntry === undefined)
			throw new MerkleLogError(
				'unsupported-suite',
				`MerkleVerifier: suite '${suite.formatName}' (formatEnum 0x${suite.formatEnum
					.toString(16)
					.padStart(2, '0')}) has no c2sp.org/tlog-cosignature §Format algorithm byte; `
				+ 'use Ed25519Suite or MlDsa44Suite, or open an issue for a newly C2SP-registered suite',
			);

		if (pubkey.length !== suite.pkSize)
			throw new MerkleLogError(
				'pubkey-size',
				`MerkleVerifier: pubkey length ${pubkey.length} != suite.pkSize ${suite.pkSize}`,
			);

		// Same modules `SignedLog` requires: the suite's modules, the
		// hasher's module, and sha2 for `deriveKeyId`. Constructor-time
		// check so a verifier built before `init()` fails at construction
		// rather than on first `verifyCheckpoint` call.
		assertModulesInitialized([
			...suite.wasmModules,
			...hasher.wasmModules,
			SHA2_MODULE,
		]);

		this.origin = origin;
		this.pubkey = pubkey.slice();
		this.hasher = hasher;
		this.suite = suite;
		this._algoEntry = algoEntry;
		this._keyId = deriveKeyId(origin, algoEntry.algoByte, this.pubkey);
	}

	/**
	 * Verify a signed-note envelope against this verifier's identity.
	 * Returns `true` iff the envelope parses, the body's origin equals
	 * the constructor origin, the body's root-hash length equals the
	 * hasher's `outputSize`, a signature line's keyId equals the
	 * pubkey-derived keyId, the `timestamped_signature` payload on
	 * that line decodes cleanly, and `suite.verify` accepts the
	 * reconstructed cosignature signed message.
	 *
	 * Returns `false` on every other path. Never throws on envelope
	 * content.
	 */
	verifyCheckpoint(envelopeBytes: Uint8Array): boolean {
		const parsed = this._parseAndVerify(envelopeBytes);
		return parsed !== null;
	}

	/**
	 * Verify a leaf's inclusion in the tree committed by an envelope.
	 * Runs `verifyCheckpoint` first; on failure returns `false`
	 * without examining the proof. On success, hashes `leafBytes`
	 * with the verifier's `Hasher` and calls `verifyInclusionProof`
	 * against the body's `treeSize` and `rootHash` per RFC 9162 §2.1.3.
	 *
	 * The "verify checkpoint first" ordering is the security-critical
	 * step: the proof is bound to the root hash inside the signed body,
	 * so trusting the proof before checking the signature would let any
	 * forger pair a malicious proof with their own root.
	 */
	verifyInclusion(opts: {
		envelopeBytes: Uint8Array;
		leafBytes: Uint8Array;
		leafIndex: number;
		proof: readonly Uint8Array[];
	}): boolean {
		const parsed = this._parseAndVerify(opts.envelopeBytes);
		if (parsed === null) return false;
		if (!(opts.leafBytes instanceof Uint8Array)) return false;
		if (!Number.isInteger(opts.leafIndex) || opts.leafIndex < 0) return false;
		if (opts.leafIndex >= parsed.treeSize) return false;
		if (!Array.isArray(opts.proof)) return false;
		for (const h of opts.proof)
			if (!(h instanceof Uint8Array)) return false;

		// RFC 9162 §2.1.1: leaf-hash domain separation happens here;
		// the proof verifier expects the MTH({d}) of the leaf, not the
		// raw leaf bytes. Computing it locally rather than accepting a
		// caller-supplied leaf hash closes the "we trust the proof
		// because we trust the leaf hash the caller gave us" gap.
		const leafHash = this.hasher.hashLeaf(opts.leafBytes);
		try {
			return verifyInclusionProof({
				hasher: this.hasher,
				leafHash,
				leafIndex: opts.leafIndex,
				treeSize: parsed.treeSize,
				proof: opts.proof,
				rootHash: parsed.rootHash,
			});
		} catch {
			// `verifyInclusionProof` throws on a wrong-sized rootHash or
			// out-of-range leafIndex. Convert to a verify-false: the
			// normie surface keeps a single failure mode.
			return false;
		}
	}

	/**
	 * Verify that the tree committed by `oldEnvelopeBytes` is a prefix
	 * of the tree committed by `newEnvelopeBytes`. Both envelopes must
	 * verify under this verifier's identity; if either fails, returns
	 * `false`. On success, calls `verifyConsistencyProof` per
	 * RFC 9162 §2.1.4 against the two sizes and roots.
	 */
	verifyConsistency(opts: {
		oldEnvelopeBytes: Uint8Array;
		newEnvelopeBytes: Uint8Array;
		proof: readonly Uint8Array[];
	}): boolean {
		const oldParsed = this._parseAndVerify(opts.oldEnvelopeBytes);
		if (oldParsed === null) return false;
		const newParsed = this._parseAndVerify(opts.newEnvelopeBytes);
		if (newParsed === null) return false;
		if (!Array.isArray(opts.proof)) return false;
		for (const h of opts.proof)
			if (!(h instanceof Uint8Array)) return false;

		try {
			return verifyConsistencyProof({
				hasher: this.hasher,
				oldSize: oldParsed.treeSize,
				newSize: newParsed.treeSize,
				oldRoot: oldParsed.rootHash,
				newRoot: newParsed.rootHash,
				proof: opts.proof,
			});
		} catch {
			return false;
		}
	}

	// ── internal ────────────────────────────────────────────────────────

	/**
	 * Parse a signed-note envelope, verify the cosignature, and return
	 * the decoded `Checkpoint`. Returns `null` on any failure mode:
	 * malformed envelope, malformed body, wrong origin, wrong root-hash
	 * length, no matching keyId line, malformed payload, signature
	 * failure. Keyed-ID comparison uses `constantTimeEqual` for hygiene
	 * around key-material-adjacent state.
	 */
	private _parseAndVerify(bytes: Uint8Array): Checkpoint | null {
		if (!(bytes instanceof Uint8Array)) return null;
		let env;
		try {
			env = parseSignedNote(bytes);
		} catch {
			return null;
		}
		let checkpoint;
		try {
			checkpoint = parseCheckpointBody(env.body, this.hasher.outputSize);
		} catch {
			return null;
		}
		if (checkpoint.origin !== this.origin) return null;
		if (checkpoint.rootHash.length !== this.hasher.outputSize) return null;

		const matching = env.signatures.find(s =>
			s.keyId.length === this._keyId.length
			&& constantTimeEqual(s.keyId, this._keyId),
		);
		if (!matching) return null;

		let payload;
		try {
			payload = parseCosigSignaturePayload(matching.signature, this._algoEntry.sigSize);
		} catch (err) {
			if (err instanceof MerkleCodecError) return null;
			throw err;
		}

		let signedMessage;
		try {
			signedMessage = this._buildSignedMessage(env.body, payload.timestamp, checkpoint);
		} catch {
			return null;
		}

		const ok = this.suite.verify(this.pubkey, signedMessage, payload.signature, EMPTY_CTX);
		return ok ? checkpoint : null;
	}

	/**
	 * Dispatch cosignature signed-message construction on the algorithm
	 * registry entry's `messageConstruction`. Mirrors `SignedLog`'s
	 * dispatch so producer and verifier always agree on the bytes the
	 * suite verifies against.
	 *
	 *   'cosig'             c2sp.org/tlog-cosignature §"Ed25519 signed
	 *                       message". The full envelope body is embedded
	 *                       verbatim after the cosignature/v1 + time
	 *                       prefix.
	 *
	 *   'cosigned-message'  c2sp.org/tlog-cosignature §"ML-DSA-44
	 *                       signed message". cosigner_name and
	 *                       log_origin both equal the checkpoint origin
	 *                       for a log's self-cosignature; start == 0;
	 *                       end == treeSize; hash == rootHash.
	 */
	private _buildSignedMessage(
		body: Uint8Array,
		timestamp: number,
		cp: Checkpoint,
	): Uint8Array {
		if (this._algoEntry.messageConstruction === 'cosig')
			return buildCosigSignedMessage(body, timestamp);
		return buildCosignedMessage({
			cosignerName: this.origin,
			timestamp,
			logOrigin: this.origin,
			start: 0,
			end: cp.treeSize,
			hash: cp.rootHash,
		});
	}
}

function resolveHasher(hashing: string): Hasher {
	if (hashing === 'sha256') return Sha256Hasher;
	if (hashing === 'blake3') return Blake3Hasher;
	throw new MerkleLogError(
		'unsupported-hashing',
		`MerkleVerifier: hashing must be 'sha256' or 'blake3', got '${hashing}'`,
	);
}

function assertModulesInitialized(modules: readonly string[]): void {
	const seen = new Set<string>();
	for (const mod of modules) {
		if (seen.has(mod)) continue;
		seen.add(mod);
		if (!isInitialized(mod as Module))
			throw new MerkleLogError(
				'module-not-initialized',
				`MerkleVerifier: WASM module '${mod}' is not initialized; `
				+ 'call init() with the appropriate sources before constructing MerkleVerifier',
			);
	}
}
