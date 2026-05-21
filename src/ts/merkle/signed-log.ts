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
// src/ts/merkle/signed-log.ts
//
// `SignedLog<S extends SignatureSuite>` ties a `MerkleTree` (Sha256Tree
// or Blake3Tree), a `SignatureSuite` registered in the C2SP cosignature
// algorithm-byte registry, and an origin string into one object that
// produces signed checkpoints, verifies received checkpoints, and
// exposes inclusion / consistency proofs.
//
// Wire format per c2sp.org/tlog-cosignature §Format and §"Ed25519
// signed message" / §"ML-DSA-44 signed message":
//
//   envelope = emitSignedNote(body, [
//     { name: origin,
//       keyId: deriveKeyId(origin, algoByte, pubkey),
//       signature: emitCosigSignaturePayload(timestamp, sig) },
//   ])
//
// where `sig` is the result of `suite.sign(sk, signedMessage, EMPTY_CTX)`
// and `signedMessage` is dispatched on `algoEntry.messageConstruction`:
//
//   'cosig'             → buildCosigSignedMessage(body, timestamp)
//                         "cosignature/v1\ntime <ts>\n<body>"
//                         (Ed25519, C2SP algo byte 0x04)
//
//   'cosigned-message'  → buildCosignedMessage({...})
//                         TLS-Presentation `cosigned_message` struct
//                         (ML-DSA-44, C2SP algo byte 0x06)
//
// Suites without a registered entry (e.g. EcdsaP256Suite, every prehash
// variant, all SLH-DSA, every hybrid) cannot construct a `SignedLog`
// and throw `SigningError('sig-unsupported-suite')` at construction.
//
// C2SP commit pinned for this implementation:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

import { isInitialized } from '../init.js';
import { SigningError, MerkleCodecError } from '../errors.js';
import { constantTimeEqual, wipe } from '../utils.js';
import {
	emitSignedNote,
	parseSignedNote,
	deriveKeyId,
	lookupAlgoEntryByFormatEnum,
	buildCosigSignedMessage,
	buildCosignedMessage,
	emitCosigSignaturePayload,
	parseCosigSignaturePayload,
} from './signed-note.js';
import {
	serializeCheckpointBody,
	parseCheckpointBody,
} from './checkpoint.js';
import type { AlgoEntry, SignatureLine } from './signed-note.js';
import type { SignedTreeHead } from './sth.js';
import type { MerkleTree } from './tree.js';
import type { SignatureSuite } from '../sign/types.js';

// ── Module surface union ────────────────────────────────────────────────────

const SHA2_MODULE = 'sha2';
// Empty ctx passed to suite.sign / suite.verify. Domain separation
// for the signed message is built in to the cosignature/v1 header
// (Ed25519 case) or the cosigned_message label (ML-DSA-44 case);
// the suite-level ctx adds no additional binding.
const EMPTY_CTX = new Uint8Array(0);

function unionModules(...lists: readonly (readonly string[])[]): readonly string[] {
	const seen = new Set<string>();
	for (const list of lists)
		for (const m of list) seen.add(m);
	return Object.freeze([...seen]);
}

function validateOriginAtConstruction(origin: string): void {
	if (origin.length === 0)
		throw new RangeError('SignedLog: origin must be non-empty');
	// c2sp.org/tlog-checkpoint §Note text MUSTs; fail at construction
	// not serialize time.
	if (/\s/.test(origin) || origin.includes('+'))
		throw new RangeError(
			'SignedLog: origin must not contain whitespace or plus characters',
		);
}

// ── SignedLog ───────────────────────────────────────────────────────────────

/**
 * Constructor options for `SignedLog`.
 */
export interface SignedLogOpts<S extends SignatureSuite> {
	/** Underlying Merkle tree, holds the stateful append + proof surface. */
	tree: MerkleTree;
	/**
	 * Signature suite. Must have an entry in the C2SP cosignature
	 * algorithm-byte registry (currently `Ed25519Suite` and
	 * `MlDsa44Suite`); other suites throw `SigningError`.
	 */
	suite: S;
	/**
	 * Log identity, the first line of every checkpoint body. Validated
	 * at construction (non-empty, no whitespace, no plus characters)
	 * per c2sp.org/tlog-checkpoint §Note text.
	 */
	origin: string;
	/**
	 * Signing key, exactly `suite.skSize` bytes. The SignedLog stores
	 * a private copy; `dispose()` zeroes that copy. The caller's view
	 * of the buffer is left untouched.
	 */
	signingKey: Uint8Array;
	/**
	 * Public key, exactly `suite.pkSize` bytes. Used to derive the
	 * 4-byte keyId stamped on every emitted signature line and to
	 * match incoming signature lines during verify.
	 */
	pubkey: Uint8Array;
}

/**
 * Signed transparency log substrate. Combines a `MerkleTree` with a
 * registered cosignature `SignatureSuite` and an origin string;
 * exposes append, proof, and cosignature sign / verify operations.
 *
 * Per-call WASM lifecycle is enforced by the suite itself (see the
 * SignatureSuite factories under `src/ts/sign/suites/`). `SignedLog`
 * does not wrap additional try/finally around `suite.sign` /
 * `suite.verify` because the suite already does. Internally the
 * SignedLog owns a private copy of the signing key wiped by
 * `dispose()`.
 */
export class SignedLog<S extends SignatureSuite> {
	readonly tree: MerkleTree;
	readonly suite: S;
	readonly origin: string;
	readonly pubkey: Uint8Array;
	readonly wasmModules: readonly string[];

	private readonly _algoEntry: AlgoEntry;
	private readonly _keyId: Uint8Array;
	private _signingKey: Uint8Array;
	private _disposed = false;

	constructor(opts: SignedLogOpts<S>) {
		const { tree, suite, origin, signingKey, pubkey } = opts;

		validateOriginAtConstruction(origin);
		if (!(signingKey instanceof Uint8Array))
			throw new TypeError('SignedLog: signingKey must be a Uint8Array');
		if (!(pubkey instanceof Uint8Array))
			throw new TypeError('SignedLog: pubkey must be a Uint8Array');
		if (signingKey.length !== suite.skSize)
			throw new RangeError(
				`SignedLog: signingKey length ${signingKey.length} != suite.skSize ${suite.skSize}`,
			);
		if (pubkey.length !== suite.pkSize)
			throw new RangeError(
				`SignedLog: pubkey length ${pubkey.length} != suite.pkSize ${suite.pkSize}`,
			);

		const algoEntry = lookupAlgoEntryByFormatEnum(suite.formatEnum);
		if (algoEntry === undefined)
			throw new SigningError(
				'sig-unsupported-suite',
				`SignedLog: suite formatEnum 0x${suite.formatEnum.toString(16).padStart(2, '0')} `
				+ `(${suite.formatName}) has no C2SP signed-note algorithm byte registered; `
				+ 'see c2sp.org/tlog-cosignature §Format for the supported algorithms',
			);

		const wasmModules = unionModules(
			tree.hasher.wasmModules,
			suite.wasmModules,
			[SHA2_MODULE],
		);
		for (const mod of wasmModules) {
			if (!isInitialized(mod as never))
				throw new Error(
					`SignedLog: WASM module '${mod}' is not initialized; `
					+ 'call init() with the appropriate sources before constructing SignedLog',
				);
		}

		this.tree = tree;
		this.suite = suite;
		this.origin = origin;
		this.pubkey = pubkey.slice();
		this.wasmModules = wasmModules;
		this._signingKey = signingKey.slice();
		this._algoEntry = algoEntry;
		this._keyId = deriveKeyId(origin, algoEntry.algoByte, this.pubkey);
	}

	// ── Tree passthroughs ──────────────────────────────────────────────

	/**
	 * Append a leaf to the underlying tree and return the new leaf's
	 * index, hash, and inclusion proof against the post-append tree size.
	 */
	append(leafBytes: Uint8Array): {
		leafIndex: number;
		leafHash: Uint8Array;
		inclusionProof: Uint8Array[];
	} {
		this._assertNotDisposed();
		const { leafIndex, leafHash } = this.tree.append(leafBytes);
		const inclusionProof = this.tree.getInclusionProof(leafIndex, this.tree.size());
		return { leafIndex, leafHash, inclusionProof };
	}

	size(): number {
		this._assertNotDisposed();
		return this.tree.size();
	}

	rootHash(): Uint8Array {
		this._assertNotDisposed();
		return this.tree.rootHash();
	}

	getInclusionProof(leafIndex: number, treeSize?: number): Uint8Array[] {
		this._assertNotDisposed();
		return this.tree.getInclusionProof(leafIndex, treeSize);
	}

	getConsistencyProof(oldSize: number, newSize: number): Uint8Array[] {
		this._assertNotDisposed();
		return this.tree.getConsistencyProof(oldSize, newSize);
	}

	// ── Sign + verify ──────────────────────────────────────────────────

	/**
	 * Issue a cosignature over the current checkpoint and emit the
	 * signed-note envelope per c2sp.org/signed-note §Format. The
	 * signature line carries the `timestamped_signature` payload
	 * from c2sp.org/tlog-cosignature §Format; the bytes the suite
	 * signs are dispatched on the algorithm's
	 * `messageConstruction`:
	 *
	 *   - `'cosig'`             → `buildCosigSignedMessage(body, ts)`
	 *                              (Ed25519, §"Ed25519 signed message")
	 *   - `'cosigned-message'`  → `buildCosignedMessage(...)`
	 *                              (ML-DSA-44, §"ML-DSA-44 signed message")
	 *
	 * `timestamp` defaults to current wall-clock POSIX seconds. The
	 * c2sp.org/tlog-witness `add-checkpoint` rule mandates a non-zero
	 * timestamp on production cosignatures; `0` is accepted by this
	 * function for test reproducibility but witness verifiers will
	 * reject envelopes that carry it. Tests and vector generators
	 * pass an explicit value to lock byte stability.
	 */
	signCheckpoint(opts?: { timestamp?: number }): Uint8Array {
		this._assertNotDisposed();
		const timestamp = opts?.timestamp ?? Math.floor(Date.now() / 1000);
		const body = serializeCheckpointBody({
			origin: this.origin,
			treeSize: this.tree.size(),
			rootHash: this.tree.rootHash(),
		});
		const signedMessage = this._buildSignedMessage(body, timestamp);
		const sig = this.suite.sign(this._signingKey, signedMessage, EMPTY_CTX);
		if (sig.length !== this._algoEntry.sigSize)
			throw new SigningError(
				'sig-malformed-input',
				`SignedLog.signCheckpoint: suite.sign returned ${sig.length} bytes, `
				+ `expected ${this._algoEntry.sigSize} per c2sp.org/tlog-cosignature §Format`,
			);
		const payload = emitCosigSignaturePayload(timestamp, sig);
		const line: SignatureLine = {
			name: this.origin,
			keyId: this._keyId,
			signature: payload,
		};
		return emitSignedNote(body, [line]);
	}

	/**
	 * Parse a signed-note envelope into the structured `SignedTreeHead`
	 * form per c2sp.org/signed-note §Format. Surfaces the body's
	 * decoded `Checkpoint`, the signature lines that survived the
	 * permissive signed-note parse, and the primary log cosignature's
	 * POSIX-seconds timestamp (extracted via
	 * `parseCosigSignaturePayload` on the line whose keyId matches
	 * this log's pubkey-derived keyId).
	 *
	 * If no signature line matches, `timestamp` is reported as 0. The
	 * field is informational at parse time; cryptographic verification
	 * lives in `verifyCheckpoint`. Throws `RangeError` on whole-envelope
	 * structural failure (the parseSignedNote / parseCheckpointBody
	 * contract); does not throw on signature line content issues.
	 */
	parseCheckpoint(bytes: Uint8Array): SignedTreeHead {
		this._assertNotDisposed();
		const env = parseSignedNote(bytes);
		const checkpoint = parseCheckpointBody(env.body, this.tree.hasher.outputSize);
		let timestamp = 0;
		const matching = env.signatures.find(s =>
			s.keyId.length === this._keyId.length
			&& constantTimeEqual(s.keyId, this._keyId),
		);
		if (matching) {
			try {
				const parsed = parseCosigSignaturePayload(matching.signature, this._algoEntry.sigSize);
				timestamp = parsed.timestamp;
			} catch (err) {
				// Soft-fail timestamp to 0 on payload codec error; verifyCheckpoint surfaces hard fail.
				if (!(err instanceof MerkleCodecError)) throw err;
			}
		}
		return { checkpoint, signatures: env.signatures, timestamp };
	}

	/**
	 * Verify a signed-note envelope against this SignedLog's origin,
	 * pubkey, suite, and tree hasher. Returns `true` iff the envelope
	 * parses, carries a signature line whose keyId matches this log's
	 * pubkey-derived keyId, the `timestamped_signature` payload on
	 * that line decodes cleanly, and the signature verifies under
	 * `suite.verify` over the cosignature signed message reconstructed
	 * with the parsed timestamp.
	 *
	 * Returns `false` on every soft-fail mode: wrong origin, wrong
	 * root-hash length, no matching keyId line, malformed payload,
	 * signature failure. Throws only on this log's own disposed
	 * state; never on envelope content (envelope content is public,
	 * so timing distinctions on its content are not security-sensitive).
	 *
	 * The keyId comparison uses `constantTimeEqual` for hygiene around
	 * key-material-adjacent state; the origin and root-hash-length
	 * early returns are intentional non-constant-time exits since
	 * both fields are public per the spec.
	 */
	verifyCheckpoint(bytes: Uint8Array): boolean {
		this._assertNotDisposed();
		let env;
		try {
			env = parseSignedNote(bytes);
		} catch {
			return false;
		}
		let checkpoint;
		try {
			checkpoint = parseCheckpointBody(env.body, this.tree.hasher.outputSize);
		} catch {
			return false;
		}
		if (checkpoint.origin !== this.origin) return false;
		if (checkpoint.rootHash.length !== this.tree.hasher.outputSize) return false;

		const matching = env.signatures.find(s =>
			s.keyId.length === this._keyId.length
			&& constantTimeEqual(s.keyId, this._keyId),
		);
		if (!matching) return false;

		let payload;
		try {
			payload = parseCosigSignaturePayload(matching.signature, this._algoEntry.sigSize);
		} catch {
			return false;
		}

		let signedMessage;
		try {
			signedMessage = this._buildSignedMessage(env.body, payload.timestamp);
		} catch {
			// Reconstruction failed (e.g. timestamp out of range, or
			// the cosigned_message branch's start/end/state contract
			// violated by some attacker-influenced field). Treat as
			// verify-false.
			return false;
		}

		return this.suite.verify(this.pubkey, signedMessage, payload.signature, EMPTY_CTX);
	}

	// ── Lifecycle ──────────────────────────────────────────────────────

	/**
	 * Zero the stored signing-key copy. Idempotent. Subsequent calls
	 * to any public method throw.
	 */
	dispose(): void {
		if (this._disposed) return;
		wipe(this._signingKey);
		this._signingKey = new Uint8Array(0);
		this._disposed = true;
	}

	private _assertNotDisposed(): void {
		if (this._disposed)
			throw new Error('SignedLog: instance has been disposed');
	}

	// ── Internal: message construction dispatch ────────────────────────

	/**
	 * Dispatch the cosignature signed-message construction on the
	 * algorithm-byte registry entry's `messageConstruction`. The
	 * `body` argument is the canonical checkpoint body from
	 * `serializeCheckpointBody`, ending in 0x0A.
	 *
	 *   'cosig'             c2sp.org/tlog-cosignature §"Ed25519 signed
	 *                       message". The full envelope body is
	 *                       embedded verbatim after the
	 *                       cosignature/v1 + time prefix.
	 *
	 *   'cosigned-message'  c2sp.org/tlog-cosignature §"ML-DSA-44
	 *                       signed message". The body is decomposed
	 *                       into origin, tree size, and root hash;
	 *                       cosigner_name == origin (Phase 7 logs sign
	 *                       their own checkpoints); start == 0; end ==
	 *                       tree size; hash == root hash.
	 */
	private _buildSignedMessage(body: Uint8Array, timestamp: number): Uint8Array {
		if (this._algoEntry.messageConstruction === 'cosig')
			return buildCosigSignedMessage(body, timestamp);
		// 'cosigned-message' branch: decompose the body to feed the
		// TLS-Presentation struct. `parseCheckpointBody` is the
		// authoritative source of truth for the three-line body
		// layout.
		const cp = parseCheckpointBody(body, this.tree.hasher.outputSize);
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
