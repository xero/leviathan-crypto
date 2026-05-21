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
// src/ts/merkle/merkle-log.ts
//
// `MerkleLog`, the producer-side normie surface. Memory-backed via
// `MemoryStorage`. Real deployments drop down to `SignedLog<S>` with a
// custom `MerkleStorage`.
//
// Defaults: `hashing: 'sha256'`, `suite: MlDsa44Suite`. ML-DSA-44 is
// the PQ default per c2sp.org/tlog-checkpoint, the only PQ suite
// currently in the c2sp.org/tlog-cosignature §Format algorithm-byte
// registry. Sigsum interop: pass `suite: Ed25519Suite`.

import { isInitialized } from '../init.js';
import type { Module } from '../init.js';
import { MerkleLogError } from '../errors.js';
import { SignedLog } from './signed-log.js';
import { MemoryStorage } from './storage.js';
import { Sha256Tree, Sha256Hasher } from './sha256-tree.js';
import { Blake3Tree, Blake3Hasher } from './blake3-tree.js';
import { lookupAlgoEntryByFormatEnum } from './signed-note.js';
import { MlDsa44Suite } from '../sign/suites/mldsa.js';
import type { Hasher, MerkleTree } from './tree.js';
import type { SignatureSuite } from '../sign/types.js';

const SHA2_MODULE = 'sha2';

/**
 * Options for `MerkleLog.create`. The signing key and pubkey are
 * caller-supplied: `MerkleLog` does not persist keys. For ephemeral
 * use cases the companion factory `MerkleLog.generate` materialises a
 * fresh keypair via `suite.keygen()` and returns the keypair to the
 * caller so it can be persisted externally.
 */
export interface MerkleLogCreateOpts {
	/**
	 * Log identity, the first line of every checkpoint body. Validated
	 * by the inner `SignedLog` (non-empty, no whitespace, no plus
	 * characters) per c2sp.org/tlog-checkpoint §Note text.
	 */
	readonly origin: string;
	/** Signing key. Length must equal `suite.skSize`. */
	readonly signingKey: Uint8Array;
	/** Public key. Length must equal `suite.pkSize`. */
	readonly pubkey: Uint8Array;
	/**
	 * Hash function the tree uses. `'sha256'` (default) resolves to
	 * `Sha256Tree`, `'blake3'` resolves to `Blake3Tree`. SHA-256 is the
	 * C2SP-interop choice; the BLAKE3 specialisation is for callers who
	 * already invest in BLAKE3 elsewhere in their stack.
	 */
	readonly hashing?: 'sha256' | 'blake3';
	/**
	 * Cosignature signature suite. Defaults to `MlDsa44Suite` per the
	 * project's PQ-first principle and c2sp.org/tlog-checkpoint
	 * §Format's MUST/SHOULD wording on ML-DSA-44. Must be registered
	 * in the c2sp.org/tlog-cosignature §Format algorithm-byte registry;
	 * other suites raise `MerkleLogError('unsupported-suite')`.
	 */
	readonly suite?: SignatureSuite;
}

/**
 * Options for `MerkleLog.generate`. Identical to `MerkleLogCreateOpts`
 * minus the key fields; `generate` materialises a fresh keypair via
 * `suite.keygen()`.
 */
export interface MerkleLogGenerateOpts {
	readonly origin: string;
	readonly hashing?: 'sha256' | 'blake3';
	readonly suite?: SignatureSuite;
}

/**
 * Memory-backed signed transparency log. The normie producer surface.
 * Construct via `MerkleLog.create` (caller supplies keys) or
 * `MerkleLog.generate` (the class materialises a fresh keypair and
 * returns it). Methods after construction are synchronous; module-init
 * readiness and keygen are the only async steps.
 *
 * Methods delegate to an inner `SignedLog<S>` with a fresh
 * `MemoryStorage` backend. For file or database storage, construct
 * `SignedLog` directly with a custom `MerkleStorage` implementation,
 * see `docs/merkle.md` for the extension pattern.
 */
export class MerkleLog {
	readonly origin: string;
	readonly hasher: Hasher;
	readonly suite: SignatureSuite;

	private readonly _inner: SignedLog<SignatureSuite>;

	private constructor(inner: SignedLog<SignatureSuite>) {
		this._inner = inner;
		this.origin = inner.origin;
		this.hasher = inner.tree.hasher;
		this.suite = inner.suite;
	}

	/**
	 * Construct a `MerkleLog` with caller-supplied keys. Validates the
	 * suite against the c2sp.org/tlog-cosignature §Format algorithm-byte
	 * registry before instantiating the inner `SignedLog`; an
	 * unregistered suite raises `MerkleLogError('unsupported-suite')`
	 * with a message naming the suite and pointing at the spec.
	 *
	 * Async to keep the construction surface uniform with `generate`,
	 * which is async because `suite.keygen()` may route through async
	 * WASM acquisition under load. The hot-path methods (`append`,
	 * `head`, `size`, etc.) stay sync per the merkle layer's locked
	 * sync invariant.
	 */
	static async create(opts: MerkleLogCreateOpts): Promise<MerkleLog> {
		const hashing = opts.hashing ?? 'sha256';
		const suite = opts.suite ?? MlDsa44Suite;

		if (lookupAlgoEntryByFormatEnum(suite.formatEnum) === undefined)
			throw new MerkleLogError(
				'unsupported-suite',
				`MerkleLog: suite '${suite.formatName}' (formatEnum 0x${suite.formatEnum
					.toString(16)
					.padStart(2, '0')}) has no c2sp.org/tlog-cosignature §Format algorithm byte; `
				+ 'use Ed25519Suite or MlDsa44Suite, or open an issue for a newly C2SP-registered suite',
			);

		const tree = buildTree(hashing);
		assertModulesInitialized([
			...suite.wasmModules,
			...tree.hasher.wasmModules,
			SHA2_MODULE,
		]);

		const inner = new SignedLog<SignatureSuite>({
			tree,
			suite,
			origin: opts.origin,
			signingKey: opts.signingKey,
			pubkey: opts.pubkey,
		});
		return new MerkleLog(inner);
	}

	/**
	 * Construct a `MerkleLog` with a freshly generated keypair. Returns
	 * the log plus the keypair; the caller is responsible for
	 * persisting the keys externally if the log outlives the process.
	 *
	 * The returned `signingKey` is a copy, the log retains its own
	 * internal copy that `dispose()` wipes; modifying the returned
	 * buffer after construction does not affect the log.
	 */
	static async generate(opts: MerkleLogGenerateOpts): Promise<{
		log: MerkleLog;
		signingKey: Uint8Array;
		pubkey: Uint8Array;
	}> {
		const hashing = opts.hashing ?? 'sha256';
		const suite = opts.suite ?? MlDsa44Suite;

		if (lookupAlgoEntryByFormatEnum(suite.formatEnum) === undefined)
			throw new MerkleLogError(
				'unsupported-suite',
				`MerkleLog.generate: suite '${suite.formatName}' (formatEnum 0x${suite.formatEnum
					.toString(16)
					.padStart(2, '0')}) has no c2sp.org/tlog-cosignature §Format algorithm byte; `
				+ 'use Ed25519Suite or MlDsa44Suite, or open an issue for a newly C2SP-registered suite',
			);

		// suite.keygen() requires the suite's modules already initialised;
		// the same modules are checked again inside create() before
		// instantiating SignedLog. Checking here keeps the throw surface
		// consistent regardless of which factory the caller used.
		const tmpHasher = resolveHasher(hashing);
		assertModulesInitialized([
			...suite.wasmModules,
			...tmpHasher.wasmModules,
			SHA2_MODULE,
		]);

		const { pk, sk } = suite.keygen();
		const log = await MerkleLog.create({
			origin: opts.origin,
			signingKey: sk,
			pubkey: pk,
			hashing,
			suite,
		});
		return { log, signingKey: sk, pubkey: pk };
	}

	/**
	 * Append a leaf and return its index, hash, and inclusion proof
	 * against the post-append tree size. Delegates to the inner
	 * `SignedLog.append`.
	 */
	append(leafBytes: Uint8Array): {
		leafIndex: number;
		leafHash: Uint8Array;
		inclusionProof: Uint8Array[];
	} {
		return this._inner.append(leafBytes);
	}

	/**
	 * Emit the current checkpoint as a signed-note envelope. Re-signed
	 * on every call; the body reflects the live tree size and root
	 * hash. Timestamp defaults to `Math.floor(Date.now() / 1000)`.
	 */
	head(opts?: { timestamp?: number }): Uint8Array {
		return this._inner.signCheckpoint(opts);
	}

	/** Current number of leaves in the tree. */
	size(): number {
		return this._inner.size();
	}

	/** Current Merkle root hash. */
	rootHash(): Uint8Array {
		return this._inner.rootHash();
	}

	/**
	 * Inclusion proof for `leafIndex` in a tree of the given size, or
	 * the current tree size if omitted. Per RFC 9162 §2.1.3.
	 */
	inclusionProof(leafIndex: number, treeSize?: number): Uint8Array[] {
		return this._inner.getInclusionProof(leafIndex, treeSize);
	}

	/**
	 * Consistency proof between two tree sizes per RFC 9162 §2.1.4.
	 * `oldSize` must be `<= newSize <= size()`.
	 */
	consistencyProof(oldSize: number, newSize: number): Uint8Array[] {
		return this._inner.getConsistencyProof(oldSize, newSize);
	}

	/**
	 * Zero the stored signing-key copy. Idempotent. Subsequent calls
	 * to any public method throw.
	 */
	dispose(): void {
		this._inner.dispose();
	}
}

function buildTree(hashing: string): MerkleTree {
	if (hashing === 'sha256') return new Sha256Tree(new MemoryStorage());
	if (hashing === 'blake3') return new Blake3Tree(new MemoryStorage());
	throw new MerkleLogError(
		'unsupported-hashing',
		`MerkleLog: hashing must be 'sha256' or 'blake3', got '${hashing}'`,
	);
}

function resolveHasher(hashing: string): Hasher {
	if (hashing === 'sha256') return Sha256Hasher;
	if (hashing === 'blake3') return Blake3Hasher;
	throw new MerkleLogError(
		'unsupported-hashing',
		`MerkleLog: hashing must be 'sha256' or 'blake3', got '${hashing}'`,
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
				`MerkleLog: WASM module '${mod}' is not initialized; `
				+ 'call init() with the appropriate sources before constructing MerkleLog',
			);
	}
}
