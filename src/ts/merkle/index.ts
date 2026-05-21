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
// src/ts/merkle/index.ts
//
// Public surface for the merkle log primitives. Interfaces, free
// functions, and the SHA-256 specialisation. Hash-agnostic by design;
// the BLAKE3 specialisation lives alongside this module and re-exports
// the same interfaces.

export { splitPoint } from './tree.js';
export type { Hasher, MerkleTree } from './tree.js';

export { MemoryStorage } from './storage.js';
export type { MerkleStorage } from './storage.js';

export {
	verifyInclusionProof,
	verifyConsistencyProof,
	buildInclusionProof,
	buildConsistencyProof,
} from './proof.js';
export type {
	VerifyInclusionInput,
	VerifyConsistencyInput,
	BuildInclusionInput,
	BuildConsistencyInput,
	GetNode,
} from './proof.js';

export { Sha256Hasher, Sha256Tree } from './sha256-tree.js';
export { Blake3Hasher, Blake3Tree } from './blake3-tree.js';

export { serializeCheckpointBody, parseCheckpointBody } from './checkpoint.js';
export type { Checkpoint } from './checkpoint.js';

export {
	emitSignedNote,
	parseSignedNote,
	deriveKeyId,
	suiteFormatEnumToAlgoByte,
	lookupAlgoEntryByFormatEnum,
	lookupAlgoEntryByByte,
	buildCosigSignedMessage,
	buildCosignedMessage,
	emitCosigSignaturePayload,
	parseCosigSignaturePayload,
	ALGO_BYTE_ED25519_NOTE,
	ALGO_BYTE_ED25519_COSIG,
	ALGO_BYTE_MLDSA44_COSIG,
} from './signed-note.js';
export type {
	SignatureLine, SignedNote,
	AlgoEntry, MessageConstruction, SignaturePayload,
	CosignedMessageInput,
} from './signed-note.js';

export type { SignedTreeHead } from './sth.js';

export { SignedLog } from './signed-log.js';
export type { SignedLogOpts } from './signed-log.js';

export { MerkleVerifier } from './merkle-verifier.js';
export type { MerkleVerifierOpts } from './merkle-verifier.js';

export { MerkleLog } from './merkle-log.js';
export type { MerkleLogCreateOpts, MerkleLogGenerateOpts } from './merkle-log.js';
