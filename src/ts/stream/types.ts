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
// src/ts/stream/types.ts
//
// CipherSuite interface — cipher-specific logic injected into SealStream
// and OpenStream. Implementations are plain objects (not classes).

export interface DerivedKeys {
	readonly bytes: Uint8Array;
	readonly kemCiphertext?: Uint8Array;  // KEM encrypt only; absent for symmetric
}

export interface CipherSuite {
	readonly formatEnum: number;          // bits 0-3 = cipher nibble; bits 4-5 = KEM selector (00=none, 01=ML-KEM-512, 10=ML-KEM-768, 11=ML-KEM-1024); bit 6 reserved; max 0x3f
	readonly formatName: string;          // human label, e.g. 'xchacha20', 'serpent'
	readonly hkdfInfo: string;
	readonly keySize: number;             // seal/encrypt key size (ek bytes for KEM)
	readonly decKeySize?: number;         // open/decrypt key size (dk bytes for KEM)
	                                      // absent → same as keySize (symmetric case)
	readonly kemCtSize: number;           // 0 for symmetric; KEM ciphertext bytes otherwise
	readonly tagSize: number;
	readonly padded: boolean;
	readonly wasmChunkSize: number;  // WASM CHUNK_SIZE constant; for padded ciphers, pool validates paddedFull <= this

	deriveKeys(key: Uint8Array, nonce: Uint8Array, kemCt?: Uint8Array): DerivedKeys;

	sealChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array;

	openChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array;

	wipeKeys(keys: DerivedKeys): void;

	readonly wasmModules: readonly string[];
	createPoolWorker(): Worker;
}

export interface SealStreamOpts {
	chunkSize?: number;
	framed?: boolean;
}
