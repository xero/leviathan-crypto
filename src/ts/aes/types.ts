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
// src/ts/aes/types.ts

/** Full set of WASM exports for the aes module used by the cipher suite + ops + pool worker. @internal */
export interface AesExports {
	memory: WebAssembly.Memory
	/** Returns a numeric module identifier. */
	getModuleId():                  number
	/** Byte offset of the 32-byte key buffer. */
	getKeyOffset():                 number
	/** Byte offset of the 16-byte block plaintext buffer. */
	getBlockPtOffset():             number
	/** Byte offset of the 16-byte block ciphertext buffer. */
	getBlockCtOffset():             number
	/** Byte offset of the 8x bitsliced block plaintext buffer. */
	getBlockPt8xOffset():           number
	/** Byte offset of the 8x bitsliced block ciphertext buffer. */
	getBlockCt8xOffset():           number
	/** Byte offset of the AES forward round-key schedule. */
	getRoundKeysOffset():           number
	/** Byte offset of the bitsliced state working buffer. */
	getBitslicedStateOffset():      number
	/** Byte offset of the Canright S-box scratch buffer. */
	getCanrightScratchOffset():     number
	/** Byte offset of the key-schedule scratch buffer. */
	getKeyScheduleScratchOffset():  number
	/** Byte offset of the EqInvCipher inverse round-key schedule. */
	getInvRoundKeysOffset():        number
	/** Byte offset of the chunk plaintext buffer. */
	getChunkPtOffset():             number
	/** Byte offset of the chunk ciphertext buffer. */
	getChunkCtOffset():             number
	/** Maximum chunk size in bytes (AES_CHUNK_SIZE constant from buffers.ts). */
	getChunkSize():                 number
	/** Byte offset of the Nr (round count) state word. */
	getNrOffset():                  number
	/** Byte offset of the 12-byte AES-GCM-SIV nonce buffer. */
	getNonceOffset():               number
	/** Byte offset of the AES-CTR counter buffer. */
	getCounterOffset():             number
	/** Byte offset of the AES-CBC IV buffer. */
	getCbcIvOffset():               number
	/** Byte offset of the GHASH H subkey. */
	getHOffset():                   number
	/** Byte offset of the AES-GCM J0 buffer. */
	getJ0Offset():                  number
	/** Byte offset of the GHASH accumulator. */
	getGhashAccOffset():            number
	/** Byte offset of the AEAD tag buffer (16 bytes). */
	getTagOffset():                 number
	/** Byte offset of the GF(2^128) precomputed table. */
	getGf128TableOffset():          number
	/** Byte offset of the AAD buffer. */
	getAadOffset():                 number
	/** Maximum AAD buffer size in bytes. */
	getAadBufferSize():             number
	/** Byte offset of the POLYVAL auth-key buffer. */
	getPolyvalAuthKeyOffset():      number
	/** Byte offset of the POLYVAL enc-key buffer. */
	getPolyvalEncKeyOffset():       number
	/** Byte offset of the SIV initial counter buffer (used by sivOpen to receive the provided tag). */
	getSivIcOffset():               number
	/** Returns the WASM linear-memory page count. */
	getMemoryPages():               number

	// ── AES block cipher (encrypt + decrypt) ────────────────────────────────
	/** Expand the key at KEY_OFFSET into the round-key schedule. @returns 0 on success */
	loadKey(n: number):             number
	/** Encrypt one 128-bit block from BLOCK_PT to BLOCK_CT. */
	encryptBlock():                 void
	/** Encrypt eight bitsliced 128-bit blocks. */
	encryptBlock_8x():              void
	/** Decrypt one 128-bit block. */
	decryptBlock():                 void
	/** Decrypt eight bitsliced 128-bit blocks. */
	decryptBlock_8x():              void

	// ── AES-GCM-SIV (RFC 8452) ───────────────────────────────────────────────
	/** Derive the per-message POLYVAL auth + AES enc keys from KGK + nonce@nonceOff (RFC 8452 §4). */
	sivDeriveKeys(nonceOff: number): void
	/** Run RFC 8452 §4 seal: POLYVAL → tag → AES-CTR over CHUNK_PT, writing CT in place and the tag to TAG_OFFSET. */
	sivSeal(aadLen: number, ptLen: number): void
	/** Run RFC 8452 §4 open: AES-CTR over CHUNK_CT into CHUNK_PT, then POLYVAL to recompute the expected tag at TAG_OFFSET. */
	sivOpen(aadLen: number, ctLen: number): void
	/** On AES-GCM-SIV authentication failure: zero CHUNK_PT before any TS code can read it. */
	sivWipeOnFail():                void

	/** Zero all key material, intermediate state, and output buffers in WASM memory. */
	wipeBuffers():                  void
}
