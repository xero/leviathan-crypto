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
/** Full set of WASM exports for the chacha20 module. @internal */
export interface ChaChaExports {
	memory: WebAssembly.Memory
	/** Returns a numeric module identifier. */
	getModuleId():           number
	/** Byte offset of the 32-byte key buffer. */
	getKeyOffset():          number
	/** Byte offset of the 12-byte ChaCha20 nonce buffer. */
	getChachaNonceOffset():  number
	/** Byte offset of the ChaCha20 counter word. */
	getChachaCtrOffset():    number
	/** Byte offset of the 64-byte ChaCha20 block buffer. */
	getChachaBlockOffset():  number
	/** Byte offset of the ChaCha20 state matrix. */
	getChachaStateOffset():  number
	/** Byte offset of the chunk plaintext input buffer. */
	getChunkPtOffset():      number
	/** Byte offset of the chunk ciphertext output buffer. */
	getChunkCtOffset():      number
	/** Maximum chunk size in bytes. */
	getChunkSize():          number
	/** Byte offset of the 32-byte Poly1305 one-time key buffer. */
	getPolyKeyOffset():      number
	/** Byte offset of the 64-byte Poly1305 message input buffer. */
	getPolyMsgOffset():      number
	/** Byte offset of the 16-byte Poly1305 tag output buffer. */
	getPolyTagOffset():      number
	/** Byte offset of the Poly1305 accumulated message length. */
	getPolyBufLenOffset():   number
	/** Byte offset of the 16-byte HChaCha20 nonce input buffer. */
	getXChaChaNonceOffset(): number
	/** Byte offset of the 32-byte HChaCha20 subkey output buffer. */
	getXChaChaSubkeyOffset():number
	/** Load key + nonce from memory buffers into the ChaCha20 state matrix. */
	chachaLoadKey():         void
	/** Set the ChaCha20 block counter to `n`. */
	chachaSetCounter(n: number): void
	/** Reset the ChaCha20 block counter to 0. */
	chachaResetCounter():    void
	/** Encrypt `n` bytes from the plaintext buffer into the ciphertext buffer (scalar). @returns 0 on success, negative on error */
	chachaEncryptChunk(n: number): number
	/** Decrypt `n` bytes from the ciphertext buffer into the plaintext buffer (scalar). @returns 0 on success, negative on error */
	chachaDecryptChunk(n: number): number
	/** Encrypt `n` bytes using SIMD ChaCha20. @returns 0 on success, negative on error */
	chachaEncryptChunk_simd(n: number): number
	/** Decrypt `n` bytes using SIMD ChaCha20. @returns 0 on success, negative on error */
	chachaDecryptChunk_simd(n: number): number
	/** Generate the Poly1305 one-time key at counter=0 and copy it to POLY_KEY_OFFSET. */
	chachaGenPolyKey():      void
	/** Compute a 32-byte HChaCha20 subkey and write it to XChaChaSubkeyOffset. */
	hchacha20():             void
	/** Initialise Poly1305 state using the key at POLY_KEY_OFFSET. */
	polyInit():              void
	/** Absorb `n` bytes from the message buffer into the Poly1305 accumulator. */
	polyUpdate(n: number):   void
	/** Finalise the Poly1305 tag and write 16 bytes to POLY_TAG_OFFSET. */
	polyFinal():             void
	/** Zero all key material, keystream, and intermediate state in WASM memory. */
	wipeBuffers():           void
}
