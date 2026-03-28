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
/** WASM exports for the chacha module */
export interface ChaChaExports {
	memory: WebAssembly.Memory
	getModuleId():           number
	getKeyOffset():          number
	getChachaNonceOffset():  number
	getChachaCtrOffset():    number
	getChachaBlockOffset():  number
	getChachaStateOffset():  number
	getChunkPtOffset():      number
	getChunkCtOffset():      number
	getChunkSize():          number
	getPolyKeyOffset():      number
	getPolyMsgOffset():      number
	getPolyTagOffset():      number
	getPolyBufLenOffset():   number
	getXChaChaNonceOffset(): number
	getXChaChaSubkeyOffset():number
	chachaLoadKey():         void
	chachaSetCounter(n: number): void
	chachaResetCounter():    void
	chachaEncryptChunk(n: number): number
	chachaDecryptChunk(n: number): number
	chachaEncryptChunk_simd(n: number): number
	chachaDecryptChunk_simd(n: number): number
	chachaGenPolyKey():      void
	hchacha20():             void
	polyInit():              void
	polyUpdate(n: number):   void
	polyFinal():             void
	wipeBuffers():           void
}
