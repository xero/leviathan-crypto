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
/** WASM exports for the sha2 module, full FIPS 180-4 surface plus
 *  HMAC variants. Importable from cross-module wrappers (e.g. mldsa's
 *  HashML-DSA pre-hash dispatcher) that need to drive sha2 directly
 *  without going through the public class API. */
export interface Sha2Exports {
	memory:                WebAssembly.Memory
	getModuleId:           () => number
	getSha256InputOffset:  () => number
	getSha256OutOffset:    () => number
	getSha256HOffset:      () => number
	getSha512InputOffset:  () => number
	getSha512OutOffset:    () => number
	getSha512HOffset:      () => number
	getHmac256IpadOffset:  () => number
	getHmac256OpadOffset:  () => number
	getHmac256InnerOffset: () => number
	getHmac512IpadOffset:  () => number
	getHmac512OpadOffset:  () => number
	getHmac512InnerOffset: () => number
	sha256Init:      () => void
	sha256Update:    (len: number) => void
	sha256Final:     () => void
	sha224Init:      () => void
	sha224Final:     () => void
	sha512Init:      () => void
	sha384Init:      () => void
	sha512_224Init:  () => void
	sha512_256Init:  () => void
	sha512Update:    (len: number) => void
	sha512Final:     () => void
	sha384Final:     () => void
	sha512_224Final: () => void
	sha512_256Final: () => void
	hmac256Init:   (keyLen: number) => void
	hmac256Update: (len: number) => void
	hmac256Final:  () => void
	hmac512Init:   (keyLen: number) => void
	hmac512Update: (len: number) => void
	hmac512Final:  () => void
	hmac384Init:   (keyLen: number) => void
	hmac384Update: (len: number) => void
	hmac384Final:  () => void
	wipeBuffers:   () => void
}
