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
// scripts/lib/modules.ts
//
// Canonical ASM modules table and ASC invocation options.
// Shared by build-asm.ts and lint-asm.ts preventing path drift

export interface AsmModule {
	name: string
	entry: string
	memory: string
	simd: boolean
	sourceMap: boolean
}

export const ASM_MODULES: readonly AsmModule[] = [
	{ name: 'cte',      entry: 'src/asm/cte/index.ts',      memory: '--initialMemory 1 --maximumMemory 1', simd: true,  sourceMap: false },
	{ name: 'serpent',  entry: 'src/asm/serpent/index.ts',  memory: '--initialMemory 3 --maximumMemory 3', simd: true,  sourceMap: true },
	{ name: 'chacha20', entry: 'src/asm/chacha20/index.ts', memory: '--initialMemory 3 --maximumMemory 3', simd: true,  sourceMap: true },
	{ name: 'aes',      entry: 'src/asm/aes/index.ts',      memory: '--initialMemory 4 --maximumMemory 4', simd: true,  sourceMap: true },
	{ name: 'sha2',     entry: 'src/asm/sha2/index.ts',     memory: '--initialMemory 3 --maximumMemory 3', simd: false, sourceMap: true },
	{ name: 'sha3',     entry: 'src/asm/sha3/index.ts',     memory: '--initialMemory 3 --maximumMemory 3', simd: false, sourceMap: true },
	{ name: 'kyber',    entry: 'src/asm/kyber/index.ts',    memory: '--initialMemory 3 --maximumMemory 3', simd: true,  sourceMap: true },
	{ name: 'mldsa',    entry: 'src/asm/mldsa/index.ts',    memory: '--initialMemory 4 --maximumMemory 4', simd: true,  sourceMap: true },
	{ name: 'slhdsa',   entry: 'src/asm/slhdsa/index.ts',   memory: '--initialMemory 2 --maximumMemory 2', simd: false, sourceMap: true },
	{ name: 'blake3',   entry: 'src/asm/blake3/index.ts',   memory: '--initialMemory 2 --maximumMemory 2', simd: true,  sourceMap: true },
	{ name: 'curve25519', entry: 'src/asm/curve25519/index.ts', memory: '--initialMemory 4 --maximumMemory 4', simd: false, sourceMap: true },
	{ name: 'p256',       entry: 'src/asm/p256/index.ts',       memory: '--initialMemory 3 --maximumMemory 3', simd: false, sourceMap: true },
] as const

export const ASC_OPTS = '--runtime stub --noAssert --optimizeLevel 3 --shrinkLevel 1'

// Modules whose .wasm is embedded as gz+b64 (everything except cte).
export const EMBED_MODULES = ASM_MODULES.filter(m => m.name !== 'cte').map(m => m.name)

// Cipher suites with a pool-worker.ts to bundle into embedded/*-pool-worker.ts
export const POOL_WORKER_CIPHERS = ['aes', 'chacha20', 'serpent'] as const
