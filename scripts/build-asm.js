#!/usr/bin/env node
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
// Build all four AssemblyScript modules.
// Produces build/{serpent,chacha,sha2,sha3}.wasm + .js
//
// Using `-o` with `--bindings esm` produces both the .wasm binary
// and a clean ESM JS wrapper (ASCII, no embedded binary).
// The JS wrapper loads the sibling .wasm file.

import { execSync } from 'child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'

const BUILD_DIR = 'build'
if (!existsSync(BUILD_DIR)) mkdirSync(BUILD_DIR)

const ASC_OPTS = '--runtime stub --noAssert --optimizeLevel 3 --shrinkLevel 1'

const modules = [
  { name: 'serpent', entry: 'src/asm/serpent/index.ts', memory: '--initialMemory 3 --maximumMemory 3', extra: '--enable simd' },
  { name: 'chacha20', entry: 'src/asm/chacha20/index.ts', memory: '--initialMemory 3 --maximumMemory 3', extra: '--enable simd' },
  { name: 'sha2',    entry: 'src/asm/sha2/index.ts', memory: '--initialMemory 3 --maximumMemory 3' },
  { name: 'sha3',    entry: 'src/asm/sha3/index.ts', memory: '--initialMemory 3 --maximumMemory 3' },
  { name: 'ct', entry: 'src/asm/ct/index.ts', memory: '--importMemory --initialMemory 1 --maximumMemory 1', extra: '--enable simd', noSourceMap: true },
  { name: 'kyber', entry: 'src/asm/kyber/index.ts', memory: '--initialMemory 3 --maximumMemory 3', extra: '--enable simd' },
]

for (const { name, entry, memory, extra = '', noSourceMap = false } of modules) {
  // --config none: prevent asc from picking up asconfig.json entries
  // when invoked per-module; each module is built with explicit options only.
  const srcMap = noSourceMap ? '' : '--sourceMap'
  const cmd = `npx asc ${entry} -o build/${name}.wasm --bindings esm ${srcMap} --config none ${ASC_OPTS} ${memory} ${extra}`
  console.log(`  asc ${entry} → build/${name}.wasm + build/${name}.js`)
  execSync(cmd, { stdio: 'inherit' })
  // ASC ESM bindings can emit duplicate names in the export destructuring
  // Deduplicate to avoid SyntaxError in strict mode (e.g. browsers)
  const jsPath = `build/${name}.js`
  const src = readFileSync(jsPath, 'utf8')
  const fixed = src.replace(
    /export const \{([^}]+)\}/s,
    (_m, inner) => {
      const seen = new Set()
      const lines = inner.split('\n').filter(l => {
        const id = l.trim().replace(/,$/, '')
        if (!id) return true
        if (seen.has(id)) return false
        seen.add(id)
        return true
      })
      return `export const {${lines.join('\n')}}`
    }
  )
  if (fixed !== src) writeFileSync(jsPath, fixed)
}

console.log('All WASM modules built successfully.')
