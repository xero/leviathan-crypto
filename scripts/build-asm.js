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
/**
 * Build all four AssemblyScript modules.
 * Produces build/{serpent,chacha,sha2,sha3}.wasm + .js
 *
 * Using `-o` with `--bindings esm` produces both the .wasm binary
 * and a clean ESM JS wrapper (ASCII, no embedded binary).
 * The JS wrapper loads the sibling .wasm file.
 */
import { execSync } from 'child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'

const BUILD_DIR = 'build'
if (!existsSync(BUILD_DIR)) mkdirSync(BUILD_DIR)

const ASC_OPTS = '--runtime stub --initialMemory 3 --maximumMemory 3 --noAssert --optimizeLevel 3 --shrinkLevel 1'

const modules = [
  { name: 'serpent', entry: 'src/asm/serpent/index.ts' },
  { name: 'chacha',  entry: 'src/asm/chacha/index.ts' },
  { name: 'sha2',    entry: 'src/asm/sha2/index.ts' },
  { name: 'sha3',    entry: 'src/asm/sha3/index.ts' },
]

for (const { name, entry } of modules) {
  console.log(`  asc ${entry} → build/${name}.wasm + build/${name}.js`)
  execSync(`npx asc ${entry} -o build/${name}.wasm --bindings esm --sourceMap ${ASC_OPTS}`, { stdio: 'inherit' })
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
