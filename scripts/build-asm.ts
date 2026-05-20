#!/usr/bin/env bun
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
// Build all AssemblyScript modules listed in scripts/lib/modules.ts.
// Produces a .wasm + .js per entry. Fans out across cpu count.
//
// asc -o + --bindings esm: .wasm binary + clean ESM wrapper that loads
// the sibling .wasm.

import {execSync} from 'node:child_process'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs'
import {cpus} from 'node:os'
import {ASM_MODULES, ASC_OPTS} from './lib/modules'
import {runFanout} from './lib/parallel'

const BUILD_DIR = 'build'

export async function run(): Promise<void> {
	if (!existsSync(BUILD_DIR)) mkdirSync(BUILD_DIR)
	const cpuCount = Math.max(1, cpus().length)
	await runFanout(ASM_MODULES.slice(), cpuCount, async ({name, entry, memory, simd, sourceMap}) => {
		// --config none: each module built with explicit options only;
		// asconfig.json not consulted.
		const srcMap = sourceMap ? '--sourceMap' : ''
		const extra  = simd ? '--enable simd' : ''
		const cmd = `npx asc ${entry} -o build/${name}.wasm --bindings esm ${srcMap} --config none ${ASC_OPTS} ${memory} ${extra}`
		console.log(`  asc ${entry} → build/${name}.wasm + build/${name}.js`)
		execSync(cmd, {stdio: 'inherit'})
		// asc esm bindings sometimes emit duplicate destructured names; dedupe to avoid strict-mode SyntaxError.
		const jsPath = `build/${name}.js`
		const src = readFileSync(jsPath, 'utf8')
		const fixed = src.replace(
			/export const \{([^}]+)\}/s,
			(_m, inner) => {
				const seen = new Set<string>()
				const lines = inner.split('\n').filter((l: string) => {
					const id = l.trim().replace(/,$/, '')
					if (!id) return true
					if (seen.has(id)) return false
					seen.add(id)
					return true
				})
				return `export const {${lines.join('\n')}}`
			},
		)
		if (fixed !== src) writeFileSync(jsPath, fixed)
	})
	console.log('All WASM modules built successfully.')
}

if (import.meta.main) await run()
