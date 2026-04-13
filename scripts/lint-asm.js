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
// "Make yourself sad for no good reason" tests
// Lints all AssemblyScript modules with `asc --pedantic`.
// Mirrors build-asm.js module table
// Exits nonzero on any WARNING / ERROR / PEDANTIC diagnostic.

import { spawnSync } from 'child_process'
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

const ASC_OPTS = '--runtime stub --noAssert --optimizeLevel 3 --shrinkLevel 1'

const modules = [
	{ name: 'serpent',  entry: 'src/asm/serpent/index.ts',  memory: '--initialMemory 3 --maximumMemory 3', extra: '--enable simd' },
	{ name: 'chacha20', entry: 'src/asm/chacha20/index.ts', memory: '--initialMemory 3 --maximumMemory 3', extra: '--enable simd' },
	{ name: 'sha2',     entry: 'src/asm/sha2/index.ts',     memory: '--initialMemory 3 --maximumMemory 3' },
	{ name: 'sha3',     entry: 'src/asm/sha3/index.ts',     memory: '--initialMemory 3 --maximumMemory 3' },
	{ name: 'ct',       entry: 'src/asm/ct/index.ts',       memory: '--initialMemory 1 --maximumMemory 1', extra: '--enable simd' },
	{ name: 'kyber',    entry: 'src/asm/kyber/index.ts',    memory: '--initialMemory 3 --maximumMemory 3', extra: '--enable simd' },
]

// asc diagnostic prefixes at start of a stderr line
const DIAG = /^(ERROR|WARNING|PEDANTIC)\b/m

const tmp = mkdtempSync(join(tmpdir(), 'asc-lint-'))
const fails = []

for (const { name, entry, memory, extra = '' } of modules) {
	const out = join(tmp, `${name}.wasm`)
	const args = [
		'asc', entry,
		'-o', out,
		'--config', 'none',
		'--pedantic',
		...ASC_OPTS.split(' '),
		...memory.split(' '),
		...(extra ? extra.split(' ') : []),
	]
	console.log(`→ lint ${name}`)
	const res = spawnSync('npx', args, {
		stdio: ['inherit', 'inherit', 'pipe'],
		encoding: 'utf8',
	})
	if (res.stderr) process.stderr.write(res.stderr)
	if (res.status !== 0 || DIAG.test(res.stderr || '')) {
		fails.push(name)
	}
}

rmSync(tmp, { recursive: true, force: true })

if (fails.length) {
	console.error(`\n✗ pedantic diagnostics in: ${fails.join(', ')}`)
	process.exit(1)
}
console.log('\n✓ all modules pass strict pedantic checks')
