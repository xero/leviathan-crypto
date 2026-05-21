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
// The "make yourself sad for no good reason" tests.
// Lints all AssemblyScript modules with `asc --pedantic`.
// Module table comes from scripts/lib/modules.ts.
// Exits nonzero on any WARNING / ERROR / PEDANTIC diagnostic.

import {spawnSync} from 'node:child_process'
import {mkdtempSync, rmSync} from 'node:fs'
import {tmpdir, cpus} from 'node:os'
import {join} from 'node:path'
import {ASM_MODULES, ASC_OPTS} from './lib/modules'
import {runFanout} from './lib/parallel'

const DIAG = /^(ERROR|WARNING|PEDANTIC)\b/m

export async function run(): Promise<void> {
	const tmp = mkdtempSync(join(tmpdir(), 'asc-lint-'))
	const fails: string[] = []
	const cpuCount = Math.max(1, cpus().length)
	try {
		await runFanout(ASM_MODULES.slice(), cpuCount, async ({name, entry, memory, simd}) => {
			const out = join(tmp, `${name}.wasm`)
			const args = [
				'asc', entry,
				'-o', out,
				'--config', 'none',
				'--pedantic',
				...ASC_OPTS.split(' '),
				...memory.split(' '),
				...(simd ? ['--enable', 'simd'] : []),
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
		})
	} finally {
		rmSync(tmp, {recursive: true, force: true})
	}
	if (fails.length) {
		console.error(`\n✗ wasm pedantic diagnostics in: ${fails.join(', ')}`)
		process.exit(1)
	}
	console.log('\n✓ all wasm modules pass strict pedantic checks')
}

if (import.meta.main) await run()
