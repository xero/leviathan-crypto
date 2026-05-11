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
// Lint dispatcher.
//   bun scripts/lint.ts            # all (ts + asm, parallel)
//   bun scripts/lint.ts ts         # eslint + tsc x3 in parallel
//   bun scripts/lint.ts asm        # asc --pedantic fanout
//   bun scripts/lint.ts --fix      # eslint --fix then asm (serial, no parallel)

import * as lintAsm from './lint-asm'
import {runParallel, type Task} from './lib/parallel'

const args = process.argv.slice(2)
const fix = args.includes('--fix')
const subRaw = args.find(a => !a.startsWith('-'))
const sub = subRaw ?? 'all'

async function lintTs(applyFix: boolean): Promise<void> {
	const tasks: Task[] = [
		{name: 'eslint',   cmd: ['bun', 'eslint', '.', ...(applyFix ? ['--fix'] : [])]},
		{name: 'tsc:main', cmd: ['bun', 'tsc', '--noEmit', '-p', 'tsconfig.json']},
		{name: 'tsc:test', cmd: ['bun', 'tsc', '--noEmit', '-p', 'tsconfig.test.json']},
		{name: 'tsc:e2e',  cmd: ['bun', 'tsc', '--noEmit', '-p', 'tsconfig.e2e.json']},
	]
	const results = await runParallel(tasks, {failFast: false})
	const failed = results.filter(r => r.code !== 0)
	if (failed.length) process.exit(Math.max(...failed.map(r => r.code)))
}

async function lintAsmRun(): Promise<void> {
	await lintAsm.run()
}

switch (sub) {
	case 'ts':
		await lintTs(fix)
		break
	case 'asm':
		if (fix) { console.error('--fix not supported for asm lint'); process.exit(1) }
		await lintAsmRun()
		break
	case 'all':
	default:
		if (fix) {
			await lintTs(true)
			await lintAsmRun()
		} else {
			const results = await runParallel([
				{name: 'ts',  cmd: ['bun', 'scripts/lint.ts', 'ts']},
				{name: 'asm', cmd: ['bun', 'scripts/lint.ts', 'asm']},
			], {failFast: false})
			const failed = results.filter(r => r.code !== 0)
			if (failed.length) process.exit(Math.max(...failed.map(r => r.code)))
		}
}
