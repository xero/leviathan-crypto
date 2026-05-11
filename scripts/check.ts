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
// Top-level check: full build, then lint + unit + e2e in parallel as
// child processes with LVTHN_SKIP_BUILD=1 so each child skips its own
// build prerequisites. Aggregates per-task timing and exit codes.

import {runTarget} from './lib/build-graph'
import {runParallel} from './lib/parallel'

const t0 = performance.now()

console.log('==> full build')
await runTarget('all')

console.log('\n==> parallel checks')
const results = await runParallel([
	{name: 'lint', cmd: ['bun', 'scripts/lint.ts'],         env: {LVTHN_SKIP_BUILD: '1'}},
	{name: 'unit', cmd: ['bun', 'scripts/test.ts', 'unit'], env: {LVTHN_SKIP_BUILD: '1'}},
	{name: 'e2e',  cmd: ['bun', 'scripts/test.ts', 'e2e'],  env: {LVTHN_SKIP_BUILD: '1'}},
], {failFast: false})

const totalS = ((performance.now() - t0) / 1000).toFixed(1)
console.log('')
for (const r of results) {
	const mark = r.code === 0 ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'
	console.log(`  ${mark} ${r.name.padEnd(6)} ${(r.ms / 1000).toFixed(1)}s`)
}
console.log(`\n  total ${totalS}s`)

const failed = results.filter(r => r.code !== 0)
process.exit(failed.length ? Math.max(...failed.map(r => r.code)) : 0)
