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
// Test dispatcher.
//   bun scripts/test.ts                     # build all + unit + e2e
//   bun scripts/test.ts unit [...files]     # all unit tests (or filter)
//   bun scripts/test.ts unit:group <name> [...files]
//   bun scripts/test.ts e2e  [...args]
//   bun scripts/test.ts e2e:install         # globally install playwright + browsers
//
// Forwards extra args to the underlying runner.
// LVTHN_SKIP_BUILD=1 skips this script's build prerequisites.

import {runTarget} from './lib/build-graph'
import {UNIT_GROUPS} from './lib/test-groups'

const skipBuild = !!process.env.LVTHN_SKIP_BUILD
const [sub, ...rest] = process.argv.slice(2)

async function runVitest(args: string[]): Promise<void> {
	const cmd = ['bun', 'vitest', 'run', '--reporter=verbose', '--no-coverage', ...args]
	const proc = Bun.spawn(cmd, {stdout: 'inherit', stderr: 'inherit'})
	const code = await proc.exited
	if (code !== 0) process.exit(code)
}

async function runPlaywright(args: string[]): Promise<void> {
	const cmd = ['bunx', 'playwright', 'test', ...args]
	const proc = Bun.spawn(cmd, {stdout: 'inherit', stderr: 'inherit'})
	const code = await proc.exited
	if (code !== 0) process.exit(code)
}

async function runStep(label: string, cmd: string[]): Promise<void> {
	console.log(`==> ${label}`)
	const proc = Bun.spawn(cmd, {stdout: 'inherit', stderr: 'inherit'})
	const code = await proc.exited
	if (code !== 0) process.exit(code)
}

function usage(): never {
	console.error('usage: bun scripts/test.ts [unit|unit:group <name>|e2e|e2e:install|all] [...files]')
	process.exit(1)
}

switch (sub) {
	case undefined:
	case 'all': {
		if (!skipBuild) await runTarget('all')
		await runVitest([])
		await runPlaywright([])
		break
	}
	case 'unit': {
		if (!skipBuild) {
			// Build the union of group deps. `core` requires ts so we always build ts.
			await runTarget('asm')
			await runTarget('embed')
			await runTarget('embed-workers')
			await runTarget('ts')
		}
		await runVitest(rest)
		break
	}
	case 'unit:group': {
		const groupName = rest[0]
		const files = rest.slice(1)
		const group = UNIT_GROUPS.find(g => g.name === groupName)
		if (!group) { console.error(`unknown group: ${groupName}`); process.exit(1) }
		if (!skipBuild) {
			for (const t of group.buildTargets) await runTarget(t)
		}
		const args = files.length ? files : group.files.slice()
		await runVitest(args)
		break
	}
	case 'e2e': {
		if (!skipBuild) await runTarget('all')
		await runPlaywright(rest)
		break
	}
	case 'e2e:install': {
		// Mirrors .github/ci.Dockerfile lines 22-25 so contributors can match
		// the CI image's playwright toolchain on a fresh local checkout.
		await runStep('bun i -g playwright',                      ['bun', 'i', '-g', 'playwright'])
		await runStep('playwright install-deps',                  ['playwright', 'install-deps'])
		await runStep('playwright install',                       ['playwright', 'install'])
		await runStep('playwright install chrome firefox webkit', ['playwright', 'install', 'chrome', 'firefox', 'webkit'])
		break
	}
	default:
		usage()
}
