#!/usr/bin/env bun
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒█
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
// Pre/post pack actions for the npm pack lifecycle.
// Wired into package.json prepack/postpack hooks.
//   --pre:  stash devDependencies and scripts from package.json,
//           generate root CLAUDE.md from docs/CLAUDE_consumer.md
//   --post: restore package.json, remove root CLAUDE.md

import {rm} from 'node:fs/promises'
import {spawnSync} from 'node:child_process'
import {runTarget} from './lib/build-graph.ts'

async function pre(): Promise<void> {
	const r = spawnSync('npm', ['pkg', 'delete', 'devDependencies', 'scripts'], {stdio: 'inherit'})
	if (r.status !== 0) process.exit(r.status ?? 1)
	await runTarget('claude-md')
}

async function post(): Promise<void> {
	// idempotent by design: --post must succeed even if --pre failed partway
	spawnSync('git', ['restore', 'package.json'], {stdio: 'inherit'})
	await rm('CLAUDE.md', {force: true})
}

const flag = process.argv[2]
if (flag === '--pre') await pre()
else if (flag === '--post') await post()
else {
	process.stderr.write('usage: bun scripts/pack.ts --pre | --post\n')
	process.exit(1)
}
