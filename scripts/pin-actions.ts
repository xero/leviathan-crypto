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
//   pins all .github/workflows/*.yml action refs to commit SHAs
//   usage: bun run pin-actions

import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const dir = '.github/workflows'
let files: string[]

try {
	files = await readdir(dir)
} catch {
	console.error(`error: could not read ${dir}`)
	process.exit(1)
}

const workflows = files.filter(f => f.endsWith('.yml') || f.endsWith('.yaml'))

if (!workflows.length) {
	console.log(`no workflow files found in ${dir}`)
	process.exit(0)
}

let failed = false

for (const f of workflows) {
	const path = join(dir, f)
	process.stdout.write(`pinning ${path} ... `)

	const r = spawnSync('pin-github-action', [path], {
		stdio: ['ignore', 'pipe', 'pipe'],
		env: { ...process.env },
	})

	const out = r.stdout?.toString().trim() || ''
	const err = r.stderr?.toString().trim() || ''

	if (r.status !== 0) {
		if ((out + err).includes('No Actions detected')) {
			console.log('skipped (no action refs)')
		} else {
			console.error(`FAILED\n       ${err || out || 'unknown error'}`)
			failed = true
		}
	} else {
		console.log('ok')
	}
}

if (failed) process.exit(1)
