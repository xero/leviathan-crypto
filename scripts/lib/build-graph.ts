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
// scripts/lib/build-graph.ts
//
// Build DAG (Directed Acyclic Graph) declaration and runTarget walker.
//
// runTarget memoizes within a single top-level invocation: callers
// receive a fresh Set<BuildTarget> of visited targets per call so the
// `all` target's manual orchestration can re-use sub-targets without
// double-running, but repeated CLI invocations within the same process
// each rebuild from scratch.

import {cp, mkdir, rm} from 'node:fs/promises'
import {glob} from 'node:fs/promises'
import {spawn} from 'node:child_process'
import {EMBED_MODULES, POOL_WORKER_CIPHERS} from './modules'
import * as buildAsm from '../build-asm'
import * as embedWasm from '../embed-wasm'
import * as embedWorkers from '../embed-workers'
import * as copyDocs from '../copy-docs'

export type BuildTarget =
	| 'asm'
	| 'embed'
	| 'embed-workers'
	| 'ts'
	| 'wasm-copy'
	| 'claude-md'
	| 'docs'
	| 'all'

export interface TargetDef {
	deps: BuildTarget[]
	run: (visited: Set<BuildTarget>) => Promise<void>
}

function spawnInherit(cmd: string, args: string[]): Promise<void> {
	return new Promise((res, rej) => {
		const p = spawn(cmd, args, {stdio: 'inherit'})
		p.on('exit', (code) => code === 0 ? res() : rej(new Error(`${cmd} exited ${code}`)))
		p.on('error', rej)
	})
}

async function rmGlob(pattern: string): Promise<void> {
	for await (const entry of glob(pattern)) {
		await rm(entry, {force: true})
	}
}

export const TARGETS: Record<BuildTarget, TargetDef> = {
	asm: {
		deps: [],
		run: async () => {
			await rm('build', {recursive: true, force: true})
			await mkdir('build', {recursive: true})
			await buildAsm.run()
		},
	},
	embed: {
		deps: ['asm'],
		run: async () => {
			const toRemove = EMBED_MODULES.map(n => `src/ts/embedded/${n}.ts`).concat(['src/ts/cte-wasm.ts'])
			await Promise.all(toRemove.map(p => rm(p, {force: true})))
			await embedWasm.run()
		},
	},
	'embed-workers': {
		// deps: embed (pool-worker.ts → utils.ts → cte-wasm.ts is emitted by embed).
		deps: ['embed'],
		run: async () => {
			await Promise.all(POOL_WORKER_CIPHERS.map(c =>
				rm(`src/ts/embedded/${c}-pool-worker.ts`, {force: true})))
			await embedWorkers.run()
		},
	},
	ts: {
		deps: ['embed-workers'],
		run: async () => {
			await rm('dist', {recursive: true, force: true})
			await spawnInherit('bunx', ['tsc'])
		},
	},
	'wasm-copy': {
		deps: ['asm', 'ts'],
		run: async () => {
			await rmGlob('dist/*.wasm')
			await mkdir('dist', {recursive: true})
			for await (const wasm of glob('build/*.wasm')) {
				const base = wasm.split('/').pop()
				if (base) await cp(wasm, `dist/${base}`)
			}
		},
	},
	'claude-md': {
		deps: [],
		run: async () => {
			await rm('CLAUDE.md', {force: true})
			await cp('docs/CLAUDE_consumer.md', 'CLAUDE.md')
		},
	},
	docs: {
		deps: ['ts'],
		run: async () => {
			await rm('dist/docs', {recursive: true, force: true})
			await copyDocs.run()
		},
	},
	all: {
		deps: [],
		run: async (visited) => {
			// Serial chain: asm → embed → embed-workers → ts.
			await walk('asm', visited)
			await walk('embed', visited)
			await walk('embed-workers', visited)
			await walk('ts', visited)
			// Post-ts copies in parallel.
			await Promise.all([
				walk('wasm-copy', visited),
				walk('docs', visited),
			])
		},
	},
}

async function walk(name: BuildTarget, visited: Set<BuildTarget>): Promise<void> {
	if (visited.has(name)) return
	visited.add(name)
	const def = TARGETS[name]
	for (const d of def.deps) await walk(d, visited)
	await def.run(visited)
}

export async function runTarget(name: BuildTarget): Promise<void> {
	const visited = new Set<BuildTarget>()
	await walk(name, visited)
}
