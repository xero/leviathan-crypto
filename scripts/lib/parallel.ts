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
// scripts/lib/parallel.ts
//
// Parallelism Helpers
//
// runParallel: spawn N child processes with line-prefixed output and
// per-task timing. Used by check.ts to fan lint/unit/e2e out.
//
// runFanout: in-process worker pool with bounded concurrency. Used by
// the asm build to run asc invocations in parallel up to cpu count.

export interface Task {
	name: string
	cmd: string[]
	env?: Record<string, string>
}

export interface Result {
	name: string
	code: number
	ms: number
}

export interface ParallelOpts {
	failFast?: boolean
}

async function pumpStream(name: string, src: ReadableStream<Uint8Array> | null, out: NodeJS.WritableStream): Promise<void> {
	if (!src) return
	const prefix = `\x1b[2m[${name}]\x1b[0m `
	const dec = new TextDecoder()
	const reader = src.getReader()
	let buf = ''
	for (;;) {
		const {done, value} = await reader.read()
		if (done) break
		if (!value) continue
		buf += dec.decode(value, {stream: true})
		let nl: number
		while ((nl = buf.indexOf('\n')) >= 0) {
			out.write(prefix + buf.slice(0, nl) + '\n')
			buf = buf.slice(nl + 1)
		}
	}
	buf += dec.decode()
	if (buf.length) out.write(prefix + buf + '\n')
}

export async function runParallel(tasks: Task[], opts: ParallelOpts = {}): Promise<Result[]> {
	const failFast = !!opts.failFast
	const ac = new AbortController()
	const results: Result[] = new Array(tasks.length)

	const promises = tasks.map(async (t, i) => {
		const env = {...process.env, ...(t.env ?? {})}
		const start = performance.now()
		const proc = Bun.spawn(t.cmd, {
			stdout: 'pipe',
			stderr: 'pipe',
			env,
			signal: ac.signal,
		})
		await Promise.all([
			pumpStream(t.name, proc.stdout as ReadableStream<Uint8Array>, process.stdout),
			pumpStream(t.name, proc.stderr as ReadableStream<Uint8Array>, process.stderr),
		])
		const code = await proc.exited
		const ms = performance.now() - start
		results[i] = {name: t.name, code, ms}
		if (failFast && code !== 0) ac.abort()
	})

	await Promise.all(promises)
	return results
}

export async function runFanout<T>(
	items: T[],
	concurrency: number,
	fn: (item: T) => Promise<void>,
): Promise<void> {
	const n = Math.max(1, concurrency)
	let cursor = 0
	const errors: unknown[] = []
	async function worker(): Promise<void> {
		for (;;) {
			const idx = cursor++
			if (idx >= items.length) return
			try {
				await fn(items[idx])
			} catch (e) {
				errors.push(e)
				return
			}
		}
	}
	const workers = Array.from({length: Math.min(n, items.length)}, () => worker())
	await Promise.all(workers)
	if (errors.length) throw errors[0]
}
