#!/usr/bin/env node
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
// Copies consumer-relevant API docs into dist/docs/ for npm packaging.
// Excludes internal/project docs (branding, audit, test-suite, etc).
// Strips SVG <img> tags from architecture.md — they reference absolute
// GitHub URLs and are useless (and large) for agents working offline.
//
// Runs after build:ts as part of the build chain.

import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const SRC  = resolve(ROOT, 'docs');
const OUT  = resolve(ROOT, 'dist/docs');

// consumer API docs only — no branding, internals, or project docs
const INCLUDE = [
	'architecture.md',
	'argon2id.md',
	'chacha20.md',
	'exports.md',
	'fortuna.md',
	'init.md',
	'loader.md',
	'serpent.md',
	'sha2.md',
	'sha3.md',
	'stream.md',
	'types.md',
	'utils.md',
	'wasm.md',
];

// strip SVG img tags — all four reference absolute GitHub URLs,
// useless for agents in an installed package context
const SVG_IMG = /<img[^>]+\.svg[^>]*>/g;

if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });

for (const file of INCLUDE) {
	const src  = resolve(SRC, file);
	const dest = resolve(OUT, file);

	if (!existsSync(src)) {
		process.stderr.write(`missing: docs/${file}\n`);
		process.exit(1);
	}

	let content = readFileSync(src, 'utf8');

	// strip SVG image lines from architecture.md
	if (file === 'architecture.md') {
		content = content
			.split('\n')
			.filter(line => !SVG_IMG.test(line))
			.join('\n');
	}

	writeFileSync(dest, content, 'utf8');
	process.stdout.write(`copied: docs/${file} → dist/docs/${file}\n`);
}

process.stdout.write(`done: ${INCLUDE.length} docs → dist/docs/\n`);
