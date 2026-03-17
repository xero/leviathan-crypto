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
// Generates a markdown changelog from git commits between the previous
// semver tag and a given tag. Parses conventional commits and groups
// them by type. Detects breaking changes via ! suffix or BREAKING keyword.
//
// Usage:
//   npx tsx scripts/gen-changelog.ts <tag>
//   npx tsx scripts/gen-changelog.ts v1.2.3
//
// Output:
//   stdout  — markdown changelog
//   exit 1  — if breaking changes detected (for CI warning banner logic)
//   exit 0  — clean release

import { execSync } from 'node:child_process';

// ── types ──────────────────────────────────────────────────────────────────

interface Commit {
	hash:     string;
	subject:  string;
	type:     string;
	scope:    string;
	breaking: boolean;
	desc:     string;
	raw:      string;
}

// ── constants ──────────────────────────────────────────────────────────────

// conventional commit subject regex
// matches: type(scope)!: desc  OR  type!: desc  OR  type(scope): desc  OR  type: desc
const CC_RE = /^([a-z]+)(?:\(([^)]+)\))?(!)?:\s*(.+)$/;

// sections in display order
const SECTIONS: { key: string; label: string; symbol: string }[] = [
	{ key: 'breaking',  label: 'Breaking Changes', symbol: '⚠' },
	{ key: 'feat',      label: 'Features',         symbol: '✰' },
	{ key: 'fix',       label: 'Bug Fixes',        symbol: '🕱' },
	{ key: 'refactor',  label: 'Refactors',        symbol: '♽' },
	{ key: 'build',     label: 'Build & CI',       symbol: '▧' },
	{ key: 'chore',     label: 'Chores',           symbol: '𛲜' },
	{ key: 'docs',      label: 'Documentation',    symbol: '🖹' },
	{ key: 'test',      label: 'Tests',            symbol: '🗹' },
	{ key: 'other',     label: 'Other',            symbol: '�' },
];

const BUILD_TYPES      = new Set(['build', 'ci']);
const CHORE_CI_SCOPES  = new Set(['cicd', 'ci', 'cd']);

// ── git helpers ────────────────────────────────────────────────────────────

const run = (cmd: string):string => {
	return execSync(cmd, { encoding: 'utf8' }).trim();
}

const getPrevTag = (currentTag: string):string | null => {
	try {
		// --merged: only tags reachable from currentTag (ancestors only — no future tags)
		// --sort=-version:refname: semantic version descending order
		const tags = run(`git tag --merged ${currentTag} --sort=-version:refname`)
			.split('\n')
			.map(t => t.trim())
			.filter(t => /^v\d/.test(t) && t !== currentTag);
		return tags[0] ?? null;
	} catch {
		return null;
	}
}

const getCommits = (range: string):string[] => {
	try {
		const out = run(`git log ${range} --pretty=format:"%H %s"`);
		return out ? out.split('\n').filter(Boolean) : [];
	} catch {
		return [];
	}
}

// ── commit parsing ─────────────────────────────────────────────────────────

const parseCommit = (line: string):Commit => {
	const spaceIdx = line.indexOf(' ');
	const hash     = line.slice(0, spaceIdx);
	const subject  = line.slice(spaceIdx + 1);
	const hasBreakingKeyword = /\bBREAKING\b/.test(subject);

	const m = CC_RE.exec(subject);
	if (!m) {
		return { hash, subject, type: 'other', scope: '', breaking: hasBreakingKeyword, desc: subject, raw: subject };
	}

	const [, type, scope = '', bang, desc] = m;
	const breaking = !!bang || hasBreakingKeyword;
	return { hash, subject, type, scope, breaking, desc, raw: subject };
}

const sectionKey = (c: Commit):string => {
	if (c.breaking) return 'breaking';
	if (BUILD_TYPES.has(c.type)) return 'build';
	if (c.type === 'chore' && CHORE_CI_SCOPES.has(c.scope.toLowerCase())) return 'build';
	if (SECTIONS.find(s => s.key === c.type)) return c.type;
	return 'other';
}

// ── formatting ─────────────────────────────────────────────────────────────

const formatCommit = (c: Commit):string => {
	if (c.type === 'other' && !CC_RE.test(c.raw)) return `- ${c.raw}`;
	const scopePart = c.scope ? `(${c.scope})` : '';
	const bangPart  = c.breaking && sectionKey(c) === 'breaking' ? '!' : '';
	return `- **${c.type}${scopePart}${bangPart}:** ${c.desc}`;
}

// ── main ───────────────────────────────────────────────────────────────────

const currentTag = process.argv[2];
if (!currentTag) {
	process.stderr.write('usage: gen-changelog.ts <tag>\n');
	process.exit(2);
}

const prevTag    = getPrevTag(currentTag);
const range      = prevTag ? `${prevTag}..${currentTag}` : currentTag;
const rangeLabel = prevTag ? `${prevTag}...${currentTag}` : 'initial release';
const rawLines   = getCommits(range);

if (rawLines.length === 0) {
	process.stdout.write(`## ${currentTag}\n\nNo commits in this release.\n`);
	process.exit(0);
}

const commits  = rawLines.map(parseCommit);
const grouped  = new Map<string, Commit[]>();
for (const s of SECTIONS) grouped.set(s.key, []);
for (const c of commits) grouped.get(sectionKey(c))?.push(c);

const hasBreaking = (grouped.get('breaking') ?? []).length > 0;

const lines: string[] = [];
lines.push(`## ${currentTag}`);
lines.push('');
lines.push(`_${rawLines.length} commit${rawLines.length === 1 ? '' : 's'} since ${prevTag ?? 'beginning'} · [${rangeLabel}]_`);
lines.push('');

if (hasBreaking) {
	lines.push('> [!WARNING]');
	lines.push('> This release contains breaking changes. Review carefully before upgrading.');
	lines.push('');
}

for (const { key, label, symbol: emoji } of SECTIONS) {
	const entries = grouped.get(key) ?? [];
	if (entries.length === 0) continue;
	lines.push(`### ${emoji} ${label}`);
	lines.push('');
	for (const c of entries) lines.push(formatCommit(c));
	lines.push('');
}

process.stdout.write(lines.join('\n'));
process.exit(hasBreaking ? 1 : 0);
