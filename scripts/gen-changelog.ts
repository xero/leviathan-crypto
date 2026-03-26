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
//
// Commit footer conventions parsed:
//   Closes/Fixes/Fix/Fixed/Close/Closed #NNN  = linked issue
//   PR: #NNN                                  = originating pull request
//   Co-authored-by: Name <user@users.noreply.github.com>  = contributor

import { execSync } from 'node:child_process';

// ── types ──────────────────────────────────────────────────────────────────

interface Commit {
	hash:         string;
	subject:      string;
	type:         string;
	scope:        string;
	breaking:     boolean;
	desc:         string;
	raw:          string;
	body:         string;
	issue:        string;
	pr:           string;
	contributors: string[];
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
	{ key: 'other',     label: 'Other',            symbol: '◈' },
];

const BUILD_TYPES     = new Set(['build', 'ci']);
const CHORE_CI_SCOPES = new Set(['cicd', 'ci', 'cd']);

// ── git helpers ────────────────────────────────────────────────────────────

const run = (cmd: string): string => execSync(cmd, { encoding: 'utf8' }).trim();

const getRepoUrl = (): string | null => {
	try {
		const r = run('git remote get-url origin');
		const m = r.match(/(?:git@github\.com:|https:\/\/github\.com\/)(.+?)(?:\.git)?$/);
		return m ? `https://github.com/${m[1]}` : null;
	} catch { return null; }
}

const getPrevTag = (tag: string): string | null => {
	try {
		const tags = run(`git tag --merged ${tag} --sort=-version:refname`)
			.split('\n').map(t => t.trim()).filter(t => /^v\d/.test(t) && t !== tag);
		return tags[0] ?? null;
	} catch { return null; }
}

// use ASCII field/record separators to safely split hash, subject, body
const getRawCommits = (range: string): {hash: string; subject: string; body: string}[] => {
	try {
		const out = run(`git log ${range} --pretty=format:"%H%x1f%s%x1f%b%x1e"`);
		if (!out) return [];
		return out.split('\x1e').filter(Boolean).map(r => {
			const [hash, subject, body = ''] = r.split('\x1f');
			return { hash: hash.trim(), subject: subject.trim(), body: body.trim() };
		});
	} catch { return []; }
}

// ── commit parsing ─────────────────────────────────────────────────────────

// prefer github username from noreply email, fallback to first name token
const parseContributor = (name: string, email: string): string =>
	email.match(/^([^@+]+)(?:\+[^@]+)?@users\.noreply\.github\.com$/)?.[1] ?? name.split(' ')[0];

const parseCommit = ({ hash, subject, body }: {hash: string; subject: string; body: string}): Commit => {
	const hasBreakingKeyword = /\bBREAKING\b/.test(subject);
	const m            = CC_RE.exec(subject);
	const issue        = body.match(/^(?:Fix(?:e[sd])?|Clos(?:e[sd]?)) #(\d+)/im)?.[1] ?? '';
	const pr           = body.match(/^PR:\s*#(\d+)/im)?.[1] ?? '';
	const contributors = [...body.matchAll(/^Co-authored-by:\s*(.+?)\s*<([^>]+)>/gim)]
		.map(a => parseContributor(a[1], a[2]));

	if (!m) return { hash, subject, type: 'other', scope: '', breaking: hasBreakingKeyword, desc: subject, raw: subject, body, issue, pr, contributors };
	const [, type, scope = '', bang, desc] = m;
	return { hash, subject, type, scope, breaking: !!bang || hasBreakingKeyword, desc, raw: subject, body, issue, pr, contributors };
}

const sectionKey = (c: Commit): string => {
	if (c.breaking) return 'breaking';
	if (BUILD_TYPES.has(c.type)) return 'build';
	if (c.type === 'chore' && CHORE_CI_SCOPES.has(c.scope.toLowerCase())) return 'build';
	if (SECTIONS.find(s => s.key === c.type)) return c.type;
	return 'other';
}

// ── formatting ─────────────────────────────────────────────────────────────

const commitSymbol = (c: Commit): string =>
	c.breaking ? '⚠' : (SECTIONS.find(s => s.key === sectionKey(c))?.symbol ?? '◈');

const tableRow = (c: Commit, repoUrl: string | null): string => {
	const scopePart = c.scope ? `(${c.scope})` : '';
	const bangPart  = c.breaking ? '!' : '';
	const base      = c.type === 'other' && !CC_RE.test(c.raw)
		? c.raw
		: `${c.type}${scopePart}${bangPart}: ${c.desc}`;
	const commit    = c.breaking ? `**${base}**` : base;

	const short    = c.hash.slice(0, 7);
	const hashLink = repoUrl ? `[${short}](${repoUrl}/commit/${c.hash})` : short;
	const meta     = [`↗ ${hashLink}`];
	if (c.issue) meta.push(repoUrl ? `[#${c.issue}](${repoUrl}/issues/${c.issue})` : `#${c.issue}`);
	if (c.pr)    meta.push(repoUrl ? `[!${c.pr}](${repoUrl}/pull/${c.pr})` : `!${c.pr}`);
	for (const u of c.contributors) meta.push(`[@${u}](https://github.com/${u})`);

	return `| ${commitSymbol(c)} | ${commit} | ${meta.join(' · ')} |`;
}

// ── main ───────────────────────────────────────────────────────────────────

const currentTag = process.argv[2];
if (!currentTag) {
	process.stderr.write('usage: gen-changelog.ts <tag>\n');
	process.exit(2);
}

const repoUrl    = getRepoUrl();
const prevTag    = getPrevTag(currentTag);
const range      = prevTag ? `${prevTag}..${currentTag}` : currentTag;
const rangeLabel = prevTag ? `${prevTag}...${currentTag}` : 'initial release';
const compareUrl = repoUrl && prevTag ? `${repoUrl}/compare/${rangeLabel}` : null;
const rangeLink  = compareUrl ? `[${rangeLabel}](${compareUrl})` : rangeLabel;
const rawCommits = getRawCommits(range);

if (rawCommits.length === 0) {
	process.stdout.write(`## ${currentTag}\n\nNo commits in this release.\n`);
	process.exit(0);
}

const commits     = rawCommits.map(parseCommit);
const hasBreaking = commits.some(c => c.breaking);

const lines: string[] = [];
lines.push(`## ${currentTag}`);
lines.push('');
lines.push(`_${rawCommits.length} commit${rawCommits.length === 1 ? '' : 's'} since ${prevTag ?? 'beginning'} · ${rangeLink}_`);
lines.push('');

if (hasBreaking) {
	lines.push('> [!WARNING]');
	lines.push('> This release contains breaking changes. Review carefully before upgrading.');
	lines.push('');
}

lines.push('| Type | Commit | Meta |');
lines.push('| :---: | :--- | :--- |');
for (const c of commits) lines.push(tableRow(c, repoUrl));

lines.push('');
lines.push('<details><summary>legend</summary>');
lines.push('');
for (const { symbol, label, key } of SECTIONS)
	lines.push(`- ${symbol} **${label}** — \`${key === 'breaking' ? 'breaking change' : key}\``);
lines.push('');
lines.push('</details>');

process.stdout.write(lines.join('\n'));
process.exit(hasBreaking ? 1 : 0);
