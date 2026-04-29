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
/**
 * `@internal` exports are stripped from the shipped .d.ts.
 *
 * `_resetForTesting` (and its `@internal`-tagged peers in init.ts) must not
 * appear in the public type surface. tsconfig.json sets `stripInternal: true`
 * which causes tsc to drop JSDoc-`@internal`-tagged exports from generated
 * .d.ts files. This test guards against:
 *
 *   (a) `stripInternal` being dropped from tsconfig
 *   (b) the `@internal` tag being lost on `_resetForTesting`
 *   (c) a new internal export being added without the tag
 *   (d) the root barrel `src/ts/index.ts` re-exporting an internal by name —
 *       a re-export declaration carries no JSDoc, so `stripInternal` does
 *       not apply at the barrel. This bypasses (a)–(c) and leaks the
 *       symbol into `dist/index.d.ts` and `dist/index.js`.
 *
 * The test runs after `bun bake` has emitted dist/. In sessions that haven't
 * built dist/ yet, the test is skipped gracefully instead of failing.
 */

import { describe, test, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here       = dirname(fileURLToPath(import.meta.url));
const distDts    = resolve(here, '../../../dist/init.d.ts');
const barrelDts  = resolve(here, '../../../dist/index.d.ts');
const barrelJs   = resolve(here, '../../../dist/index.js');
const fortunaDts = resolve(here, '../../../dist/fortuna.d.ts');

const INTERNAL_SYMBOLS = [
	'_resetForTesting',
	'_acquireModule',
	'_releaseModule',
	'_isModuleBusy',
	'_assertNotOwned',
];

// Fortuna `@internal` test-only accessors. These live on the class, not in the
// init module, so `stripInternal: true` only drops them from `.d.ts`. The
// runtime method bodies remain in `dist/index.js` — that is expected. We only
// guard the type surface here.
const FORTUNA_INTERNAL_SYMBOLS = [
	'_createDeterministicForTesting',
	'_getGenKey',
	'_getPoolEntropy',
	'_getReseedCnt',
	'_getPoolHash',
];

// In CI, dist/ artifacts must exist — otherwise this regression guard silently
// no-ops and stripInternal regressions ship undetected. Locally, skip gracefully
// for sessions that haven't run `bun run build:ts` yet.
function requireFile(path: string): string {
	if (!existsSync(path)) {
		if (process.env.CI)
			throw new Error(
				`${path} missing in CI — the workflow must run 'bun run build:ts' before this test.`,
			);
		return '';
	}
	return readFileSync(path, 'utf8');
}

describe('internal-API strip from dist/init.d.ts', () => {
	test('_resetForTesting is absent from dist/init.d.ts', () => {
		const dts = requireFile(distDts);
		if (!dts) return;
		expect(dts).not.toContain('_resetForTesting');
	});

	test('other @internal-tagged init exports are also stripped', () => {
		const dts = requireFile(distDts);
		if (!dts) return;
		// These all carry `@internal` in src/ts/init.ts and should be stripped.
		expect(dts).not.toContain('_acquireModule');
		expect(dts).not.toContain('_releaseModule');
		expect(dts).not.toContain('_isModuleBusy');
		expect(dts).not.toContain('_assertNotOwned');
	});

	test('public init exports survive strip', () => {
		const dts = requireFile(distDts);
		if (!dts) return;
		// Smoke check: the public contract is still present.
		expect(dts).toContain('initModule');
		expect(dts).toContain('getInstance');
		expect(dts).toContain('isInitialized');
	});
});

describe('internal-API strip from root barrel (dist/index.d.ts, dist/index.js)', () => {
	test('no @internal init symbol appears in dist/index.d.ts', () => {
		const dts = requireFile(barrelDts);
		if (!dts) return;
		for (const sym of INTERNAL_SYMBOLS)
			expect(dts, `symbol ${sym} leaked into dist/index.d.ts`).not.toContain(sym);
	});

	test('no @internal init symbol appears in dist/index.js', () => {
		const js = requireFile(barrelJs);
		if (!js) return;
		for (const sym of INTERNAL_SYMBOLS)
			expect(js, `symbol ${sym} leaked into dist/index.js`).not.toContain(sym);
	});

	test('public `_<module>Ready` probes are still re-exported from the barrel', () => {
		const dts = requireFile(barrelDts);
		if (!dts) return;
		// These are legitimate public API — they must survive the barrel filter.
		expect(dts).toContain('_sha2Ready');
		expect(dts).toContain('_sha3Ready');
		expect(dts).toContain('_serpentReady');
		expect(dts).toContain('_chachaReady');
		expect(dts).toContain('_kyberReady');
	});

	test('public barrel exports survive', () => {
		const dts = requireFile(barrelDts);
		if (!dts) return;
		expect(dts).toContain('isInitialized');
		expect(dts).toContain('init');
	});
});

describe('internal-API strip from Fortuna class (dist/fortuna.d.ts)', () => {
	// The Fortuna class declaration lives in dist/fortuna.d.ts; the barrel
	// only re-exports the class name. A dropped `@internal` tag on a method
	// leaks via the class .d.ts, so check there. Also assert nothing leaks
	// through an explicit barrel re-export by symbol name.
	test('no @internal Fortuna symbol appears in dist/fortuna.d.ts', () => {
		const dts = requireFile(fortunaDts);
		if (!dts) return;
		for (const sym of FORTUNA_INTERNAL_SYMBOLS)
			expect(dts, `symbol ${sym} leaked into dist/fortuna.d.ts`).not.toContain(sym);
	});

	test('no @internal Fortuna symbol appears in dist/index.d.ts', () => {
		const dts = requireFile(barrelDts);
		if (!dts) return;
		for (const sym of FORTUNA_INTERNAL_SYMBOLS)
			expect(dts, `symbol ${sym} leaked into dist/index.d.ts`).not.toContain(sym);
	});

	test('Fortuna public API survives strip', () => {
		const dts = requireFile(fortunaDts);
		if (!dts) return;
		expect(dts).toContain('class Fortuna');
		expect(dts).toContain('addEntropy');
		expect(dts).toContain('getEntropy');
	});
});
