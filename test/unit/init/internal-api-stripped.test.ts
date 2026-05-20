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
 * Public type-surface guard. `@internal` JSDoc + `stripInternal: true`
 * drops symbols from dist/*.d.ts; barrel re-exports bypass that. Test
 * asserts none leak (submodule .d.ts, submodule .js, barrel .d.ts,
 * barrel .js). v2.1.1: `_<module>Ready` probes removed; assert absent.
 * Skipped gracefully if dist/ not built.
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

// Fortuna `@internal` test-only accessors; stripped from .d.ts only.
const FORTUNA_INTERNAL_SYMBOLS = [
	'_createDeterministicForTesting',
	'_getGenKey',
	'_getPoolEntropy',
	'_getReseedCnt',
	'_getPoolHash',
];

// Removed in v2.1.1; assert absent across all four artifact classes.
const REMOVED_READY_PROBES: { module: string; symbol: string }[] = [
	{ module: 'serpent',  symbol: '_serpentReady' },
	{ module: 'chacha20', symbol: '_chachaReady'  },
	{ module: 'sha2',     symbol: '_sha2Ready'    },
	{ module: 'sha3',     symbol: '_sha3Ready'    },
	{ module: 'kyber',    symbol: '_kyberReady'   },
];

// CI: dist/ must exist or fail; local: skip gracefully.
function requireFile(path: string): string {
	if (!existsSync(path)) {
		if (process.env.CI)
			throw new Error(
				`${path} missing in CI, the workflow must run 'bun run build:ts' before this test.`,
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

	test('removed `_<module>Ready` probes are absent from dist/index.d.ts', () => {
		const dts = requireFile(barrelDts);
		if (!dts) return;
		for (const { symbol } of REMOVED_READY_PROBES)
			expect(dts, `${symbol} re-introduced into dist/index.d.ts`).not.toContain(symbol);
	});

	test('removed `_<module>Ready` probes are absent from dist/index.js', () => {
		const js = requireFile(barrelJs);
		if (!js) return;
		for (const { symbol } of REMOVED_READY_PROBES)
			expect(js, `${symbol} re-introduced into dist/index.js`).not.toContain(symbol);
	});

	test('public barrel exports survive', () => {
		const dts = requireFile(barrelDts);
		if (!dts) return;
		expect(dts).toContain('isInitialized');
		expect(dts).toContain('init');
	});
});

describe('removed `_<module>Ready` probes are absent from each submodule (v2.1.1)', () => {
	// Catches re-introduction at either the source declaration (would re-emit
	// into the submodule `.d.ts` / `.js`) or the barrel re-export (would land
	// in `dist/index.{d.ts,js}` and is covered by the barrel block above).
	for (const { module, symbol } of REMOVED_READY_PROBES) {
		test(`${symbol} is absent from dist/${module}/index.d.ts`, () => {
			const path = resolve(here, `../../../dist/${module}/index.d.ts`);
			const dts  = requireFile(path);
			if (!dts) return;
			expect(
				dts,
				`${symbol} re-emitted in dist/${module}/index.d.ts, it was removed in v2.1.1; use isInitialized('${module}') instead.`,
			).not.toContain(symbol);
		});

		test(`${symbol} is absent from dist/${module}/index.js`, () => {
			const path = resolve(here, `../../../dist/${module}/index.js`);
			const js   = requireFile(path);
			if (!js) return;
			expect(
				js,
				`${symbol} re-emitted in dist/${module}/index.js, it was removed in v2.1.1.`,
			).not.toContain(symbol);
		});
	}
});

describe('internal-API strip from Fortuna class (dist/fortuna.d.ts)', () => {
	// Class lives in dist/fortuna.d.ts; barrel re-exports the class name only.
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
