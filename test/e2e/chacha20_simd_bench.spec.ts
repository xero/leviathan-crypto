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
// ChaCha20 SIMD 4-wide throughput benchmark — browser runtimes.
// Measures scalar vs inter-block SIMD throughput (MB/s) after JIT warmup.
// Primary purpose: document Firefox (SpiderMonkey) SIMD gain.
import { test } from '@playwright/test';

const JS_URL = 'http://localhost:1337/build/chacha.js';

const KEY   = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const NONCE = '000000090000004a00000000';

const BENCH_SRC = `
var __wasmCache = null;
async function loadWasm() {
  if (__wasmCache) return __wasmCache;
  __wasmCache = await import('${JS_URL}');
  return __wasmCache;
}
function fromHex(h) { return Uint8Array.from(h.match(/.{2}/g).map(b => parseInt(b, 16))) }

function benchOnce(wasm, fn, pt, key, nonce) {
  const mem = new Uint8Array(wasm.memory.buffer);
  mem.set(key,   wasm.getKeyOffset());
  mem.set(nonce, wasm.getChachaNonceOffset());
  wasm.chachaSetCounter(1);
  wasm.chachaLoadKey();
  mem.set(pt, wasm.getChunkPtOffset());
  fn(pt.length);
}

async function runBench(chunkSize, warmup, trials) {
  const wasm  = await loadWasm();
  const key   = fromHex('${KEY}');
  const nonce = fromHex('${NONCE}');
  const pt    = new Uint8Array(chunkSize).fill(0x5a);
  const scalar = wasm.chachaEncryptChunk.bind(wasm);
  const simd   = wasm.chachaEncryptChunk_simd.bind(wasm);

  // Warmup
  for (let i = 0; i < warmup; i++) {
    benchOnce(wasm, scalar, pt, key, nonce);
    benchOnce(wasm, simd,   pt, key, nonce);
  }

  // Measure scalar
  const t0s = performance.now();
  for (let i = 0; i < trials; i++) benchOnce(wasm, scalar, pt, key, nonce);
  const scalarMs = performance.now() - t0s;

  // Measure SIMD
  const t0m = performance.now();
  for (let i = 0; i < trials; i++) benchOnce(wasm, simd, pt, key, nonce);
  const simdMs = performance.now() - t0m;

  const totalBytes = chunkSize * trials;
  const scalarMBs  = (totalBytes / 1e6) / (scalarMs / 1000);
  const simdMBs    = (totalBytes / 1e6) / (simdMs   / 1000);
  return { chunkSize, scalarMBs, simdMBs, speedup: simdMBs / scalarMBs };
}
`;

test.beforeEach(async ({ page }) => {
	await page.goto('http://localhost:1337/');
	await page.evaluate(BENCH_SRC);
});

test('ChaCha20 SIMD throughput benchmark — 65536 bytes', async ({ page }) => {
	const result = await page.evaluate(async () => {
		return await runBench(65536, 50, 200);
	});
	console.log(`[SIMD bench] 65536B  scalar=${result.scalarMBs.toFixed(1)} MB/s  SIMD=${result.simdMBs.toFixed(1)} MB/s  speedup=${result.speedup.toFixed(2)}x`);
});

test('ChaCha20 SIMD throughput benchmark — 16384 bytes', async ({ page }) => {
	const result = await page.evaluate(async () => {
		return await runBench(16384, 50, 500);
	});
	console.log(`[SIMD bench] 16384B  scalar=${result.scalarMBs.toFixed(1)} MB/s  SIMD=${result.simdMBs.toFixed(1)} MB/s  speedup=${result.speedup.toFixed(2)}x`);
});

test('ChaCha20 SIMD throughput benchmark — 256 bytes', async ({ page }) => {
	const result = await page.evaluate(async () => {
		return await runBench(256, 100, 5000);
	});
	console.log(`[SIMD bench]   256B  scalar=${result.scalarMBs.toFixed(1)} MB/s  SIMD=${result.simdMBs.toFixed(1)} MB/s  speedup=${result.speedup.toFixed(2)}x`);
});
