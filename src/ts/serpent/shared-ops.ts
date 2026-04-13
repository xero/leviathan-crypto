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
// src/ts/serpent/shared-ops.ts
//
// Pure-function primitives shared between the main-thread `SerpentCipher`
// (cipher-suite.ts) and the `SealStreamPool` worker (pool-worker.ts). Both
// call sites hold their own WASM exports — pool workers instantiate modules
// locally, the main thread fetches via `getInstance()` — so every function
// here takes the sha2/serpent exports as parameters. No dependency on
// `init.ts`, no module-level state, no instance wrappers.
//
// These helpers are strictly single-chunk: the caller already divided the
// payload into chunks ≤ WASM CHUNK_SIZE. For multi-chunk use, see
// `SerpentCbc.encrypt`/`decrypt`, which loop over the same WASM exports.
//
// This file owns the canonical `pkcs7Pad` / `pkcs7Strip`; `serpent-cbc.ts`
// re-exports them. A single source of truth keeps the branch-free,
// Vaudenay-2002-closed padding check identical on the main-thread and
// pool-worker paths — divergence between the two would reintroduce an
// oracle.

// ── WASM export interfaces ───────────────────────────────────────────────────

/** Subset of the sha2 WASM exports used by `hmacSha256`. */
export interface Sha2OpsExports {
	memory:              WebAssembly.Memory;
	getSha256InputOffset:() => number;
	getSha256OutOffset:  () => number;
	sha256Init:          () => void;
	sha256Update:        (len: number) => void;
	sha256Final:         () => void;
	hmac256Init:         (keyLen: number) => void;
	hmac256Update:       (len: number) => void;
	hmac256Final:        () => void;
}

/** Subset of the serpent WASM exports used by `cbcEncryptChunk`/`cbcDecryptChunk`. */
export interface SerpentOpsExports {
	memory:               WebAssembly.Memory;
	getKeyOffset:         () => number;
	getChunkPtOffset:     () => number;
	getChunkCtOffset:     () => number;
	getChunkSize:         () => number;
	getCbcIvOffset:       () => number;
	loadKey:              (n: number) => number;
	cbcEncryptChunk:      (n: number) => number;
	cbcDecryptChunk_simd: (n: number) => number;
}

// ── PKCS7 ────────────────────────────────────────────────────────────────────

// Generic error string used by every failure mode of `pkcs7Strip` and the
// length/alignment gate in `SerpentCbc.decrypt`. No numeric leaks, no
// structural disclosure — a caller cannot distinguish "bad length" from
// "bad padding" by message or by timing.
export const PKCS7_INVALID = 'invalid ciphertext';

export function pkcs7Pad(data: Uint8Array): Uint8Array {
	const padLen = 16 - (data.length % 16);  // 1..16
	const out    = new Uint8Array(data.length + padLen);
	out.set(data);
	out.fill(padLen, data.length);
	return out;
}

// `pkcs7Strip` is branch-free over secret bits and throws a single generic
// `RangeError` for every failure mode. See `serpent-cbc.ts` for the
// Vaudenay-2002 rationale; this is the canonical implementation that the
// main-thread class and pool worker share.
export function pkcs7Strip(data: Uint8Array): Uint8Array {
	if (data.length === 0 || data.length % 16 !== 0)
		throw new RangeError(PKCS7_INVALID);

	const padLen = data[data.length - 1];

	let bad = 0;
	bad |= ((padLen - 1) >>> 31);       // 1 if padLen == 0
	bad |= ((16 - padLen) >>> 31);      // 1 if padLen > 16

	// Per-byte pad-region mask without branches on secret bits.
	//   inPadRegion = 0xff when i >= 16 - padLen
	//               = 0x00 otherwise
	//
	// (16 - padLen - i - 1) is negative iff i >= 16 - padLen. A signed
	// arithmetic shift by 31 yields -1 for negative, 0 for non-negative;
	// ANDing with 0xff collapses those to 0xff and 0x00.
	for (let i = 0; i < 16; i++) {
		const idx  = data.length - 16 + i;
		const mask = ((16 - padLen - i - 1) >> 31) & 0xff;
		bad |= (data[idx] ^ padLen) & mask;
	}

	const invalid = ((bad - 1) >>> 31) ^ 1;
	if (invalid) throw new RangeError(PKCS7_INVALID);

	return data.subarray(0, data.length - padLen);
}

// ── HMAC-SHA-256 ─────────────────────────────────────────────────────────────

// Match RFC 2104 §3: keys longer than the block size (64 bytes for SHA-256)
// are pre-hashed. The loop feeds the SHA-256 / HMAC input buffer in 64-byte
// chunks — the input buffer holds exactly one block.
export function hmacSha256(
	sx: Sha2OpsExports,
	key: Uint8Array,
	msg: Uint8Array,
): Uint8Array {
	const inOff  = sx.getSha256InputOffset();
	const outOff = sx.getSha256OutOffset();
	let k = key;
	if (k.length > 64) {
		sx.sha256Init();
		feedMemory(sx.memory, inOff, k, 64, sx.sha256Update);
		sx.sha256Final();
		k = new Uint8Array(sx.memory.buffer).slice(outOff, outOff + 32);
	}
	const mem = new Uint8Array(sx.memory.buffer);
	mem.set(k, inOff);
	sx.hmac256Init(k.length);
	feedMemory(sx.memory, inOff, msg, 64, sx.hmac256Update);
	sx.hmac256Final();
	return new Uint8Array(sx.memory.buffer).slice(outOff, outOff + 32);
}

function feedMemory(
	memory: WebAssembly.Memory,
	inputOff: number,
	msg: Uint8Array,
	chunkSize: number,
	update: (n: number) => void,
): void {
	const mem = new Uint8Array(memory.buffer);
	let pos = 0;
	while (pos < msg.length) {
		const n = Math.min(msg.length - pos, chunkSize);
		mem.set(msg.subarray(pos, pos + n), inputOff);
		update(n);
		pos += n;
	}
}

// ── Serpent-CBC (single chunk) ───────────────────────────────────────────────

// Encrypt one chunk of plaintext with Serpent-256 CBC + PKCS7 padding. The
// chunk must fit in the WASM CHUNK_SIZE after padding (i.e. chunk.length
// must be ≤ CHUNK_SIZE - 16 when chunk.length is a multiple of 16, or
// ≤ CHUNK_SIZE - (chunk.length % 16) otherwise).
export function cbcEncryptChunk(
	kx: SerpentOpsExports,
	key: Uint8Array,
	iv: Uint8Array,
	chunk: Uint8Array,
): Uint8Array {
	loadKeyAndIv(kx, key, iv);
	const padded = pkcs7Pad(chunk);
	const ptOff = kx.getChunkPtOffset();
	const ctOff = kx.getChunkCtOffset();
	const mem = new Uint8Array(kx.memory.buffer);
	mem.set(padded, ptOff);
	const ret = kx.cbcEncryptChunk(padded.length);
	if (ret < 0) throw new RangeError(
		`cbcEncryptChunk rejected len=${padded.length}` +
		` (WASM CHUNK_SIZE=${kx.getChunkSize()})`,
	);
	return new Uint8Array(kx.memory.buffer).slice(ctOff, ctOff + padded.length);
}

// Decrypt one CBC chunk using the SIMD decrypt path (matches main-thread
// `SerpentCbc.decrypt`). Throws `RangeError('invalid ciphertext')` on any
// length/padding failure.
export function cbcDecryptChunk(
	kx: SerpentOpsExports,
	key: Uint8Array,
	iv: Uint8Array,
	ct: Uint8Array,
): Uint8Array {
	if (ct.length === 0 || ct.length % 16 !== 0)
		throw new RangeError(PKCS7_INVALID);
	loadKeyAndIv(kx, key, iv);
	const ctOff = kx.getChunkCtOffset();
	const ptOff = kx.getChunkPtOffset();
	const mem = new Uint8Array(kx.memory.buffer);
	mem.set(ct, ctOff);
	const ret = kx.cbcDecryptChunk_simd(ct.length);
	if (ret < 0) throw new RangeError(
		`cbcDecryptChunk_simd rejected len=${ct.length}` +
		` (WASM CHUNK_SIZE=${kx.getChunkSize()})`,
	);
	const raw = new Uint8Array(kx.memory.buffer).slice(ptOff, ptOff + ct.length);
	return pkcs7Strip(raw);
}

function loadKeyAndIv(
	kx: SerpentOpsExports,
	key: Uint8Array,
	iv: Uint8Array,
): void {
	if (key.length !== 16 && key.length !== 24 && key.length !== 32)
		throw new RangeError(`Serpent key must be 16, 24, or 32 bytes (got ${key.length})`);
	if (iv.length !== 16)
		throw new RangeError(`CBC IV must be 16 bytes (got ${iv.length})`);
	const mem = new Uint8Array(kx.memory.buffer);
	mem.set(key, kx.getKeyOffset());
	kx.loadKey(key.length);
	mem.set(iv, kx.getCbcIvOffset());
}
