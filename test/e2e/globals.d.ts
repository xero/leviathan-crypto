// Ambient declarations for globals injected into the browser context
// via page.evaluate(INIT) in each e2e spec. These do not exist in
// Node/Playwright runner scope — declared here so tsc does not emit
// "Cannot find name" diagnostics inside page.evaluate() callbacks.

// Superset of all WASM module exports used across e2e specs.
// Each spec's module only implements a subset at runtime.
interface WasmExports {
	memory: WebAssembly.Memory;
	wipeBuffers(): void;
	// serpent
	getKeyOffset(): number;
	getBlockPtOffset(): number;
	getBlockCtOffset(): number;
	getChunkPtOffset(): number;
	getChunkCtOffset(): number;
	getNonceOffset(): number;
	loadKey(len: number): number;
	encryptBlock(): void;
	decryptBlock(): void;
	resetCounter(): void;
	encryptChunk(len: number): void;
	decryptChunk(len: number): void;
	setCounter(n: number): void;
	// chacha20
	getChachaNonceOffset(): number;
	getPolyKeyOffset(): number;
	getPolyMsgOffset(): number;
	getPolyTagOffset(): number;
	getXChaChaNonceOffset(): number;
	getXChaChaSubkeyOffset(): number;
	chachaSetCounter(n: number): void;
	chachaLoadKey(): void;
	chachaEncryptChunk(len: number): void;
	chachaGenPolyKey(): void;
	hchacha20(): void;
	polyInit(): void;
	polyUpdate(len: number): void;
	polyFinal(): void;
	// sha2
	getSha256InputOffset(): number;
	getSha256OutOffset(): number;
	getSha512InputOffset(): number;
	getSha512OutOffset(): number;
	sha256Init(): void;
	sha256Update(len: number): void;
	sha256Final(): void;
	sha512Init(): void;
	sha512Update(len: number): void;
	sha512Final(): void;
	sha384Init(): void;
	sha384Final(): void;
	hmac256Init(len: number): void;
	hmac256Update(len: number): void;
	hmac256Final(): void;
	hmac512Init(len: number): void;
	hmac512Update(len: number): void;
	hmac512Final(): void;
	// sha3
	getInputOffset(): number;
	getOutOffset(): number;
	sha3_256Init(): void;
	sha3_256Final(): void;
	sha3_512Init(): void;
	sha3_512Final(): void;
	shake128Init(): void;
	shakeFinal(len: number): void;
	keccakAbsorb(len: number): void;
}

// ── Universal (every spec) ─────────────────────────────────────────
declare function loadWasm(): Promise<WasmExports>;
declare function fromHex(hex: string): Uint8Array;
declare function toHex(bytes: Uint8Array | number[]): string;
declare let __wasmCache: WasmExports | null;

// ── Pool specs (load compiled TS dist instead of raw WASM) ────────
interface PoolLibSerpentStream {
	seal(key: Uint8Array, pt: Uint8Array, chunkSize?: number): Uint8Array;
	open(key: Uint8Array, ct: Uint8Array): Uint8Array;
	dispose(): void;
}

interface PoolLibSerpentStreamPool {
	seal(key: Uint8Array, pt: Uint8Array, chunkSize?: number): Promise<Uint8Array>;
	open(key: Uint8Array, ct: Uint8Array): Promise<Uint8Array>;
	dispose(): void;
	size: number;
}

interface PoolLibXChaCha {
	encrypt(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad?: Uint8Array): Uint8Array;
	decrypt(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad?: Uint8Array): Uint8Array;
	dispose(): void;
}

interface PoolLibXChaChaPool {
	encrypt(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;
	decrypt(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;
	dispose(): void;
	size: number;
}

interface PoolLib {
	SerpentStream: new () => PoolLibSerpentStream;
	SerpentStreamPool: { create(opts?: { workers?: number }): Promise<PoolLibSerpentStreamPool> };
	XChaCha20Poly1305: new () => PoolLibXChaCha;
	XChaCha20Poly1305Pool: { create(opts?: { workers?: number }): Promise<PoolLibXChaChaPool> };
}

declare function loadLib(): Promise<PoolLib>;

// ── Poly1305 / ChaCha20-Poly1305 / XChaCha20 specs ────────────────
declare function polyFeed(wasm: WasmExports, data: Uint8Array): void;
declare function lenBlock(aadLen: number, ctLen: number): Uint8Array;
declare function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
declare function xchachaEncrypt(
	wasm: WasmExports,
	key: Uint8Array,
	nonce24: Uint8Array,
	pt: Uint8Array,
	aad: Uint8Array
): Uint8Array;

// ── Serpent-Nessie spec ────────────────────────────────────────────
declare function nessieBytes(hex: string): string;
declare function parseNessie(text: string): { key: string; pt: string; ct: string }[];
