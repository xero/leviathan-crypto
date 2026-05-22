[![GitHub Release](https://img.shields.io/github/v/release/xero/leviathan-crypto?sort=semver&display_name=tag&style=flat&logo=github&logoColor=989da4&label=latest%20release&labelColor=161925&color=1c7293)](https://github.com/xero/leviathan-crypto/releases/latest) [![npm package minimized gzipped size](https://img.shields.io/bundlejs/size/leviathan-crypto?format=both&style=flat&logo=googlecontaineroptimizedos&logoColor=989da4&label=package%20size&labelColor=161925&color=1c7293)](https://www.npmjs.com/package/leviathan-crypto) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/xero/leviathan-crypto/test-suite.yml?branch=main&style=flat&logo=github&logoColor=989da4&label=test%20suite&labelColor=161925&color=1a936f)](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/xero/leviathan-crypto/wiki.yml?branch=main&style=flat&logo=gitbook&logoColor=989da4&label=wiki%20publish&labelColor=161925&color=1a936f)](https://github.com/xero/leviathan-crypto/wiki)

![simd webassembly](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-wasm-simd.svg) ![side-effect free](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-side-effect-free.svg) ![tree-shakeable](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-tree-shakeable.svg) ![zero dependencies](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-zero-dependencies.svg) [![MIT Licensed](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-mit-license.svg)](https://github.com/xero/leviathan-crypto/blob/main/LICENSE)

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400" >

# Leviathan Crypto: post-quantum WASM cryptography

**Zero runtime dependencies.** No NPM graph to audit. No supply chain attack surface.

**Tree-shakeable.** Import only what you use. Subpath exports let bundlers exclude everything else.

**Side-effect free.** Nothing runs on import. [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) is explicit and asynchronous.

**Cipher Triptych.** Leviathan provides three ciphers. The implementations all use a round structure that operates as a bitsliced Boolean circuit, implemented with register-only logic and no S-box lookup tables. Each compiles to an independent, v128 SIMD-optimized WebAssembly module with isolated linear memory, which prevents cross-module memory access by design. Every operation zeroes key material on exit, including on failure.

**[Serpent-256](https://github.com/xero/leviathan-crypto/wiki/serpent_reference): maximum paranoia.** 32 rounds of eight different 4-bit S-boxes, each bitsliced as a Boolean circuit with no table lookups. An ouroboros devouring every bit, in every block, through every round.

**[XChaCha20-Poly1305](https://github.com/xero/leviathan-crypto/wiki/chacha_reference): precise elegance.** 20 rounds of add-rotate-XOR alternating column and diagonal quarter-rounds, choreography without S-boxes or cache-timing leakage. A dance closing with Poly1305's unconditional forgery bound.

**[AES-256-GCM-SIV](https://github.com/xero/leviathan-crypto/wiki/aes_reference): industry standard, sharpened.** 14 rounds bitsliced into Boolean gates with tower-field S-box with no table lookups. A fresh POLYVAL key per nonce leaves GHASH-key recovery with no target.

**Beneath the cipher suites sit three hash primitive families:** [`sha2`](https://github.com/xero/leviathan-crypto/wiki/sha2) (SHA-224/256/384/512 and SHA-512/224/256, with HMAC and HKDF variants), [`sha3`](https://github.com/xero/leviathan-crypto/wiki/sha3) (SHA3-224/256/384/512 and SHAKE128/256), and [`blake3`](https://github.com/xero/leviathan-crypto/wiki/blake3) (default-mode hash, keyed_hash, derive_key, and an unbounded XOF reader). The round permutations are constant-time by algorithm design: pure bit operations with no S-box lookups and no data-dependent branches. `sha2` powers the seal layer's HKDF key derivation and Serpent's HMAC authentication. `sha3` is the Keccak sponge ML-KEM and ML-DSA rely on internally. The SHA-512 truncation variants (SHA-512/224, SHA-512/256) and SHA-224 support the twelve HashML-DSA pre-hash functions. `blake3` is the SIMD-only tree-mode hash for transcripts, content-addressed storage, and KDF work; it ships a `HashFn` compatible with the Fortuna substrate.

**Above the cipher suites sits a cipher-agnostic [AEAD layer](https://github.com/xero/leviathan-crypto/wiki/aead):** `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool`. Each takes a `CipherSuite` at construction, and the seal layer handles key derivation, nonce management, and authentication. `Seal` covers one-shot encryption for data that fits in memory. `SealStream` and `OpenStream` handle chunked data too large to buffer. WASM instances are single-threaded by design, so `SealStreamPool` distributes chunks across Web Workers to reach multi-core throughput. Any authentication failure kills the pool. Pending operations reject, workers zero their keys and terminate, and the master synchronously zeroes its copies. No retry, no partial results. All four share one wire format. A `Seal` blob is structurally a single-chunk `SealStream` output, and `OpenStream` decrypts it interchangeably.

**[ML-KEM](https://github.com/xero/leviathan-crypto/wiki/kyber): post-quantum handshake.** `KyberSuite` is a fourth `CipherSuite` factory that wraps an ML-KEM parameter set (`MlKem512`, `MlKem768`, `MlKem1024`) around any of the three ciphers above. The result slots into `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` unchanged. Constant-time Fujisaki-Okamoto comparisons run inside the Kyber WASM module; the 32-byte shared secret derives directly from a SHA-3 output and never crosses the wire, so the leading-zero-trim timing leak that hit TLS-DH(E) (the Raccoon attack) has no structural analog here.

**[X25519](https://github.com/xero/leviathan-crypto/wiki/x25519): classical key agreement.** Curve25519 Diffie-Hellman per RFC 7748 §5, with a constant-time Montgomery ladder and TS-layer rejection of the all-zero shared secret. Same key-agreement role as ML-KEM but without post-quantum guarantees; use it for ecosystem interop, ML-KEM when the threat model assumes a future CRQC, or both together when you want a hybrid handshake.

**Beside the AEAD layer sits a scheme-agnostic [signature layer](https://github.com/xero/leviathan-crypto/wiki/signing):** `Sign`, `SignStream`, and `VerifyStream`. Each takes a `SignatureSuite` at construction, and the signature layer handles M' formatting, cross-protocol domain separation, hedged-by-default signing, and constant-time verification. `Sign` covers one-shot signing over inputs that fit in memory. `SignStream` and `VerifyStream` chunk through the prehash variants for anything larger. The shipping catalog covers ML-DSA, SLH-DSA, Ed25519 (pure and Ed25519ph), and ECDSA P-256, plus PQ-only and classical+PQ hybrid composites. Every suite speaks the same interface.

**[ML-DSA](https://github.com/xero/leviathan-crypto/wiki/mldsa): lattice mainline.** `MlDsa44`, `MlDsa65`, and `MlDsa87` are FIPS 204 lattice-based signatures at NIST security categories 2, 3, and 5. Polynomial arithmetic, NTT, and rejection sampling are constant-time at the algorithm level. HashML-DSA covers the streaming path. The implementation lands every FIPS 204 §D.3 SUF-CMA check at runtime.

**[SLH-DSA](https://github.com/xero/leviathan-crypto/wiki/slhdsa): assumption-diverse hedge.** `SlhDsa128f`, `SlhDsa192f`, and `SlhDsa256f` are FIPS 205 stateless hash-based signatures at NIST security categories 1, 3, and 5. Security rests on SHAKE preimage and collision resistance rather than any lattice or number-theoretic assumption, so a future lattice break against ML-DSA does not transfer. Three PQ-only hybrid composites (`MlDsa44SlhDsa128fSuite`, `MlDsa65SlhDsa192fSuite`, `MlDsa87SlhDsa256fSuite`) bind both PQ families to the same prehash digest under a unique `ctxDomain`. One break does not cascade.

**[Merkle log](https://github.com/xero/leviathan-crypto/wiki/merkle): trust-anchored transparency.** `MerkleVerifier` and `MerkleLog` produce and verify C2SP-conformant signed checkpoints with RFC 9162 §2.1.3 / §2.1.4 inclusion and consistency proofs. Cosignatures use `Ed25519Suite` for Sigsum interop or `MlDsa44Suite` as the post-quantum default.

**[Fortuna](https://github.com/xero/leviathan-crypto/wiki/fortuna): pluggable randomness.** It collects entropy from platform-specific sources (browser input events, timing jitter, Node.js process stats, plus `crypto.getRandomValues()` as a baseline), distributes it across 32 independent pools, and reseeds an internal generator built on a cipher-as-PRF construction. The generator key is replaced after every `get()` call, so state compromise at time T cannot reveal any output produced before T. The primitive pair is pluggable, mirroring `CipherSuite`'s extension-point pattern: any of the three ciphers above plugs into the generator, paired with either SHA-256 or SHA3-256 for hashing.

**Atop the seal layer sits the [ratchet module](https://github.com/xero/leviathan-crypto/wiki/ratchet):** KDF primitives from Signal's Sparse Post-Quantum Ratchet (SPQR), the post-quantum extension of the Double Ratchet protocol. `ratchetInit` bootstraps the root and chain keys from an out-of-band shared secret. `KDFChain` advances a symmetric chain key and derives per-message keys with forward secrecy. `kemRatchetEncap` and `kemRatchetDecap` perform the ML-KEM ratchet step for post-compromise security. `SkippedKeyStore` caches message keys for out-of-order delivery; cached keys return through a transactional handle that commits on auth success and rolls back on failure, so a garbage ciphertext at a valid counter cannot consume the legitimate message's slot. The store also bounds memory and per-message HKDF work, so a malicious header with a high counter cannot force unbounded derivations. These are primitives, not a full session: state machines, message counters, header format, and epoch orchestration are application concerns. Consumers compose them with their own transport for forward-secret protocols whose needs outgrow one-shot AEAD.

**Outside the WASM-backed primitives ships a [utility tier](https://github.com/xero/leviathan-crypto/wiki/utils).** No `init()` call required, every utility function works immediately on import. Pure-TypeScript encoding converters handle hex, base64, and the common byte-format round-trips. `wipe` and `xor` modules cover byte-buffer zeroing and exclusive OR logical operations. The `cte` module is the constant-time path. It carries its own dedicated WebAssembly binary that compiles synchronously, with a zero-copy v128 SIMD XOR-accumulate kernel. `constantTimeEqual` is the library's recommended path for any equality check on secret material.

**Discipline binds the layers.** Every cipher, hash, KEM, and signature scheme derives independently from its authoritative spec, never ported from another implementation. Known-answer test vectors come from spec authors, and cross-checks run against multiple independent reference implementations. The test suite covers unit tests at the primitive level plus end-to-end tests across three browser engines (Chromium, Firefox, WebKit) and Node.js. Detailed reference documentation ships at the [project wiki](https://github.com/xero/leviathan-crypto/wiki).

---

## Architecture: TypeScript over WASM

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/layers.svg" alt="Typescript Over Wasm Layered Diagram" width="700">

The TypeScript layer never implements cryptographic algorithms. It manages the boundary between JavaScript and WebAssembly by writing inputs into WASM linear memory, calling exported functions, and reading back outputs. All algorithm logic resides within AssemblyScript.

Higher-level classes like `Seal`, `SealStream`, and `SealStreamPool` are pure TypeScript, but they compose WASM-backed primitives (Serpent-CBC, HMAC-SHA256, ChaCha20-Poly1305, and HKDF-SHA256) rather than implementing new cryptographic logic. TypeScript orchestrates, while WASM computes. Pool workers instantiate their own WASM modules and directly call primitives, bypassing the main-thread module cache.

See [wasm.md](https://github.com/xero/leviathan-crypto/wiki/wasm) for a fuller primer on WebAssembly in the context of this library.

---

## Installation

```bash
# use bun
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

v3 is the current stable line; semver applies. Runs in modern browsers, Node.js 22+, Bun, Deno, and Cloudflare Workers.

> [!IMPORTANT]
> [Serpent](https://github.com/xero/leviathan-crypto/wiki/serpent), [ChaCha20](https://github.com/xero/leviathan-crypto/wiki/chacha20), [ML-KEM](https://github.com/xero/leviathan-crypto/wiki/kyber), [AES](https://github.com/xero/leviathan-crypto/wiki/aes), [ML-DSA](https://github.com/xero/leviathan-crypto/wiki/mldsa), [BLAKE3](https://github.com/xero/leviathan-crypto/wiki/blake3), and [constantTimeEqual](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal) require WebAssembly SIMD support. This has been a baseline feature of all major browsers and runtimes [since 2021](https://caniuse.com/wasm-simd).

SIMD throughput on Apple Silicon peaks at ~1.3 GB/s for ChaCha20 and ~40 MB/s for Serpent, single-threaded; 1.2-3.2× over scalar. Full matrix across V8, SpiderMonkey, and JSC in [benchmarks](https://github.com/xero/leviathan-crypto/wiki/benchmarks).

> [!NOTE]
> Found a security issue? Don't open a public issue. See [SECURITY.md](./SECURITY.md#reporting-a-vulnerability) for the disclosure policy.

### Loading

Three loading strategies are available. Choose based on your runtime and bundler setup.

```typescript
import { init } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

// Embedded: gzip+base64 blobs bundled in the package
await init({ serpent: serpentWasm, sha2: sha2Wasm })

// URL: streaming compilation from a served .wasm file
await init({ serpent: new URL('/assets/wasm/serpent.wasm', import.meta.url) })

// Pre-compiled: pass a WebAssembly.Module directly (edge runtimes, KV cache)
const compiledModule = await WebAssembly.compileStreaming(fetch('/assets/wasm/serpent.wasm'))
await init({ serpent: compiledModule })
```

All three patterns also work straight from a CDN with no install or bundler:

```html
<script type="module">
  import { init, Seal, SerpentCipher } from 'https://unpkg.com/leviathan-crypto/dist/index.js'
  import { serpentWasm } from 'https://unpkg.com/leviathan-crypto/dist/serpent/embedded.js'
  import { sha2Wasm }    from 'https://unpkg.com/leviathan-crypto/dist/sha2/embedded.js'

  await init({ serpent: serpentWasm, sha2: sha2Wasm })
  // ... use as normal
</script>
```

See the [CDN reference](https://github.com/xero/leviathan-crypto/wiki/cdn) for unpkg/esm.sh, version pinning, SRI, and import maps.

### Tree-shaking with subpath imports

Each module ships as its own subpath export. Bundlers with tree-shaking support and `"sideEffects": false` drop every module you don't import.

```typescript
// Only serpent.wasm + sha2.wasm end up in your bundle
import { serpentInit } from 'leviathan-crypto/serpent'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Init } from 'leviathan-crypto/sha2'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await serpentInit(serpentWasm)
await sha2Init(sha2Wasm)

// ML-KEM requires kyber + sha3
import { kyberInit } from 'leviathan-crypto/kyber'
import { kyberWasm } from 'leviathan-crypto/kyber/embedded'
import { sha3Init } from 'leviathan-crypto/sha3'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await kyberInit(kyberWasm)
await sha3Init(sha3Wasm)
```

Real bundle sizes (esbuild minified + gzip):

| Use case | gzip bundle |
|---|---:|
| `Seal` + `XChaCha20Cipher` | ~17 KB |
| `Seal` + `SerpentCipher` | ~29 KB |
| Merkle log + ML-DSA-44 cosig | ~29 KB |
| Full root barrel (every export) | ~53 KB |

| Subpath                              | Module                                                  |
| ------------------------------------ | ------------------------------------------------------- |
| `leviathan-crypto`                   | root barrel (all exports)                               |
| `leviathan-crypto/stream`            | cipher-agnostic seal layer                              |
| `leviathan-crypto/serpent`           | Serpent-256                                             |
| `leviathan-crypto/serpent/embedded`  | Serpent-256 WASM blob                                   |
| `leviathan-crypto/chacha20`          | XChaCha20-Poly1305                                      |
| `leviathan-crypto/chacha20/embedded` | XChaCha20-Poly1305 WASM blob                            |
| `leviathan-crypto/sha2`              | SHA-2 family (224 / 256 / 384 / 512, HMAC, HKDF)        |
| `leviathan-crypto/sha2/embedded`     | SHA-2 WASM blob                                         |
| `leviathan-crypto/sha3`              | SHA-3 / SHAKE family                                    |
| `leviathan-crypto/sha3/embedded`     | SHA-3 WASM blob                                         |
| `leviathan-crypto/keccak`            | Keccak alias for SHA-3                                  |
| `leviathan-crypto/keccak/embedded`   | Keccak WASM blob (same bytes as `sha3/embedded`)        |
| `leviathan-crypto/kyber`             | ML-KEM                                                  |
| `leviathan-crypto/kyber/embedded`    | ML-KEM WASM blob                                        |
| `leviathan-crypto/aes`               | AES-256-GCM-SIV                                         |
| `leviathan-crypto/aes/embedded`      | AES WASM blob                                           |
| `leviathan-crypto/blake3`            | BLAKE3                                                  |
| `leviathan-crypto/blake3/embedded`   | BLAKE3 WASM blob                                        |
| `leviathan-crypto/ecdsa`             | ECDSA-P256                                              |
| `leviathan-crypto/ecdsa/embedded`    | NIST P-256 WASM blob                                    |
| `leviathan-crypto/ed25519`           | Ed25519 (pure and Ed25519ph)                            |
| `leviathan-crypto/ed25519/embedded`  | Curve25519 WASM blob                                    |
| `leviathan-crypto/mldsa`             | ML-DSA                                                  |
| `leviathan-crypto/mldsa/embedded`    | ML-DSA WASM blob                                        |
| `leviathan-crypto/slhdsa`            | SLH-DSA                                                 |
| `leviathan-crypto/slhdsa/embedded`   | SLH-DSA WASM blob                                       |
| `leviathan-crypto/x25519`            | X25519 (Curve25519 Diffie-Hellman)                      |
| `leviathan-crypto/x25519/embedded`   | Curve25519 WASM blob (same bytes as `ed25519/embedded`) |
| `leviathan-crypto/ratchet`           | forward-secret ratchet (SPQR)                           |
| `leviathan-crypto/sign`              | scheme-agnostic signature layer                         |
| `leviathan-crypto/merkle`            | Merkle log substrate                                    |

Subpaths resolve to `./dist/<mod>/index.js` and `./dist/<mod>/embedded.js`; see [`package.json`](https://github.com/xero/leviathan-crypto/blob/main/package.json) for the exact export map.

See the [exports reference](https://github.com/xero/leviathan-crypto/wiki/exports) for what each subpath exports and the [WASM loading reference](https://github.com/xero/leviathan-crypto/wiki/loader) for loading strategies.

---

## Quick Start

**_One-shot authenticated encryption._** [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal) handles nonces, key derivation, and authentication. Zero config beyond [`init()`](https://github.com/xero/leviathan-crypto/wiki/init#init).

```typescript
import {
	init,
	Seal,
	XChaCha20Cipher,
} from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key  = XChaCha20Cipher.keygen()
const blob = Seal.encrypt(XChaCha20Cipher, key, plaintext)
// throws AuthenticationError on tamper
const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)
```

**_Prefer Serpent-256?_** Swap the cipher and its module.

```diff
 import {
 	init,
 	Seal,
-	XChaCha20Cipher,
+	SerpentCipher,
 } from 'leviathan-crypto'
-import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
+import { serpentWasm }  from 'leviathan-crypto/serpent/embedded'
 import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

-await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })
+await init({ serpent: serpentWasm, sha2: sha2Wasm })

-const key  = XChaCha20Cipher.keygen()
+const key  = SerpentCipher.keygen()
-const blob = Seal.encrypt(XChaCha20Cipher, key, plaintext)
+const blob = Seal.encrypt(SerpentCipher, key, plaintext)
 // throws AuthenticationError on tamper
-const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)
+const pt   = Seal.decrypt(SerpentCipher, key, blob)
```

**_Data too large to buffer in memory?_** [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream) and [`OpenStream`](https://github.com/xero/leviathan-crypto/wiki/aead#openstream) encrypt and decrypt in chunks without loading the full message.

```typescript
import { SealStream, OpenStream } from 'leviathan-crypto/stream'

const sealer   = new SealStream(XChaCha20Cipher, key, { chunkSize: 65536 })
const preamble = sealer.preamble       // send first

const ct0    = sealer.push(chunk0)
const ct1    = sealer.push(chunk1)
const ctLast = sealer.finalize(lastChunk)

const opener = new OpenStream(XChaCha20Cipher, key, preamble)
const pt0    = opener.pull(ct0)
const pt1    = opener.pull(ct1)
const ptLast = opener.finalize(ctLast)
```

**_Need parallel throughput?_** [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool) distributes chunks across Web Workers with the same wire format.

```typescript
import { SealStreamPool } from 'leviathan-crypto/stream'

const pool      = await SealStreamPool.create(XChaCha20Cipher, key, { wasm: chacha20Wasm })
const encrypted = await pool.seal(plaintext)
const decrypted = await pool.open(encrypted)
pool.destroy()
```

**_Want post-quantum security?_** [`KyberSuite`](https://github.com/xero/leviathan-crypto/wiki/kyber#kybersuite) wraps ML-KEM and a cipher suite into a hybrid construction. It plugs directly into [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream). The sender encrypts with the public encapsulation key and only the recipient's private decapsulation key can open it.

```typescript
import { KyberSuite, MlKem768 } from 'leviathan-crypto/kyber'
import { kyberWasm }    from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })

const suite = KyberSuite(new MlKem768(), XChaCha20Cipher)
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()

// sender: encrypts with the public key
const sealer   = new SealStream(suite, ek)
const preamble = sealer.preamble       // 1108 bytes: 20B header + 1088B KEM ciphertext
const ct0      = sealer.push(chunk0)
const ctLast   = sealer.finalize(lastChunk)

// recipient: decrypts with the private key
const opener = new OpenStream(suite, dk, preamble)
const pt0    = opener.pull(ct0)
const ptLast = opener.finalize(ctLast)
```

**_Need post-quantum signatures?_** The [sign module](https://github.com/xero/leviathan-crypto/wiki/signing) wraps ML-DSA (FIPS 204) behind a `SignatureSuite` abstraction. `Sign` covers single-shot attached / detached signatures; `SignStream` and `VerifyStream` handle chunked input via HashML-DSA.

```typescript
import { init, Sign, SignStream, MlDsa65Suite, MlDsa65PreHashSuite } from 'leviathan-crypto'
import { mldsaWasm } from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }  from 'leviathan-crypto/sha3/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm })

const { pk, sk } = MlDsa65Suite.keygen()
const msg = new TextEncoder().encode('hello world')
const ctx = new TextEncoder().encode('myapp/v1')

// single-shot
const blob    = Sign.sign(MlDsa65Suite, sk, msg, ctx)
const payload = Sign.verify(MlDsa65Suite, pk, blob, ctx)

// streamed (over chunked input)
const signer = new SignStream(MlDsa65PreHashSuite, sk, ctx)
signer.update(chunk1)
signer.update(chunk2)
const sig = signer.finalize()
// wire output is signer.preamble + chunk1 + chunk2 + sig
```

Six ML-DSA suites ship: `MlDsa44Suite` / `MlDsa65Suite` / `MlDsa87Suite` for pure ML-DSA, and `MlDsa44PreHashSuite` / `MlDsa65PreHashSuite` / `MlDsa87PreHashSuite` for HashML-DSA. See the [signing reference](https://github.com/xero/leviathan-crypto/wiki/signing) for the wire format and error reference, and the [signaturesuite reference](https://github.com/xero/leviathan-crypto/wiki/signaturesuite) for the full 22-entry catalog.

**_Want belt-and-suspenders post-quantum signatures?_** Three PQ-only hybrid suites pair ML-DSA (lattice) with SLH-DSA (hash-based) at each NIST security category. The combined signature is secure as long as either family holds; a future break in one PQ assumption does not transfer to the other. The wire is one combined byte string the receiver verifies through the same `Sign` entry points.

```typescript
import { init, Sign, MlDsa65SlhDsa192fSuite } from 'leviathan-crypto'
import { mldsaWasm }  from 'leviathan-crypto/mldsa/embedded'
import { sha3Wasm }   from 'leviathan-crypto/sha3/embedded'
import { slhdsaWasm } from 'leviathan-crypto/slhdsa/embedded'

await init({ mldsa: mldsaWasm, sha3: sha3Wasm, slhdsa: slhdsaWasm })

const { pk, sk } = MlDsa65SlhDsa192fSuite.keygen()
const msg = new TextEncoder().encode('release manifest v1.2.3')
const ctx = new TextEncoder().encode('release-signing/v1')

const blob    = Sign.sign  (MlDsa65SlhDsa192fSuite, sk, msg, ctx)
const payload = Sign.verify(MlDsa65SlhDsa192fSuite, pk, blob, ctx)
// throws SigningError if either half fails to verify
```

Three hybrid suites ship at the matching NIST categories: `MlDsa44SlhDsa128fSuite` (category 1), `MlDsa65SlhDsa192fSuite` (category 3), `MlDsa87SlhDsa256fSuite` (category 5). The PQ-only hybrids complement the planned classical+PQ hybrids; the two families defend against different threat models and the [signaturesuite reference](https://github.com/xero/leviathan-crypto/wiki/signaturesuite) covers when to pick which.

**_Need classical ECDSA for X.509, JWS, or TLS interop?_** [`EcdsaP256Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#ecdsa-p256-suite) wraps ECDSA over NIST P-256 (FIPS 186-5 §6) with SHA-256 prehash baked in. Hedged-by-default per `draft-irtf-cfrg-det-sigs-with-noise-05`, low-S enforced on signer and verifier per RFC 6979 §3.5. Wire bytes are 64-byte raw `r || s`; the [`ecdsaSignatureToDer`](https://github.com/xero/leviathan-crypto/wiki/ecdsa-p256#der-utility) / [`ecdsaSignatureFromDer`](https://github.com/xero/leviathan-crypto/wiki/ecdsa-p256#der-utility) helpers convert between raw and the RFC 3279 §2.2.3 DER form for ecosystem interop.

```typescript
import { init, Sign, EcdsaP256Suite, ecdsaSignatureToDer } from 'leviathan-crypto'
import { p256Wasm } from 'leviathan-crypto/ecdsa/embedded'
import { sha2Wasm } from 'leviathan-crypto/sha2/embedded'

await init({ p256: p256Wasm, sha2: sha2Wasm })

const { pk, sk } = EcdsaP256Suite.keygen()
const msg = new TextEncoder().encode('hello world')
const sig = Sign.signDetached(EcdsaP256Suite, sk, msg, new Uint8Array(0))
const ok  = Sign.verifyDetached(EcdsaP256Suite, pk, msg, sig, new Uint8Array(0))

const der = ecdsaSignatureToDer(sig)   // X.509 / JWS / TLS interop
```

ECDSA-P256 is classical (not post-quantum); pair it with an ML-DSA or SLH-DSA suite when the threat model assumes a future CRQC. ECDSA has no native context parameter, so `EcdsaP256Suite` rejects non-empty `user_ctx`; the reserved classical+PQ hybrid suites at `0x22` / `0x23` will provide context-bound classical+PQ signing.

**_Building a secure messenger?_** The [ratchet module](https://github.com/xero/leviathan-crypto/wiki/ratchet) provides Sparse Post-Quantum Ratchet primitives for consumers who need forward secrecy and post-compromise security at the session layer. [`ratchetInit`](https://github.com/xero/leviathan-crypto/wiki/ratchet#ratchetinit) bootstraps the symmetric chains, [`KDFChain`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kdfchain) derives per-message keys, [`kemRatchetEncap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetencap) / [`kemRatchetDecap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetdecap) perform the ML-KEM ratchet step, and [`SkippedKeyStore`](https://github.com/xero/leviathan-crypto/wiki/ratchet#skippedkeystore) handles out-of-order delivery.

```typescript
import { ratchetInit, KDFChain } from 'leviathan-crypto/ratchet'

await init({ sha2: sha2Wasm })   // KDF layer only; add kyber + sha3 for KEM steps

const { nextRootKey, sendChainKey, recvChainKey } = ratchetInit(sharedSecret)
const chain = new KDFChain(sendChainKey)
const { key: messageKey, counter } = chain.stepWithCounter()
// encrypt a message with messageKey; include counter in the wire header
```

These are the primitives, not a full session. You compose them into your
transport, header format, and epoch orchestration. See the
[ratchet guide](https://github.com/xero/leviathan-crypto/wiki/ratchet)
for full construction details.

**_Looking for examples of hashing, key derivation, Fortuna, and raw primitives?_** See [examples](https://github.com/xero/leviathan-crypto/wiki/examples).

---

## Demos

**`web`** [ [demo](https://leviathan.3xi.club/web) · [source](https://github.com/xero/leviathan-demos/tree/main/web) · [readme](https://github.com/xero/leviathan-demos/blob/main/web/README.md) ]

A self-contained browser encryption tool in a single HTML file. Encrypt text or files with Serpent-256-CBC and Argon2id key derivation, then share the armored output. No server, no install, no network connection after initial load. The code is written to be read. The Encrypt-then-MAC construction, HMAC input, and Argon2id parameters are all intentional examples worth studying.

**`chat`** [ [demo](https://leviathan.3xi.club/chat) · [source](https://github.com/xero/leviathan-demos/tree/main/chat) · [readme](https://github.com/xero/leviathan-demos/blob/main/chat/README.md) ]

End-to-end encrypted chat over X25519 key exchange and XChaCha20-Poly1305 message encryption. The relay server is a dumb WebSocket pipe that never sees plaintext. Messages carry sequence numbers so the protocol detects and rejects replayed messages. The demo deconstructs the protocol step by step with visual feedback for injection and replay attacks.

**`cli`** [ [npm](https://www.npmjs.com/package/lvthn) · [source](https://github.com/xero/leviathan-demos/tree/main/cli) · [readme](https://github.com/xero/leviathan-demos/blob/main/cli/README.md) ]

Command-line file encryption tool supporting both Serpent-256 and XChaCha20-Poly1305 via `--cipher`. A single keyfile works with both ciphers. The header byte determines decryption automatically. Chunks distribute across a worker pool sized to `hardwareConcurrency`. Each worker owns an isolated WASM instance with no shared memory. The tool can export its own interactive completions for a variety of shells.

```sh
bun add -g lvthn
lvthn keygen --armor -o my.key
cat secret.txt | lvthn encrypt -k my.key --armor > secret.enc
```

**`kyber`** [ [demo](https://leviathan.3xi.club/kyber) · [source](https://github.com/xero/leviathan-demos/tree/main/kyber) · [readme](https://github.com/xero/leviathan-demos/blob/main/kyber/README.md) ]

Post-quantum cryptography demo simulating a complete ML-KEM key encapsulation ceremony between two browser-side clients. A live wire at the top of the page logs every value that crosses the channel; importantly, the shared secret never appears in the wire. After the ceremony completes, both sides independently derive a symmetric key using HKDF-SHA256 and exchange messages encrypted with XChaCha20-Poly1305. Each wire frame is expandable, revealing the raw nonce, ciphertext, Poly1305 tag, and AAD.

**`COVCOM`** [ [demo](https://leviathan.3xi.club/covcom) · [source](https://github.com/xero/covcom/) · [readme](https://github.com/xero/covcom/blob/master/README.md) ]

A covert communications application for end-to-end encrypted group conversations. Share an invite, talk, exit, and it's gone. Clients available for both the web and cli, along with a containerized dumb server for managing rooms. No secrets or cleartext beyond the handle you chose to join a room with are ever visible to the server. Featuring sparse post-quantum ratcheting, ML-KEM-768, KDFChains, Seal+KyberSuite, and a XChaCha20-Poly1305 core.

---

## Highlights

| **_I want to..._** | |
|---|---|
| Encrypt data | [`Seal`](./aead.md#seal) with [`SerpentCipher`](./serpent.md#serpentcipher), [`XChaCha20Cipher`](./chacha20.md#xchacha20cipher), or [`AESGCMSIVCipher`](./aes.md#aesgcmsivcipher) |
| Encrypt a stream or large file | [`SealStream`](./aead.md#sealstream) to encrypt, [`OpenStream`](./aead.md#openstream) to decrypt |
| Encrypt in parallel | [`SealStreamPool`](./aead.md#sealstreampool) distributes chunks across Web Workers |
| Add post-quantum security | [`KyberSuite`](./kyber.md#kybersuite) wraps [`MlKem512`](./kyber.md#parameter-sets), [`MlKem768`](./kyber.md#parameter-sets), or [`MlKem1024`](./kyber.md#parameter-sets) with any cipher suite |
| Build a forward-secret session | [`ratchetInit`](./ratchet.md#ratchetinit), [`KDFChain`](./ratchet.md#kdfchain), [`kemRatchetEncap`](./ratchet.md#kemratchetencap) / [`kemRatchetDecap`](./ratchet.md#kemratchetdecap), [`SkippedKeyStore`](./ratchet.md#skippedkeystore) |
| Sign data with a classical signature | [`Ed25519Suite`](./signaturesuite.md#ed25519-suites) / [`Ed25519PreHashSuite`](./signaturesuite.md#ed25519-suites) ([ed25519.md](./ed25519.md)) or [`EcdsaP256Suite`](./signaturesuite.md#ecdsa-p256-suite) ([ecdsa-p256.md](./ecdsa-p256.md)) via [`Sign`](./signing.md#sign) / [`SignStream`](./signing.md#signstream) / [`VerifyStream`](./signing.md#verifystream) |
| Sign data with a post-quantum signature | `MlDsa44/65/87Suite` (+ `*PreHashSuite`) for lattice ML-DSA ([mldsa.md](./mldsa.md)) or `SlhDsa128f/192f/256fSuite` (+ `*PreHashSuite`) for hash-based SLH-DSA ([slhdsa.md](./slhdsa.md)). Full catalog in [signaturesuite.md](./signaturesuite.md) |
| Sign data with a classical+PQ hybrid | [`MlDsa44Ed25519Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding), [`MlDsa65Ed25519Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding), [`MlDsa44EcdsaP256Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding), [`MlDsa65EcdsaP256Suite`](./signaturesuite.md#classicalpq-hybrid-composite-encoding) for `draft-ietf-lamps-pq-composite-sigs` |
| Sign data with a PQ-only hybrid | [`MlDsa44SlhDsa128fSuite`](./signaturesuite.md#pq-only-hybrid-suites), [`MlDsa65SlhDsa192fSuite`](./signaturesuite.md#pq-only-hybrid-suites), [`MlDsa87SlhDsa256fSuite`](./signaturesuite.md#pq-only-hybrid-suites) for ML-DSA + SLH-DSA composites at matching NIST categories |
| Build a transparency log | [`MerkleLog`](./merkle.md#merklelog) for append plus inclusion / consistency proofs, [`MerkleVerifier`](./merkle.md#merkleverifier) for clients, [`SignedLog`](./merkle.md#signedlog) for custom storage backends |
| Exchange a key with a peer | [`X25519`](./x25519.md) for Curve25519 Diffie-Hellman |
| Hash data | [`SHA256`](./sha2.md#sha256), [`SHA384`](./sha2.md#sha384), [`SHA512`](./sha2.md#sha512), [`SHA3_256`](./sha3.md#sha3_256), [`SHA3_512`](./sha3.md#sha3_512), [`SHAKE256`](./sha3.md#shake256) ... |
| Authenticate a message | [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), [`HMAC_SHA512`](./sha2.md#hmac_sha512), or [`KMAC256`](./kmac.md#kmac256) |
| Derive keys | [`HKDF_SHA256`](./sha2.md#hkdf_sha256) or [`HKDF_SHA512`](./sha2.md#hkdf_sha512) |
| Generate random bytes | [`Fortuna`](./fortuna.md#api-reference) for forward-secret generation, [`randomBytes`](./utils.md#randombytes) for one-off use |
| Compare secrets safely | [`constantTimeEqual`](./utils.md#constanttimeequal) uses a WASM SIMD path to prevent timing attacks |
| Work with bytes | [`hexToBytes`](./utils.md#hextobytes), [`bytesToHex`](./utils.md#bytestohex), [`wipe`](./utils.md#wipe), [`xor`](./utils.md#xor), [`concat`](./utils.md#concat) ... |

*For raw primitives, low-level cipher access, and ASM internals see the [full API reference](https://github.com/xero/leviathan-crypto/wiki/index).*

---

## Going deeper

| **Document** | |
|---|---|
| [Architecture](https://github.com/xero/leviathan-crypto/wiki/architecture) | Repository structure, module relationships, build pipeline, and buffer layouts |
| [Test Suite](https://github.com/xero/leviathan-crypto/wiki/test-suite) | How the test suite works, vector corpus, and gate discipline |
| [Security Policy](./SECURITY.md) | Security posture and vulnerability disclosure details |
| [Audits](https://github.com/xero/leviathan-crypto/wiki/audits) | Every primitive has a published audit covering spec conformance, known-answer tests, constant-time discipline, and ACVP validation where applicable. |
| [Lexicon](https://github.com/xero/leviathan-crypto/wiki/lexicon) | Glossary of cryptographic terms |
| [WASM Primer](https://github.com/xero/leviathan-crypto/wiki/wasm) | WebAssembly primer in the context of this library |
| [CDN](https://github.com/xero/leviathan-crypto/wiki/cdn) | Use leviathan-crypto directly from a CDN with no bundler |
| [argon2id](https://github.com/xero/leviathan-crypto/wiki/argon2id) | Passphrase-based encryption using Argon2id alongside leviathan primitives |

---

## License

leviathan-crypto is released under the [MIT license](./LICENSE).

```
                ▄▄▄▄▄▄▄▄▄▄
         ▄████████████████████▄▄
      ▄██████████████████████ ▀████▄
    ▄█████████▀▀▀     ▀███████▄▄███████▌
   ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
   ████████      ███▀▀     ████▀  █▀ █▀
   ███████▌    ▀██▀         ██
    ███████   ▀███           ▀██ ▀█▄
     ▀██████   ▄▄██            ▀▀  ██▄
       ▀█████▄   ▄██▄             ▄▀▄▀
          ▀████▄   ▄██▄
            ▐████   ▐███
     ▄▄██████████    ▐███         ▄▄
  ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███
 ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀
████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄
█████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄███▀
▀██████▀             ▀████▄▄▄████▀
                        ▀█████▀
```
