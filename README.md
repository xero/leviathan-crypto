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

**A uniform API.** The same call shape drives [authenticated encryption](https://github.com/xero/leviathan-crypto/wiki/aead), [signatures and key agreement](https://github.com/xero/leviathan-crypto/wiki/signing), [post-quantum KEM](https://github.com/xero/leviathan-crypto/wiki/mlkem), [hashing](https://github.com/xero/leviathan-crypto/wiki/hashing), [transparency logs](https://github.com/xero/leviathan-crypto/wiki/merkle), [post-quantum ratchet](https://github.com/xero/leviathan-crypto/wiki/ratchet), the [Fortuna CSPRNG](https://github.com/xero/leviathan-crypto/wiki/fortuna), [utilities](https://github.com/xero/leviathan-crypto/wiki/utils), and [types](https://github.com/xero/leviathan-crypto/wiki/types).

**The correctness contract.** Every cipher, hash, KEM, and signature scheme derives independently from its authoritative spec, never ported from another implementation. Known-answer test vectors come from spec authors, and cross-checks run against multiple independent reference implementations. The test suite covers unit tests at the primitive level plus end-to-end tests across three browser engines (Chromium, Firefox, WebKit) and Node.js. Detailed reference documentation ships at the [project wiki](https://github.com/xero/leviathan-crypto/wiki).

---

## Highlights

| **_I want to..._** | |
|---|---|
| Encrypt data | [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal) with [`SerpentCipher`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentcipher), [`XChaCha20Cipher`](https://github.com/xero/leviathan-crypto/wiki/chacha20#xchacha20cipher), or [`AESGCMSIVCipher`](https://github.com/xero/leviathan-crypto/wiki/aes#aesgcmsivcipher) |
| Encrypt a stream or large file | [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream) to encrypt, [`OpenStream`](https://github.com/xero/leviathan-crypto/wiki/aead#openstream) to decrypt |
| Encrypt in parallel | [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool) distributes chunks across Web Workers |
| Add post-quantum security | [`MlKemSuite`](https://github.com/xero/leviathan-crypto/wiki/mlkem#mlkemsuite) wraps [`MlKem512`](https://github.com/xero/leviathan-crypto/wiki/mlkem#parameter-sets), [`MlKem768`](https://github.com/xero/leviathan-crypto/wiki/mlkem#parameter-sets), or [`MlKem1024`](https://github.com/xero/leviathan-crypto/wiki/mlkem#parameter-sets) with any cipher suite |
| Build a forward-secret session | [`ratchetInit`](https://github.com/xero/leviathan-crypto/wiki/ratchet#ratchetinit), [`KDFChain`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kdfchain), [`kemRatchetEncap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetencap) / [`kemRatchetDecap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetdecap), [`SkippedKeyStore`](https://github.com/xero/leviathan-crypto/wiki/ratchet#skippedkeystore) |
| Sign data with a classical signature | [`Ed25519Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#ed25519-suites) / [`Ed25519PreHashSuite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#ed25519-suites) ([ed25519](https://github.com/xero/leviathan-crypto/wiki/ed25519)) or [`EcdsaP256Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#ecdsa-p256-suite) ([ecdsa-p256](https://github.com/xero/leviathan-crypto/wiki/ecdsa-p256)) via [`Sign`](https://github.com/xero/leviathan-crypto/wiki/signing#sign) / [`SignStream`](https://github.com/xero/leviathan-crypto/wiki/signing#signstream) / [`VerifyStream`](https://github.com/xero/leviathan-crypto/wiki/signing#verifystream) |
| Sign data with a post-quantum signature | `MlDsa44/65/87Suite` (+ `*PreHashSuite`) for lattice ML-DSA ([mldsa](https://github.com/xero/leviathan-crypto/wiki/mldsa)) or `SlhDsa128f/192f/256fSuite` (+ `*PreHashSuite`) for hash-based SLH-DSA ([slhdsa](https://github.com/xero/leviathan-crypto/wiki/slhdsa)). Full catalog in [signaturesuite](https://github.com/xero/leviathan-crypto/wiki/signaturesuite) |
| Sign data with a classical+PQ hybrid | [`MlDsa44Ed25519Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#classicalpq-hybrid-composite-encoding), [`MlDsa65Ed25519Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#classicalpq-hybrid-composite-encoding), [`MlDsa44EcdsaP256Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#classicalpq-hybrid-composite-encoding), [`MlDsa65EcdsaP256Suite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#classicalpq-hybrid-composite-encoding) for `draft-ietf-lamps-pq-composite-sigs` |
| Sign data with a PQ-only hybrid | [`MlDsa44SlhDsa128fSuite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#pq-only-hybrid-suites), [`MlDsa65SlhDsa192fSuite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#pq-only-hybrid-suites), [`MlDsa87SlhDsa256fSuite`](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#pq-only-hybrid-suites) for ML-DSA + SLH-DSA composites at matching NIST categories |
| Build a transparency log | [`MerkleLog`](https://github.com/xero/leviathan-crypto/wiki/merkle#merklelog) for append plus inclusion / consistency proofs, [`MerkleVerifier`](https://github.com/xero/leviathan-crypto/wiki/merkle#merkleverifier) for clients, [`SignedLog`](https://github.com/xero/leviathan-crypto/wiki/merkle#signedlog) for custom storage backends |
| Exchange a key with a peer | [`X25519`](https://github.com/xero/leviathan-crypto/wiki/x25519) for Curve25519 Diffie-Hellman |
| Hash data | [`SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2#sha256), [`SHA384`](https://github.com/xero/leviathan-crypto/wiki/sha2#sha384), [`SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2#sha512), [`SHA3_256`](https://github.com/xero/leviathan-crypto/wiki/sha3#sha3_256), [`SHA3_512`](https://github.com/xero/leviathan-crypto/wiki/sha3#sha3_512), [`SHAKE256`](https://github.com/xero/leviathan-crypto/wiki/sha3#shake256) ... |
| Authenticate a message | [`HMAC_SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2#hmac_sha256), [`HMAC_SHA384`](https://github.com/xero/leviathan-crypto/wiki/sha2#hmac_sha384), [`HMAC_SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2#hmac_sha512), or [`KMAC256`](https://github.com/xero/leviathan-crypto/wiki/kmac#kmac256) |
| Derive keys | [`HKDF_SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2#hkdf_sha256) or [`HKDF_SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2#hkdf_sha512) |
| Generate random bytes | [`Fortuna`](https://github.com/xero/leviathan-crypto/wiki/fortuna#api-reference) for forward-secret generation, [`randomBytes`](https://github.com/xero/leviathan-crypto/wiki/utils#randombytes) for one-off use |
| Compare secrets safely | [`constantTimeEqual`](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal) uses a WASM SIMD path to prevent timing attacks |
| Work with bytes | [`hexToBytes`](https://github.com/xero/leviathan-crypto/wiki/utils#hextobytes), [`bytesToHex`](https://github.com/xero/leviathan-crypto/wiki/utils#bytestohex), [`wipe`](https://github.com/xero/leviathan-crypto/wiki/utils#wipe), [`xor`](https://github.com/xero/leviathan-crypto/wiki/utils#xor), [`concat`](https://github.com/xero/leviathan-crypto/wiki/utils#concat) ... |

*For raw primitives, low-level cipher access, and ASM internals see the [full API reference](https://github.com/xero/leviathan-crypto/wiki/index).*

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
> [Serpent](https://github.com/xero/leviathan-crypto/wiki/serpent), [ChaCha20](https://github.com/xero/leviathan-crypto/wiki/chacha20), [ML-KEM](https://github.com/xero/leviathan-crypto/wiki/mlkem), [AES](https://github.com/xero/leviathan-crypto/wiki/aes), [ML-DSA](https://github.com/xero/leviathan-crypto/wiki/mldsa), [BLAKE3](https://github.com/xero/leviathan-crypto/wiki/blake3), and [constantTimeEqual](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal) require WebAssembly SIMD support. This has been a baseline feature of all major browsers and runtimes [since 2021](https://caniuse.com/wasm-simd).

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

// ML-KEM requires mlkem + sha3
import { mlkemInit } from 'leviathan-crypto/mlkem'
import { mlkemWasm } from 'leviathan-crypto/mlkem/embedded'
import { sha3Init } from 'leviathan-crypto/sha3'
import { sha3Wasm } from 'leviathan-crypto/sha3/embedded'

await mlkemInit(mlkemWasm)
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
| `leviathan-crypto/mlkem`             | ML-KEM                                                  |
| `leviathan-crypto/mlkem/embedded`    | ML-KEM WASM blob                                        |
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

Subpaths resolve to `./dist/<mod>/index.js` and `./dist/<mod>/embedded.js`.

> [!NOTE]
> See also:
> - [`package.json`](https://github.com/xero/leviathan-crypto/blob/main/package.json) for the exact export map
> - [exports reference](https://github.com/xero/leviathan-crypto/wiki/exports) for what each subpath exports
> - [WASM loading reference](https://github.com/xero/leviathan-crypto/wiki/loader) for the three loading strategies

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

**_Want post-quantum security?_** [`MlKemSuite`](https://github.com/xero/leviathan-crypto/wiki/mlkem#mlkemsuite) wraps ML-KEM and a cipher suite into a hybrid construction. It plugs directly into [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream). The sender encrypts with the public encapsulation key and only the recipient's private decapsulation key can open it.

```typescript
import { MlKemSuite, MlKem768 } from 'leviathan-crypto/mlkem'
import { mlkemWasm }    from 'leviathan-crypto/mlkem/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'

await init({ mlkem: mlkemWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })

const suite = MlKemSuite(new MlKem768(), XChaCha20Cipher)
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

await init({ sha2: sha2Wasm })   // KDF layer only; add mlkem + sha3 for KEM steps

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

A self-contained browser encryption tool in a single HTML file. Encrypt text or files with Serpent-256-CBC and scrypt key derivation, then share the armored output. No server, no install, no network connection after initial load. The code is written to be read. The Encrypt-then-MAC construction, HMAC input, and scrypt parameters are all intentional examples worth studying.

**`tamper`** [ [demo](https://leviathan.3xi.club/tamper) · [source](https://github.com/xero/leviathan-demos/tree/main/tamper) · [readme](https://github.com/xero/leviathan-demos/blob/main/tamper/README.md) ]

A crypto attack-resilience demo. It runs a real two-party encrypted channel, then lets you attack it: forge a replay and the sequence check rejects it, tamper with a frame and the Poly1305 tag fails. Key exchange uses X25519 with HKDF-SHA256, message encryption uses XChaCha20-Poly1305, and the relay server is a dumb WebSocket pipe that never sees plaintext. The demo deconstructs the protocol step by step with visual feedback for injection and replay attacks. For a real, production-ready secure messenger built on the same library, see [COVCOM](https://github.com/xero/covcom).

**`cli`** [ [npm](https://www.npmjs.com/package/lvthn) · [source](https://github.com/xero/leviathan-demos/tree/main/cli) · [readme](https://github.com/xero/leviathan-demos/blob/main/cli/README.md) ]

Command-line file encryption tool supporting Serpent-256-CBC+HMAC-SHA256, XChaCha20-Poly1305, and AES-256-GCM-SIV via `--cipher`. A single keyfile works with all three ciphers. The header byte determines decryption automatically. Chunks distribute across a worker pool sized to `hardwareConcurrency`. Each worker owns an isolated WASM instance with no shared memory. The tool can export its own interactive completions for a variety of shells.

```sh
bun add -g lvthn
lvthn keygen --armor -o my.key
cat secret.txt | lvthn encrypt -k my.key --armor > secret.enc
```

**`kyber`** [ [demo](https://leviathan.3xi.club/kyber) · [source](https://github.com/xero/leviathan-demos/tree/main/kyber) · [readme](https://github.com/xero/leviathan-demos/blob/main/kyber/README.md) ]

Post-quantum cryptography demo simulating a complete ML-KEM key encapsulation ceremony between two browser-side clients. A live wire at the top of the page logs every value that crosses the channel; importantly, the shared secret never appears in the wire. After the ceremony completes, both sides independently derive a symmetric key using HKDF-SHA256 and exchange messages encrypted with XChaCha20-Poly1305. Each wire frame is expandable, revealing the raw nonce, ciphertext, Poly1305 tag, and AAD.

**`jwt`** [ [demo](https://leviathan.3xi.club/jwt) · [source](https://github.com/xero/leviathan-demos/tree/main/jwt) · [readme](https://github.com/xero/leviathan-demos/blob/main/jwt/README.md) ]

Classical and post-quantum JSON Web Token signing demo in a single self-contained HTML file. It signs the same claims across eleven algorithms: EdDSA and ES256, the post-quantum ML-DSA and SLH-DSA families, and the leviathan hybrid composites. Every algorithm runs through one uniform path on the `Sign` suite API, with no per-algorithm branching. The token renders with its three segments color-coded and a live byte readout, so the cost of quantum resistance is visible: the same token grows from about 220 bytes under Ed25519 to past 66 kilobytes under SLH-DSA-SHAKE-256f. Tamper with the payload and verification rejects it, because the signature covers the original bytes.

**`COVCOM`** [ [demo](https://leviathan.3xi.club/covcom) · [source](https://github.com/xero/covcom/) · [readme](https://github.com/xero/covcom/blob/master/README.md) ]

Covert communications app suite for private group conversations. Invite, talk, close the client, and the chat vanishes. Every message is encrypted with XChaCha20 and signed with Ed25519. A BLAKE3 fingerprint on each key allows peers to verify one another. SPQR's manual and epoch ratchets add forward secrecy, while post-quantum ML-KEM-768 encapsulation keeps recorded communications unreadable and secure against future cryptanalysis.

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
