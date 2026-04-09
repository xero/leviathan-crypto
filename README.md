[![GitHub Release](https://img.shields.io/github/v/release/xero/leviathan-crypto?sort=semver&display_name=tag&style=flat&logo=github&logoColor=989da4&label=latest%20release&labelColor=161925&color=1c7293)](https://github.com/xero/leviathan-crypto/releases/latest) [![npm package minimized gzipped size](https://img.shields.io/bundlejs/size/leviathan-crypto?format=both&style=flat&logo=googlecontaineroptimizedos&logoColor=989da4&label=package%20size&labelColor=161925&color=1c7293&cacheSeconds=36000)](https://www.npmjs.com/package/leviathan-crypto) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/xero/leviathan-crypto/test-suite.yml?branch=main&style=flat&logo=github&logoColor=989da4&label=test%20suite&labelColor=161925&color=1a936f)](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/xero/leviathan-crypto/wiki.yml?branch=main&style=flat&logo=gitbook&logoColor=989da4&label=wiki%20publish&labelColor=161925&color=1a936f)](https://github.com/xero/leviathan-crypto/wiki)

![simd webassembly](https://img.shields.io/badge/SIMD%20-%20WASM?style=flat&logo=wasmer&logoColor=1a936f&label=WASM&labelColor=33383e&color=161925) ![side-effect free](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-side-effect-free.svg) ![tree-shakeable](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-tree-shakable.svg) ![zero dependencies](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-zero-dependancies.svg) [![MIT Licensed](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-mit-license.svg)](https://github.com/xero/leviathan-crypto/blob/main/LICENSE)

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400" >

# Leviathan-Crypto

---

> WebAssembly cryptography library built on the paranoia of Serpent-256 and the elegance of XChaCha20-Poly1305.

**Serpent-256** won the AES security vote but lost the competition. The deciding factor was performance on embedded hardware, a constraint that doesn't apply to modern software. 32 rounds. S-boxes in pure Boolean logic with no table lookups. It processes every bit in every block. You use it because you trust the cryptanalysis, not because a committee endorsed it.

**XChaCha20-Poly1305** has nothing to hide. An ARX construction with 20 rounds. Add, rotate, XOR with no S-boxes or cache-timing leakage. It needs no hardware acceleration to be fast. Poly1305 adds an unconditional forgery bound. The security proof is readable.

**_Two ciphers from opposite design philosophies, only agreeing on security properties._**

**WebAssembly is the correctness layer.** Every primitive runs in its own isolated binary with its own linear memory. Execution is deterministic with no JIT speculation. Key material in one module can't interact with another, even in principle. See the [security policy](./SECURITY.md).

**TypeScript is the ergonomics layer.** The `Seal` and `SealStream` family are cipher-agnostic. Drop in `SerpentCipher` or `XChaCha20Cipher` and they handle nonces, key derivation, and authentication for you. Explicit [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) gates give you full control over how and when WASM loads. Strict typing catches misuse before it reaches production.

**Zero dependencies.** No npm graph to audit. No supply chain attack surface.

**Tree-shakeable.** Import only what you use. Subpath exports let bundlers exclude everything else.

**Side-effect free.** Nothing runs on import. [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) is explicit and asynchronous.

**Audited primitives.** Every implementation is verified against its specification. See the [audit index](https://github.com/xero/leviathan-crypto/wiki/audits.md).

---

## Installation

```bash
# use bun
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

> [!NOTE]
> [Serpent](https://github.com/xero/leviathan-crypto/wiki/serpent.md), [ChaCha20](https://github.com/xero/leviathan-crypto/wiki/chacha20.md), [ML-KEM](https://github.com/xero/leviathan-crypto/wiki/kyber.md), and [constantTimeEqual](https://github.com/xero/leviathan-crypto/wiki/utils.md#constanttimeequal) require WebAssembly SIMD support. This has been a baseline feature of all major browsers and runtimes [since 2021](https://caniuse.com/wasm-simd). SHA-2 and SHA-3 run on any WASM-capable runtime.

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
await init({ serpent: compiledModule })
```

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

| Subpath                              | Entry point                    |
| ------------------------------------ | ------------------------------ |
| `leviathan-crypto`                   | `./dist/index.js`              |
| `leviathan-crypto/stream`            | `./dist/stream/index.js`       |
| `leviathan-crypto/serpent`           | `./dist/serpent/index.js`      |
| `leviathan-crypto/serpent/embedded`  | `./dist/serpent/embedded.js`   |
| `leviathan-crypto/chacha20`          | `./dist/chacha20/index.js`     |
| `leviathan-crypto/chacha20/embedded` | `./dist/chacha20/embedded.js`  |
| `leviathan-crypto/sha2`              | `./dist/sha2/index.js`         |
| `leviathan-crypto/sha2/embedded`     | `./dist/sha2/embedded.js`      |
| `leviathan-crypto/sha3`              | `./dist/sha3/index.js`         |
| `leviathan-crypto/sha3/embedded`     | `./dist/sha3/embedded.js`      |
| `leviathan-crypto/kyber`             | `./dist/kyber/index.js`        |
| `leviathan-crypto/kyber/embedded`    | `./dist/kyber/embedded.js`     |

See [loader.md](https://github.com/xero/leviathan-crypto/wiki/loader) for the full WASM loading reference.

---

## Quick Start

*One-shot authenticated encryption.* [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead.md#seal) handles nonces, key derivation, and authentication. Zero config beyond [`init()`](https://github.com/xero/leviathan-crypto/wiki/init.md#init).

```typescript
import { init, Seal, XChaCha20Cipher } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key  = XChaCha20Cipher.keygen()
const blob = Seal.encrypt(XChaCha20Cipher, key, plaintext)
const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)  // throws AuthenticationError on tamper
```

_Prefer Serpent-256?_ Swap the cipher object and everything else stays the same.

```typescript
import { SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)
```

_Data too large to buffer in memory?_ [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead.md#sealstream) and [`OpenStream`](https://github.com/xero/leviathan-crypto/wiki/aead.md#openstream) encrypt and decrypt in chunks without loading the full message.

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

_Need parallel throughput?_ [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead.md#sealstreampool) distributes chunks across Web Workers with the same wire format.

```typescript
import { SealStreamPool } from 'leviathan-crypto/stream'

const pool      = await SealStreamPool.create(XChaCha20Cipher, key, { wasm: chacha20Wasm })
const encrypted = await pool.seal(plaintext)
const decrypted = await pool.open(encrypted)
pool.destroy()
```

_Want post-quantum security?_ [`KyberSuite`](https://github.com/xero/leviathan-crypto/wiki/kyber.md#kybersuite) wraps ML-KEM and a cipher suite into a hybrid construction. It plugs directly into [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead.md#sealstream). The sender encrypts with the public encapsulation key and only the recipient's private decapsulation key can open it.

```typescript
import { KyberSuite, MlKem768 } from 'leviathan-crypto/kyber'
import { kyberWasm }    from 'leviathan-crypto/kyber/embedded'
import { sha3Wasm }     from 'leviathan-crypto/sha3/embedded'

await init({ kyber: kyberWasm, sha3: sha3Wasm, chacha20: chacha20Wasm, sha2: sha2Wasm })

const suite = KyberSuite(new MlKem768(), XChaCha20Cipher)
const { encapsulationKey: ek, decapsulationKey: dk } = suite.keygen()

// sender — encrypts with the public key
const sealer   = new SealStream(suite, ek)
const preamble = sealer.preamble       // 1108 bytes: 20B header + 1088B KEM ciphertext
const ct0      = sealer.push(chunk0)
const ctLast   = sealer.finalize(lastChunk)

// recipient — decrypts with the private key
const opener = new OpenStream(suite, dk, preamble)
const pt0    = opener.pull(ct0)
const ptLast = opener.finalize(ctLast)
```

_More examples including hashing, key derivation, Fortuna, and raw primitives?_ See the [examples page](https://github.com/xero/leviathan-crypto/wiki/examples).

---

## Demos

**`lvthn-web`** [ [demo](https://leviathan.3xi.club/web) · [source](https://github.com/xero/leviathan-demos/tree/main/web) · [readme](https://github.com/xero/leviathan-demos/blob/main/web/README.md) ]

A self-contained browser encryption tool in a single HTML file. Encrypt text or files with Serpent-256-CBC and Argon2id key derivation, then share the armored output. No server, no install, no network connection after initial load. The code is written to be read. The Encrypt-then-MAC construction, HMAC input, and Argon2id parameters are all intentional examples worth studying.

**`lvthn-chat`** [ [demo](https://leviathan.3xi.club/chat) · [source](https://github.com/xero/leviathan-demos/tree/main/chat) · [readme](https://github.com/xero/leviathan-demos/blob/main/chat/README.md) ]

End-to-end encrypted chat over X25519 key exchange and XChaCha20-Poly1305 message encryption. The relay server is a dumb WebSocket pipe that never sees plaintext. Messages carry sequence numbers so the protocol detects and rejects replayed messages. The demo deconstructs the protocol step by step with visual feedback for injection and replay attacks.

**`lvthn-cli`** [ [npm](https://www.npmjs.com/package/lvthn) · [source](https://github.com/xero/leviathan-demos/tree/main/lvthn-cli) · [readme](https://github.com/xero/leviathan-demos/blob/main/lvthn-cli/README.md) ]

File encryption CLI supporting both Serpent-256 and XChaCha20-Poly1305 via `--cipher`. A single keyfile works with both ciphers. The header byte determines decryption automatically. Chunks distribute across a worker pool sized to `hardwareConcurrency`. Each worker owns an isolated WASM instance with no shared memory.

```sh
bun i -g lvthn # or npm slow mode
lvthn keygen --armor -o my.key
cat secret.txt | lvthn encrypt -k my.key --armor > secret.enc
```

---

## Highlights

| **_I want to..._** | |
|---|---|
| Encrypt data | [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead.md#seal) with [`SerpentCipher`](https://github.com/xero/leviathan-crypto/wiki/serpent.md#serpentcipher) or [`XChaCha20Cipher`](https://github.com/xero/leviathan-crypto/wiki/chacha20.md#xchacha20cipher) |
| Encrypt a stream or large file | [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead.md#sealstream) to encrypt, [`OpenStream`](https://github.com/xero/leviathan-crypto/wiki/aead.md#openstream) to decrypt |
| Encrypt in parallel | [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead.md#sealstreampool) distributes chunks across Web Workers |
| Add post-quantum security | [`KyberSuite`](https://github.com/xero/leviathan-crypto/wiki/kyber.md#kybersuite) wraps [`MlKem512`](https://github.com/xero/leviathan-crypto/wiki/kyber.md#parameter-sets), [`MlKem768`](https://github.com/xero/leviathan-crypto/wiki/kyber.md#parameter-sets), or [`MlKem1024`](https://github.com/xero/leviathan-crypto/wiki/kyber.md#parameter-sets) with any cipher suite |
| Hash data | [`SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#sha256), [`SHA384`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#sha384), [`SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#sha512), [`SHA3_256`](https://github.com/xero/leviathan-crypto/wiki/sha3.md#sha3_256), [`SHA3_512`](https://github.com/xero/leviathan-crypto/wiki/sha3.md#sha3_512), [`SHAKE256`](https://github.com/xero/leviathan-crypto/wiki/sha3.md#shake256) ... |
| Authenticate a message | [`HMAC_SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#hmac_sha256), [`HMAC_SHA384`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#hmac_sha384), or [`HMAC_SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#hmac_sha512) |
| Derive keys | [`HKDF_SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#hkdf_sha256) or [`HKDF_SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2.md#hkdf_sha512) |
| Generate random bytes | [`Fortuna`](https://github.com/xero/leviathan-crypto/wiki/fortuna.md#api-reference) for forward-secret generation, [`randomBytes`](https://github.com/xero/leviathan-crypto/wiki/utils.md#randombytes) for one-off use |
| Compare secrets safely | [`constantTimeEqual`](https://github.com/xero/leviathan-crypto/wiki/utils.md#constanttimeequal) uses a WASM SIMD path to prevent timing attacks |
| Work with bytes | [`hexToBytes`](https://github.com/xero/leviathan-crypto/wiki/utils.md#hextobytes), [`bytesToHex`](https://github.com/xero/leviathan-crypto/wiki/utils.md#bytestohex), [`wipe`](https://github.com/xero/leviathan-crypto/wiki/utils.md#wipe), [`xor`](https://github.com/xero/leviathan-crypto/wiki/utils.md#xor), [`concat`](https://github.com/xero/leviathan-crypto/wiki/utils.md#concat) ... |

*For raw primitives, low-level cipher access, and ASM internals see the [full API reference](https://github.com/xero/leviathan-crypto/wiki/index).*

---

## Going deeper

|   |   |
|---|---|
| [Architecture](https://github.com/xero/leviathan-crypto/wiki/architecture.md) | Repository structure, module relationships, build pipeline, and buffer layouts |
| [Test Suite](https://github.com/xero/leviathan-crypto/wiki/test-suite.md) | How the test suite works, vector corpus, and gate discipline |
| [Security Policy](./SECURITY.md) | Security posture and vulnerability disclosure details |
| [Lexicon](https://github.com/xero/leviathan-crypto/wiki/lexicon.md) | Glossary of cryptographic terms |
| [WASM Primer](https://github.com/xero/leviathan-crypto/wiki/wasm.md) | WebAssembly primer in the context of this library |
| [CDN](https://github.com/xero/leviathan-crypto/wiki/cdn.md) | Use leviathan-crypto directly from a CDN with no bundler |
| [argon2id](https://github.com/xero/leviathan-crypto/wiki/argon2id.md) | Passphrase-based encryption using Argon2id alongside leviathan primitives |

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
