[![GitHub Release](https://img.shields.io/github/v/release/xero/leviathan-crypto?sort=semver&display_name=tag&style=flat&logo=github&logoColor=989da4&label=latest%20release&labelColor=161925&color=1c7293)](https://github.com/xero/leviathan-crypto/releases/latest) [![npm package minimized gzipped size](https://img.shields.io/bundlejs/size/leviathan-crypto?format=both&style=flat&logo=googlecontaineroptimizedos&logoColor=989da4&label=package%20size&labelColor=161925&color=1c7293)](https://www.npmjs.com/package/leviathan-crypto) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/xero/leviathan-crypto/test-suite.yml?branch=main&style=flat&logo=github&logoColor=989da4&label=test%20suite&labelColor=161925&color=1a936f)](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/xero/leviathan-crypto/wiki.yml?branch=main&style=flat&logo=gitbook&logoColor=989da4&label=wiki%20publish&labelColor=161925&color=1a936f)](https://github.com/xero/leviathan-crypto/wiki)

![simd webassembly](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-wasm-simd.svg) ![side-effect free](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-side-effect-free.svg) ![tree-shakeable](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-tree-shakable.svg) ![zero dependencies](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-zero-dependancies.svg) [![MIT Licensed](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-mit-license.svg)](https://github.com/xero/leviathan-crypto/blob/main/LICENSE)

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400" >

# Leviathan-Crypto: a strictly-typed webassembly cryptography library

**JS is the problem, SIMD WASM is the solution.** JavaScript engines offer no formal constant-time guarantees. JIT compilers optimize based on runtime patterns, which leak secrets through cache access and instruction timing. By contrast, WebAssembly executes entirely outside the JIT, running compiled bytecode with user-controlled linear memory. This guarantees consistent instruction execution, free from speculative optimization or value-dependent branches.

**WebAssembly is the correctness layer.** All algorithm logic resides in WASM. Six AssemblyScript modules (`serpent`, `chacha20`, `sha2`, `sha3`, `kyber`, and `ct`) compile independently to WASM, leveraging SIMD where beneficial. Each operates as its own instance with its own linear memory. Within each module, stateful primitives share the instance, and a runtime exclusivity model prevents mutual interference.

**TypeScript is the ergonomics layer.** The strongly-typed public API covers [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal), [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream), [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool), [`Fortuna`](https://github.com/xero/leviathan-crypto/wiki/fortuna), [`HKDF`](https://github.com/xero/leviathan-crypto/wiki/sha2#hkdf_sha256), [`SkippedKeyStore`](https://github.com/xero/leviathan-crypto/wiki/ratchet#skippedkeystore), and other components. Its design is misuse-resistant by default, incorporating features such as verify-then-decrypt authentication, key material wiping on dispose, validation before any cryptographic path, and one-shot AEADs that lock on first call. TypeScript never implements cryptographic algorithms; instead, it orchestrates the WASM layer and enforces best practices through API shape, rather than mere convention.

_**The paranoia of Serpent-256 and the elegance of XChaCha20-Poly1305.**_

**[Serpent-256](https://github.com/xero/leviathan-crypto/wiki/serpent_reference)** employs thirty-two round S-boxes implemented using pure Boolean logic gates, avoiding table lookups. Designed without compromise, it processes every bit for each block.

**[XChaCha20-Poly1305](https://github.com/xero/leviathan-crypto/wiki/chacha_reference)** features twenty rounds of add-rotate-XOR, precisely choreographed to use no S-boxes and prevent cache-timing leakage. Poly1305 adds an unconditional forgery bound.

Cipher choice is pluggable. Both ciphers share the same [`CipherSuite`](https://github.com/xero/leviathan-crypto/wiki/ciphersuite) interface, allowing them to integrate interchangeably into [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal), [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream), and [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool) interchangeably. This modularity extends to post-quantum coverage: [`KyberSuite`](https://github.com/xero/leviathan-crypto/wiki/ciphersuite#kybersuite) integrates ML-KEM-512, ML-KEM-768, or ML-KEM-1024 with any cipher suite, and the [SPQR ratchet](https://github.com/xero/leviathan-crypto/wiki/ratchet) builds forward-secret sessions on top.

**Zero dependencies.** No npm graph to audit means no supply chain attack surface.

**Tree-shakeable.** Import only what you use. Subpath exports let bundlers exclude everything else.

**Side-effect free.** Nothing runs on import. [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) is explicit and asynchronous.

**Audited primitives.** Every implementation is [verified against its specification](https://github.com/xero/leviathan-crypto/wiki/audits).

---

## Installation

```bash
# use bun
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

> [!NOTE]
> [Serpent](https://github.com/xero/leviathan-crypto/wiki/serpent), [ChaCha20](https://github.com/xero/leviathan-crypto/wiki/chacha20), [ML-KEM](https://github.com/xero/leviathan-crypto/wiki/kyber.md), and [constantTimeEqual](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal) require WebAssembly SIMD support. This has been a baseline feature of all major browsers and runtimes [since 2021](https://caniuse.com/wasm-simd). SHA-2 and SHA-3 run on any WASM-capable runtime.

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
| `leviathan-crypto/ratchet`           | `./dist/ratchet/index.js`      |

See [loader.md](https://github.com/xero/leviathan-crypto/wiki/loader) for the full WASM loading reference.

---

## Quick Start

**_One-shot authenticated encryption._** [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal) handles nonces, key derivation, and authentication. Zero config beyond [`init()`](https://github.com/xero/leviathan-crypto/wiki/init#init).

```typescript
import { init, Seal, XChaCha20Cipher } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, sha2: sha2Wasm })

const key  = XChaCha20Cipher.keygen()
const blob = Seal.encrypt(XChaCha20Cipher, key, plaintext)
const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)  // throws AuthenticationError on tamper
```

**_Prefer Serpent-256?_** Swap the cipher object and everything else stays the same.

```typescript
import { init, Seal, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)
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

**_Building a secure messenger?_** The [ratchet module](https://github.com/xero/leviathan-crypto/wiki/ratchet) provides Double-Ratchet primitives with post-quantum KEM steps for consumers who need forward-secrecy and post-compromise security at the session layer. [`ratchetInit`](https://github.com/xero/leviathan-crypto/wiki/ratchet#ratchetinit) bootstraps the symmetric chains, [`KDFChain`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kdfchain) derives per-message keys, [`kemRatchetEncap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetencap) / [`kemRatchetDecap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetdecap) perform the ML-KEM ratchet step, and [`SkippedKeyStore`](https://github.com/xero/leviathan-crypto/wiki/ratchet#skippedkeystore) handles out-of-order delivery.

```typescript
import { ratchetInit, KDFChain } from 'leviathan-crypto/ratchet'

await init({ sha2: sha2Wasm })   // KDF layer only; add kyber + sha3 for KEM steps

const { nextRootKey, sendChainKey, recvChainKey } = ratchetInit(sharedSecret)
const chain = new KDFChain(sendChainKey)
const { key: messageKey, counter } = chain.stepWithCounter()
// encrypt a message with messageKey; include counter in the wire header
```

These are the primitives, not a full session. You compose them into your transport, header format, and epoch orchestration. See the [ratchet guide](https://github.com/xero/leviathan-crypto/wiki/ratchet) for the full construction.

**_Looking for more examples including hashing, key derivation, Fortuna, and raw primitives?_** See the [examples page](https://github.com/xero/leviathan-crypto/wiki/examples).

---

## Demos

**`web`** [ [demo](https://leviathan.3xi.club/web) · [source](https://github.com/xero/leviathan-demos/tree/main/web) · [readme](https://github.com/xero/leviathan-demos/blob/main/web/README.md) ]

A self-contained browser encryption tool in a single HTML file. Encrypt text or
files with Serpent-256-CBC and Argon2id key derivation, then share the armored
output. No server, no install, no network connection after initial load. The
code is written to be read. The Encrypt-then-MAC construction, HMAC input, and
Argon2id parameters are all intentional examples worth studying.

**`chat`** [ [demo](https://leviathan.3xi.club/chat) · [source](https://github.com/xero/leviathan-demos/tree/main/chat) · [readme](https://github.com/xero/leviathan-demos/blob/main/chat/README.md) ]

End-to-end encrypted chat over X25519 key exchange and XChaCha20-Poly1305
message encryption. The relay server is a dumb WebSocket pipe that never sees
plaintext. Messages carry sequence numbers so the protocol detects and rejects
replayed messages. The demo deconstructs the protocol step by step with visual
feedback for injection and replay attacks.

**`cli`** [ [npm](https://www.npmjs.com/package/lvthn) · [source](https://github.com/xero/leviathan-demos/tree/main/cli) · [readme](https://github.com/xero/leviathan-demos/blob/main/cli/README.md) ]

Command-line file encryption tool supporting both Serpent-256 and
XChaCha20-Poly1305 via `--cipher`. A single keyfile works with both ciphers.
The header byte determines decryption automatically. Chunks distribute across a
worker pool sized to `hardwareConcurrency`. Each worker owns an isolated WASM
instance with no shared memory. The tool can export its own interactive
completions for a variety of shells.

```sh
bun add -g lvthn
lvthn keygen --armor -o my.key
cat secret.txt | lvthn encrypt -k my.key --armor > secret.enc
```

**`kyber`** [ [demo](https://leviathan.3xi.club/kyber) · [source](https://github.com/xero/leviathan-demos/tree/main/kyber) · [readme](https://github.com/xero/leviathan-demos/blob/main/kyber/README.md) ]

Post-quantum cryptography demo simulating a complete ML-KEM key encapsulation
ceremony between two browser-side clients. A live wire at the top of the page
logs every value that crosses the channel; importantly, the shared secret never
appears in the wire. After the ceremony completes, both sides independently
derive a symmetric key using HKDF-SHA256 and exchange messages encrypted with
XChaCha20-Poly1305. Each wire frame is expandable, revealing the raw nonce,
ciphertext, Poly1305 tag, and AAD.

**`COVCOM`** [ [demo](https://leviathan.3xi.club/covcom) · [source](https://github.com/xero/covcom/) · [readme](https://github.com/xero/covcom/blob/master/README.m) ]

A covert communications application for end-to-end encrypted group
conversations. Share an invite, talk, exit, and it's gone. Clients available for
both the web and cli, along with a containerized dumb server for managing
rooms. No secrets or cleartext beyond the handle you chose to join a room with
are ever visible to the server. Featuring sparse post-quantum ratcheting,
ML-KEM-768, KDFChains, Seal+KyberSuite, and a XChaCha20-Poly1305 core.

---

## Highlights

| **_I want to..._** | |
|---|---|
| Encrypt data | [`Seal`](https://github.com/xero/leviathan-crypto/wiki/aead#seal) with [`SerpentCipher`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentcipher) or [`XChaCha20Cipher`](https://github.com/xero/leviathan-crypto/wiki/chacha20#xchacha20cipher) |
| Encrypt a stream or large file | [`SealStream`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstream) to encrypt, [`OpenStream`](https://github.com/xero/leviathan-crypto/wiki/aead#openstream) to decrypt |
| Encrypt in parallel | [`SealStreamPool`](https://github.com/xero/leviathan-crypto/wiki/aead#sealstreampool) distributes chunks across Web Workers |
| Add post-quantum security | [`KyberSuite`](https://github.com/xero/leviathan-crypto/wiki/kyber#kybersuite) wraps [`MlKem512`](https://github.com/xero/leviathan-crypto/wiki/kyber#parameter-sets), [`MlKem768`](https://github.com/xero/leviathan-crypto/wiki/kyber#parameter-sets), or [`MlKem1024`](https://github.com/xero/leviathan-crypto/wiki/kyber#parameter-sets) with any cipher suite |
| Build a forward-secret session | [`ratchetInit`](https://github.com/xero/leviathan-crypto/wiki/ratchet#ratchetinit), [`KDFChain`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kdfchain), [`kemRatchetEncap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetencap) / [`kemRatchetDecap`](https://github.com/xero/leviathan-crypto/wiki/ratchet#kemratchetdecap), [`SkippedKeyStore`](https://github.com/xero/leviathan-crypto/wiki/ratchet#skippedkeystore) |
| Hash data | [`SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2#sha256), [`SHA384`](https://github.com/xero/leviathan-crypto/wiki/sha2#sha384), [`SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2#sha512), [`SHA3_256`](https://github.com/xero/leviathan-crypto/wiki/sha3#sha3_256), [`SHA3_512`](https://github.com/xero/leviathan-crypto/wiki/sha3#sha3_512), [`SHAKE256`](https://github.com/xero/leviathan-crypto/wiki/sha3#shake256) ... |
| Authenticate a message | [`HMAC_SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2#hmac_sha256), [`HMAC_SHA384`](https://github.com/xero/leviathan-crypto/wiki/sha2#hmac_sha384), or [`HMAC_SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2#hmac_sha512) |
| Derive keys | [`HKDF_SHA256`](https://github.com/xero/leviathan-crypto/wiki/sha2#hkdf_sha256) or [`HKDF_SHA512`](https://github.com/xero/leviathan-crypto/wiki/sha2#hkdf_sha512) |
| Generate random bytes | [`Fortuna`](https://github.com/xero/leviathan-crypto/wiki/fortuna#api-reference) for forward-secret generation, [`randomBytes`](https://github.com/xero/leviathan-crypto/wiki/utils#randombytes) for one-off use |
| Compare secrets safely | [`constantTimeEqual`](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal) uses a WASM SIMD path to prevent timing attacks |
| Work with bytes | [`hexToBytes`](https://github.com/xero/leviathan-crypto/wiki/utils#hextobytes), [`bytesToHex`](https://github.com/xero/leviathan-crypto/wiki/utils#bytestohex), [`wipe`](https://github.com/xero/leviathan-crypto/wiki/utils#wipe), [`xor`](https://github.com/xero/leviathan-crypto/wiki/utils#xor), [`concat`](https://github.com/xero/leviathan-crypto/wiki/utils#concat) ... |

*For raw primitives, low-level cipher access, and ASM internals see the [full API reference](https://github.com/xero/leviathan-crypto/wiki/index).*

---

## Going deeper

|   |   |
|---|---|
| [Architecture](https://github.com/xero/leviathan-crypto/wiki/architecture) | Repository structure, module relationships, build pipeline, and buffer layouts |
| [Test Suite](https://github.com/xero/leviathan-crypto/wiki/test-suite) | How the test suite works, vector corpus, and gate discipline |
| [Security Policy](./SECURITY) | Security posture and vulnerability disclosure details |
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
