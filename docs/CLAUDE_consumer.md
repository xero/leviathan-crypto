# leviathan-crypto: AI Assistant Guide

> [!NOTE]
> This file ships with the npm package to help AI assistants use this
> library correctly. If you are working **inside** the `leviathan-crypto`
> repository, stop reading this file and open `AGENTS.md` at the repo root
> — that is the contract for developing the library itself.

---

## What this library is

`leviathan-crypto` is a zero-dependency WASM cryptography library for
TypeScript and JavaScript. All cryptographic computation runs in
WebAssembly, outside the JavaScript JIT; the TypeScript layer is input
validation and ergonomics only. Ships three symmetric ciphers
(Serpent-256, XChaCha20-Poly1305, AES-256-GCM-SIV), three post-quantum
families (ML-KEM, ML-DSA, SLH-DSA + PQ-only hybrids), and a forward-secret
ratchet from Signal's SPQR.

---

## How the API is organized

Two parallel hierarchies, both built on a suite extension point:

**AEAD.** `Seal` (one-shot) → `SealStream` + `OpenStream` (streaming) →
`SealStreamPool` (parallel via Web Workers). All four take a `CipherSuite`
at construction and share one wire format — a `Seal` blob is structurally
a single-chunk `SealStream` output, and `OpenStream` decrypts it
interchangeably. Three symmetric suites ship: `SerpentCipher`,
`XChaCha20Cipher`, `AESGCMSIVCipher`. `KyberSuite` is a fourth, wrapping
any of them with ML-KEM for hybrid PQ encryption — same `CipherSuite`
interface, no change to the consuming API.

**Signatures.** `Sign` (one-shot) → `SignStream` + `VerifyStream`
(streaming). Both take a `SignatureSuite`. ML-DSA, SLH-DSA, prehash
variants, and PQ-only hybrid composites all slot in unchanged.

Pick the tier by data shape, pick the suite by cryptographic choice — the
axes are orthogonal. **Prefer the high-level surface
(`Seal`/`Sign`/`Fortuna`)** — it handles key derivation, nonce management,
authentication, key wipes, counter-binding, and rejects tampered,
reordered, or spliced inputs before plaintext is released. The lower-level
primitives (`SerpentCbc`, raw `ChaCha20`, etc.) require reading the
relevant `docs/<feature>.md` Security Notes section first.

---

## Critical foot-guns

Cross-cutting gotchas. Primitive-specific ones (SerpentCbc arg order, KMAC
empty key, FIPS 205 §10.2.2 category restrictions, etc.) live in the
per-feature docs.

### 1. `init()` is required

No class works before `init()` is called. The call throws clearly when a
needed module is missing. Use the `/embedded` subpath of each module for
the bundled gzip+base64 blob. `init()` is idempotent — safe to call from
multiple entry points.

### 2. `dispose()` in `finally`

Every stateful class holds key material in WASM memory until `dispose()`
zeroes it. Wrap stateful use in `try { ... } finally { x.dispose() }`.
Atomic one-shot APIs (`Seal.encrypt`, `Sign.sign`, `SHA256.hash`,
`HMAC_SHA256.hash`, `Poly1305.mac`, etc.) wipe internally; no explicit
dispose needed.

### 3. Stateful classes hold exclusive module access

A stateful class (`SHAKE128`, `ChaCha20`, `SerpentCtr`, `SerpentCbc`,
`SealStream`, etc.) holds exclusive access to its WASM module for its
lifetime. Constructing a second stateful instance on the same module
throws. Atomic methods on the same module also throw while a stateful
holder is alive. Pool workers are unaffected — each has its own WASM
instance.

### 4. AEAD `decrypt()` throws on auth failure — never returns null

All `Seal.decrypt`, AEAD `decrypt()`, and `OpenStream.pull` paths throw on
authentication failure. They do not return null and never return corrupted
plaintext. Wrap calls in try/catch — wrong key, tampered blob, and
corrupted bytes all surface as exceptions.

### 5. Signature `verify()` returns a boolean — never throws on bad sig

For raw `MlDsa*.verify` / `SlhDsa*.verify` / hybrid `verifyPrehashed`, a
bad signature returns `false`. It does not throw. Branching on "did
`verify` complete without throwing" is a bug — bad sigs complete too.

```typescript
if (!dsa.verify(vk, M, sig, ctx)) throw new Error('signature invalid')
```

Only contract violations (`ctx.length > 255`, unsupported pre-hash,
category mismatch) throw. **Discriminator:** the higher-level `Sign.verify`
envelope *does* throw on failure for parity with `Seal.decrypt`. Raw
primitives are boolean; `Sign.verify` is throw.

### 6. Pure-mode and prehash signatures are NOT interchangeable

A signature produced by `dsa.sign` will not verify under `dsa.verifyHash`
on the same key, and vice versa — even with identical message bytes. The
M' construction binds a different domain-separator byte (0x00 vs 0x01,
FIPS 204 §3.6.4 / FIPS 205 §10.2.2) to prevent cross-protocol forgery.
Choose one mode per protocol and stay consistent. The same wall holds at
the SignatureSuite layer: pure-mode and prehash suites are
type-incompatible at the call site, by design.

### 7. v3 sign envelope: `ctx` is required, never optional

Every `Sign.sign` / `Sign.verify` / `SignStream` / `VerifyStream` takes
`ctx` as a required argument. Pass `new Uint8Array()` for the empty case;
the suite layer does not default it. Each suite has a built-in `ctxDomain`
prefix that prevents one suite's signature from verifying under another
even with identical inputs. Per-call `ctx` ≤ 200 bytes; longer throws
`SigningError('sig-ctx-too-long')`.

### 8. Ratchet exports are KDF primitives, not a session protocol

`ratchetInit`, `KDFChain`, `kemRatchetEncap`, `kemRatchetDecap`,
`SkippedKeyStore`, and `RatchetKeypair` are the KDF layer from Signal's
Sparse Post-Quantum Ratchet spec. They provide forward secrecy and
post-compromise security primitives, not a full session. State machines,
message counters, header format, epoch orchestration, and transport are
application concerns. If you arrived expecting a drop-in Signal client,
this is not it.

---

## Subpath imports

The eight primitive modules each have a subpath `leviathan-crypto/<mod>`
with init function `<mod>Init(source)` and an embedded blob at
`<mod>/embedded` (exported as `<mod>Wasm`). The modules: `serpent`,
`chacha20`, `aes`, `sha2`, `sha3`, `keccak`, `kyber`, `mldsa`. `keccak`
is an alias for `sha3` — same WASM binary, same instance slot.

Two subpaths have no `/embedded` companion:
`leviathan-crypto/ratchet` (KDF over sha2 + kyber + sha3) and
`leviathan-crypto/stream` (cipher-agnostic AEAD layer entry, takes a
`CipherSuite` from one of the primitive modules).

---

## Working with primitives

Read the cited doc before non-trivial work. Files ship under
`node_modules/leviathan-crypto/dist/docs/`.

| Working with | Required modules | Read first |
|---|---|---|
| `Seal` / `SealStream` / `OpenStream` / `SealStreamPool` | varies by suite | `aead.md`, `ciphersuite.md` |
| `SerpentCipher` | `serpent`, `sha2` | `ciphersuite.md`, `serpent.md` |
| `XChaCha20Cipher` | `chacha20`, `sha2` | `ciphersuite.md`, `chacha20.md` |
| `AESGCMSIVCipher` | `aes`, `sha2` | `ciphersuite.md`, `aes.md` |
| `KyberSuite(MlKem*, inner)` | `kyber`, `sha3` + inner | `ciphersuite.md`, `kyber.md` |
| `Serpent` / `SerpentCtr` / `SerpentCbc` (raw) | `serpent` | `serpent.md` |
| `AES` / `AESCbc` / `AESCtr` / `AESGCM` / `AESGCMSIV` / `AESGenerator` | `aes` | `aes.md` |
| `ChaCha20` / `Poly1305` / `ChaCha20Poly1305` / `XChaCha20Poly1305` | `chacha20` | `chacha20.md` |
| `SHA224/256/384/512`, `HMAC_SHA*`, `HKDF_SHA*` | `sha2` | `sha2.md` |
| `SHA3_*`, `SHAKE128/256` | `sha3` | `sha3.md` |
| `CSHAKE128/256`, `KMAC128/256`, `KMACXOF128/256` | `sha3` | `kmac.md` |
| `MlKem512/768/1024` | `kyber`, `sha3` | `kyber.md` |
| `MlDsa44/65/87` (+HashML-DSA) | `mldsa`, `sha3` (+`sha2` SHA-2 prehash) | `mldsa.md` |
| `SlhDsa128f/192f/256f` (+HashSLH-DSA) | `slhdsa` (+`sha3` prehash, +`sha2` SHA-2 prehash) | `slhdsa.md` |
| `Sign` / `SignStream` / `VerifyStream` + `*Suite` consts | varies | `signaturesuite.md` |
| `Fortuna` — use `await Fortuna.create({ generator, hash })` | one cipher + one hash | `fortuna.md` |
| Sparse PQ Ratchet (KDF only, see foot-gun #8) | `sha2`, `kyber`, `sha3` | `ratchet.md` |
| Argon2id passphrase KDF | see doc | `argon2id.md` |
| Utilities (`hexToBytes`, `randomBytes`, `constantTimeEqual`, `wipe`, ...) | none | `utils.md` |

---

## Reference docs

| Topic | Doc |
|---|---|
| Full export catalog | `exports.md` |
| `init()` API, `WasmSource` types | `init.md` |
| Worked examples across the API | `examples.md` |
| TypeScript interfaces (`Hash`, `Blockcipher`, etc.) | `types.md` |
| Loading strategies (URL, ArrayBuffer, edge) | `loader.md` |
| Loading via CDN | `cdn.md` |

---

## Canonical example

`Seal` + `SerpentCipher` round-trip — init, recommended high-level path,
throw-on-failure decrypt:

```typescript
import { init, Seal, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)

try {
  const plaintext = Seal.decrypt(SerpentCipher, key, blob)
} catch {
  // wrong key, tampered blob, or corrupted bytes
}
```

Streaming: swap `Seal` for `SealStream` + `OpenStream`. PQ hybrid: swap
`SerpentCipher` for `KyberSuite(new MlKem768(), SerpentCipher)`. Same call
site, same wire format, same catch semantics.
