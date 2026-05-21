# leviathan-crypto: AI Assistant Guide

> [!NOTE]
> Ships with the npm package. Inside the repo? Read `AGENTS.md` at the
> repo root instead; this file is for consumers.

## What this is

Zero-dependency WASM crypto for TS/JS. All compute in WASM (outside JS
JIT); TS layer = input validation + ergonomics.

| Family | Primitives |
|---|---|
| Symmetric AEAD | Serpent-256, XChaCha20-Poly1305, AES-256-GCM-SIV |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, PQ-only hybrid composites |
| Forward-secret ratchet | Signal SPQR KDF layer (see rule #8) |

## API shape

Two parallel hierarchies sharing a suite extension point. Tier = data
shape. Suite = crypto choice. Axes are orthogonal.

| Tier | AEAD | Signatures |
|---|---|---|
| One-shot | `Seal` | `Sign` |
| Streaming | `SealStream` / `OpenStream` | `SignStream` / `VerifyStream` |
| Parallel | `SealStreamPool` (Web Workers) | n/a |
| Suite arg | `CipherSuite` | `SignatureSuite` |

`Seal` blob = single-chunk `SealStream` output (interchangeable).
Symmetric suites: `SerpentCipher`, `XChaCha20Cipher`, `AESGCMSIVCipher`.
`KyberSuite(MlKem*, inner)` wraps any of them for hybrid PQ (same
`CipherSuite` interface). ML-DSA, SLH-DSA, prehash variants, PQ-only
hybrid composites slot into the signature tier unchanged.

**Prefer the high-level surface (`Seal` / `Sign` / `Fortuna`).** Handles
KDF, nonce management, auth, key wipes, counter binding. Rejects
tampered/reordered/spliced inputs before plaintext release. Low-level
primitives (`SerpentCbc`, raw `ChaCha20`, etc.) require reading the
relevant `docs/<feature>.md` Security Notes first.

## Rules (cross-cutting foot-guns)

Primitive-specific gotchas (`SerpentCbc` arg order, KMAC empty key,
FIPS 205 §10.2.2 category restrictions, etc.) live in per-feature docs.

1. **`init()` required.** Nothing works before `init()`. Throws on
   missing module. Use `/embedded` subpath for bundled gzip+base64 blob.
   Idempotent.
2. **`dispose()` stateful in `finally`.** Stateful classes hold key
   material in WASM until `dispose()` zeroes it. Wrap in
   `try { ... } finally { x.dispose() }`. Atomic one-shots
   (`Seal.encrypt`, `Sign.sign`, hashes, MACs) self-wipe; no dispose.
3. **Stateful = exclusive module access.** A stateful class
   (`SHAKE128`, `ChaCha20`, `SerpentCtr/Cbc`, `SealStream`, etc.) owns
   its WASM module for its lifetime. Second stateful instance on same
   module throws. Atomic methods on same module throw while a stateful
   holder is alive. Pool workers isolated (own WASM each).
4. **AEAD `decrypt()` always throws on auth failure.** `Seal.decrypt`,
   AEAD `decrypt()`, `OpenStream.pull` never return null or corrupted
   plaintext. Wrong key, tampered blob, corrupted bytes all surface as
   exceptions.
5. **Raw `verify()` returns `bool`, never throws on bad sig.**
   `MlDsa*.verify`, `SlhDsa*.verify`, hybrid `verifyPrehashed` return
   `false` on bad sig. Only contract violations (`ctx.length > 255`,
   unsupported pre-hash, category mismatch) throw. **Discriminator:**
   `Sign.verify` envelope _throws_ on bad sig (parity with
   `Seal.decrypt`); raw primitives return bool.

   ```typescript
   if (!dsa.verify(vk, M, sig, ctx)) throw new Error('signature invalid')
   ```
6. **Pure-mode and prehash sigs NOT interchangeable.** `dsa.sign` vs
   `dsa.verifyHash` bind different M' domain bytes (0x00 vs 0x01,
   FIPS 204 §3.6.4 / FIPS 205 §10.2.2). Sigs don't cross even with
   identical messages. SignatureSuite enforces at type level (pure-mode
   and prehash suites type-incompatible at call site).
7. **v3 sign envelope: `ctx` is required.** `Sign.sign` / `Sign.verify`
   / `SignStream` / `VerifyStream` all require `ctx`. Pass
   `new Uint8Array()` for empty; suite layer doesn't default it. Each
   suite prepends `ctxDomain` (blocks cross-suite verify). Per-call
   `ctx` ≤ 255 bytes (FIPS 204 §3.6.1); longer throws
   `SigningError('sig-ctx-too-long')`. `effective_ctx` shares the
   255-byte cap → per-call ceiling = `253 - len(ctxDomain)` (221-234
   bytes across catalog).
8. **Ratchet exports = KDF primitives, not session.** `ratchetInit`,
   `KDFChain`, `kemRatchetEncap`, `kemRatchetDecap`, `SkippedKeyStore`,
   `RatchetKeypair` = KDF layer from Signal SPQR spec. Forward secrecy
   + post-compromise security primitives only. State machine, message
   counters, header format, epoch orchestration, transport = app
   concerns. Not a drop-in Signal client.

## Subpath imports

**Standard pattern.** `leviathan-crypto/<mod>` exports
`<mod>Init(source)`. `leviathan-crypto/<mod>/embedded` exports
`<mod>Wasm` (gzip+base64 blob). Twelve modules follow:
`serpent`, `chacha20`, `aes`, `sha2`, `sha3`, `keccak`, `kyber`,
`mldsa`, `slhdsa`, `blake3`, `curve25519`, `p256`.

**Aliases (share WASM binary + instance slot):**

| Alias | Backed by | Notes |
|---|---|---|
| `keccak` | `sha3` | identical binary; either `init` key resolves |
| `ed25519` | `curve25519` | own `ed25519Init` + `ed25519Wasm`; resolves to `curve25519` slot |
| `x25519` | `curve25519` | own `x25519Init` + `x25519Wasm`; same as `ed25519` |
| `ecdsa` | `p256` | subpath for `EcdsaP256`; init `ecdsaP256Init`; embedded exports `p256Wasm` + `ecdsaP256Wasm` |

**No `/embedded` companion:** `leviathan-crypto/ratchet` (KDF over
`sha2`+`kyber`+`sha3`); `leviathan-crypto/stream` (cipher-agnostic AEAD
entry, takes any `CipherSuite`).

## Working with primitives

Docs ship under `node_modules/leviathan-crypto/dist/docs/`. Every
`*Cipher` cipher suite also needs `ciphersuite.md`; every `*Suite`
signature type also needs `signaturesuite.md`, and signing through
`Sign` / `SignStream` / `VerifyStream` also needs `signing.md`.
Omitted from rows below.

| Working with | Required modules | Read first |
|---|---|---|
| `Seal` / `SealStream` / `OpenStream` / `SealStreamPool` | varies by suite | `aead.md`, `ciphersuite.md` |
| `SerpentCipher` | `serpent`, `sha2` | `serpent.md` |
| `XChaCha20Cipher` | `chacha20`, `sha2` | `chacha20.md` |
| `AESGCMSIVCipher` | `aes`, `sha2` | `aes.md` |
| `KyberSuite(MlKem*, inner)` | `kyber`, `sha3` + inner | `kyber.md` |
| `Serpent` / `SerpentCtr` / `SerpentCbc` (raw) | `serpent` | `serpent.md` |
| `AES` / `AESCbc` / `AESCtr` / `AESGCM` / `AESGCMSIV` / `AESGenerator` | `aes` | `aes.md` |
| `ChaCha20` / `Poly1305` / `ChaCha20Poly1305` / `XChaCha20Poly1305` | `chacha20` | `chacha20.md` |
| `SHA224/256/384/512`, `HMAC_SHA*`, `HKDF_SHA*` | `sha2` | `sha2.md` |
| `SHA3_*`, `SHAKE128/256` | `sha3` | `sha3.md` |
| `CSHAKE128/256`, `KMAC128/256`, `KMACXOF128/256` | `sha3` | `kmac.md` |
| `BLAKE3` family (+ streaming, `BLAKE3OutputReader`, `BLAKE3Hash`) | `blake3` | `blake3.md` |
| `MlKem512/768/1024` | `kyber`, `sha3` | `kyber.md` |
| `MlDsa44/65/87` (+HashML-DSA) | `mldsa`, `sha3` (+`sha2` for SHA-2 prehash) | `mldsa.md` |
| `SlhDsa128f/192f/256f` (+HashSLH-DSA) | `slhdsa` (+`sha3` prehash, +`sha2` SHA-2 prehash) | `slhdsa.md` |
| `Ed25519` (pure + Ed25519ph) | `curve25519` (+`sha2` for prehash) | `ed25519.md` |
| `X25519` | `curve25519` | `x25519.md` |
| `EcdsaP256` | `p256` | `ecdsa-p256.md` |
| `Ed25519Suite` / `Ed25519PreHashSuite` | `curve25519` (+`sha2` for PreHash) | `ed25519.md` |
| `EcdsaP256Suite` (hedged, low-S) | `p256`, `sha2` | `ecdsa-p256.md` |
| `ecdsaSignatureToDer` / `ecdsaSignatureFromDer` (X.509/JWS interop) | none (pure TS, RFC 3279 §2.2.3) | `ecdsa-p256.md` |
| `MlDsa{44,65}Ed25519Suite` (hybrid, fmt `0x20`/`0x21`) | `mldsa`, `sha3`, `curve25519`, `sha2` | `mldsa.md`, `ed25519.md` |
| `MlDsa{44,65}EcdsaP256Suite` (hybrid, fmt `0x22`/`0x23`) | `mldsa`, `sha3`, `p256`, `sha2` | `mldsa.md`, `ecdsa-p256.md` |
| `MlDsa44SlhDsa128fSuite` / `MlDsa65SlhDsa192fSuite` / `MlDsa87SlhDsa256fSuite` (PQ-only hybrid, fmt `0x30`/`0x31`/`0x32`) | `mldsa`, `sha3`, `slhdsa` | `mldsa.md`, `slhdsa.md` |
| `MerkleVerifier` / `MerkleLog` (transparency log + STH) | `sha2` always; +suite (`curve25519` for `Ed25519Suite`, `sha3`+`mldsa` for `MlDsa44Suite`); +`blake3` if `hashing: 'blake3'` | `merkle.md` |
| `Fortuna` (`await Fortuna.create({ generator, hash })`) | one cipher + one hash | `fortuna.md` |
| Sparse PQ Ratchet (KDF only, rule #8) | `sha2`, `kyber`, `sha3` | `ratchet.md` |
| Argon2id passphrase KDF | see doc | `argon2id.md` |
| Utilities (`hexToBytes`, `randomBytes`, `constantTimeEqual`, `wipe`, ...) | none | `utils.md` |

## Reference docs

| Topic | Doc |
|---|---|
| Full export catalog | `exports.md` |
| `init()` API, `WasmSource` types | `init.md` |
| Worked examples across the API | `examples.md` |
| TypeScript interfaces (`Hash`, `Blockcipher`, etc.) | `types.md` |
| Loading strategies (URL, ArrayBuffer, edge) | `loader.md` |
| Loading via CDN | `cdn.md` |

## Canonical example

`Seal` + `SerpentCipher` round-trip (init + high-level path):

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

Streaming: `Seal` → `SealStream` + `OpenStream`. PQ hybrid:
`SerpentCipher` → `KyberSuite(new MlKem768(), SerpentCipher)`. Same call
site, wire format, and catch semantics.
