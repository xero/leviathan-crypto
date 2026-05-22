# leviathan-crypto: AI Assistant Guide

> [!NOTE]
> Ships with the npm package. Inside the repo? Read `AGENTS.md` instead.

## What this is

Zero-dependency WASM crypto for TS/JS. All compute in WASM (outside JS JIT); TS layer = input validation + ergonomics.

| Family | Primitives |
|---|---|
| Symmetric AEAD | Serpent-256, XChaCha20-Poly1305, AES-256-GCM-SIV |
| Post-quantum sig | ML-DSA, SLH-DSA, PQ-only hybrid composites |
| Classical sig | Ed25519, ECDSA-P256, classical+PQ hybrid composites |
| Key agreement | ML-KEM, X25519 |
| Transparency log | Merkle log (C2SP-conformant) |
| Forward-secret ratchet | Signal SPQR KDF (rule 8) |

## API shape

Two hierarchies, one suite extension point. Tier = data shape. Suite = crypto choice.

| Tier | AEAD | Signatures |
|---|---|---|
| One-shot | Seal | Sign |
| Streaming | SealStream / OpenStream | SignStream / VerifyStream |
| Parallel | SealStreamPool (Web Workers) | n/a |
| Suite arg | CipherSuite | SignatureSuite |

`Seal` blob = single-chunk `SealStream` output (interchangeable). Symmetric: `SerpentCipher`, `XChaCha20Cipher`, `AESGCMSIVCipher`. `KyberSuite(MlKem*, inner)` wraps any of them for PQ hybrid (same `CipherSuite` interface).

**Prefer the high-level surface (Seal / Sign / Fortuna).** Handles KDF, nonce management, auth, key wipes, counter binding. Rejects tampered/reordered/spliced inputs before plaintext release. Low-level primitives (raw `ChaCha20`, `SerpentCbc`, etc.) require reading their wiki page first.

## Rules (cross-cutting foot-guns)

1. **`init()` required.** Nothing works before `init()`. Throws on missing module. Idempotent. Use `/embedded` subpath for bundled gzip+base64 blob.

2. **`dispose()` stateful in `finally`.** Stateful classes hold key material in WASM until `dispose()` zeros it. Wrap in `try { ... } finally { x.dispose() }`. Atomic one-shots (`Seal.encrypt`, `Sign.sign`, hashes, MACs) self-wipe.

3. **Stateful = exclusive module access.** A stateful class (`SHAKE128`, `ChaCha20`, `SerpentCtr/Cbc`, `SealStream`, `MlKem*`, etc.) owns its WASM module for its lifetime. Second stateful instance on same module throws. Atomic methods on same module throw while a stateful holder is alive. Pool workers isolated.

4. **AEAD `decrypt()` throws on auth failure.** `Seal.decrypt`, AEAD `decrypt()`, `OpenStream.pull` never return null or corrupted plaintext. Wrong key, tampered blob, corrupted bytes all surface as exceptions.

5. **Raw `verify()` returns bool. `Sign.verify` throws.** Raw primitives (`MlDsa*.verify`, `SlhDsa*.verify`, hybrid `verifyPrehashed`) return `false` on bad sig; only contract violations throw. `Sign.verify` envelope throws on bad sig (parity with `Seal.decrypt`).

6. **Pure-mode and prehash sigs NOT interchangeable.** `dsa.sign` vs `dsa.verifyHash` bind different M' domain bytes (0x00 vs 0x01, FIPS 204 §3.6.4 / FIPS 205 §10.2.2). Sigs don't cross even with identical messages. SignatureSuite enforces at the type level.

7. **v3 sign envelope: `ctx` required.** `Sign.sign` / `Sign.verify` / `SignStream` / `VerifyStream` all require `ctx`. Pass `new Uint8Array()` for empty. Each suite prepends `ctxDomain` (blocks cross-suite verify). Per-call `ctx` ≤ 255 bytes (FIPS 204 §3.6.1); longer throws `SigningError('sig-ctx-too-long')`. Per-call ceiling = `253 - len(ctxDomain)` (221-234 bytes across catalog).

8. **Ratchet = KDF primitives, not a session.** Forward secrecy + post-compromise security primitives only. State machine, message counters, header format, epoch orchestration, transport = app concerns. NOT a drop-in Signal client.

## Subpath imports

Pattern: `leviathan-crypto/<mod>` exports `<mod>Init(source)`; `leviathan-crypto/<mod>/embedded` exports `<mod>Wasm`. Twelve modules: `serpent`, `chacha20`, `aes`, `sha2`, `sha3`, `keccak`, `kyber`, `mldsa`, `slhdsa`, `blake3`, `curve25519`, `p256`.

Aliases share binary + instance slot:

| Alias | Backed by |
|---|---|
| keccak | sha3 |
| ed25519 | curve25519 |
| x25519 | curve25519 |
| ecdsa | p256 |

No `/embedded`: `leviathan-crypto/ratchet`, `leviathan-crypto/stream`, `leviathan-crypto/sign`, `leviathan-crypto/merkle`.

## Class → init modules + wiki

| Class | init modules | wiki |
|---|---|---|
| Seal / SealStream / OpenStream / SealStreamPool | varies by suite | https://github.com/xero/leviathan-crypto/wiki/aead |
| SerpentCipher | serpent, sha2 | https://github.com/xero/leviathan-crypto/wiki/serpent |
| XChaCha20Cipher | chacha20, sha2 | https://github.com/xero/leviathan-crypto/wiki/chacha20 |
| AESGCMSIVCipher | aes, sha2 | https://github.com/xero/leviathan-crypto/wiki/aes |
| KyberSuite(MlKem*, inner) | kyber, sha3 + inner | https://github.com/xero/leviathan-crypto/wiki/kyber |
| Sign / SignStream / VerifyStream | varies by suite | https://github.com/xero/leviathan-crypto/wiki/signing |
| MlDsa{44,65,87}Suite (pure, prehash) | mldsa, sha3 (+sha2 for SHA-2 prehash) | https://github.com/xero/leviathan-crypto/wiki/mldsa |
| SlhDsa{128f,192f,256f}Suite | slhdsa, sha3 (+sha2 for SHA-2 prehash) | https://github.com/xero/leviathan-crypto/wiki/slhdsa |
| Ed25519Suite / Ed25519PreHashSuite | curve25519 (+sha2 for PreHash) | https://github.com/xero/leviathan-crypto/wiki/ed25519 |
| EcdsaP256Suite (hedged, low-S) | p256, sha2 | https://github.com/xero/leviathan-crypto/wiki/ecdsa-p256 |
| MlDsa{44,65}Ed25519Suite (0x20, 0x21) | mldsa, sha3, curve25519, sha2 | https://github.com/xero/leviathan-crypto/wiki/signaturesuite |
| MlDsa{44,65}EcdsaP256Suite (0x22, 0x23) | mldsa, sha3, p256, sha2 | https://github.com/xero/leviathan-crypto/wiki/signaturesuite |
| MlDsa{44,65,87}SlhDsa{128f,192f,256f}Suite (0x30-0x32) | mldsa, sha3, slhdsa | https://github.com/xero/leviathan-crypto/wiki/signaturesuite |
| X25519 | curve25519 | https://github.com/xero/leviathan-crypto/wiki/x25519 |
| MerkleVerifier / MerkleLog | sha2 + suite (+blake3 if `hashing: 'blake3'`) | https://github.com/xero/leviathan-crypto/wiki/merkle |
| Sparse PQ Ratchet (KDF, rule 8) | sha2, kyber, sha3 | https://github.com/xero/leviathan-crypto/wiki/ratchet |
| Fortuna | one cipher + one hash | https://github.com/xero/leviathan-crypto/wiki/fortuna |
| SHA-2 / HMAC / HKDF | sha2 | https://github.com/xero/leviathan-crypto/wiki/sha2 |
| SHA-3 / SHAKE | sha3 | https://github.com/xero/leviathan-crypto/wiki/sha3 |
| CSHAKE / KMAC / KMACXOF | sha3 | https://github.com/xero/leviathan-crypto/wiki/kmac |
| BLAKE3 family | blake3 | https://github.com/xero/leviathan-crypto/wiki/blake3 |

Other refs:

| Topic | wiki |
|---|---|
| init() / WasmSource | https://github.com/xero/leviathan-crypto/wiki/init |
| Loading strategies | https://github.com/xero/leviathan-crypto/wiki/loader |
| CDN usage | https://github.com/xero/leviathan-crypto/wiki/cdn |
| Worked examples | https://github.com/xero/leviathan-crypto/wiki/examples |
| Utilities | https://github.com/xero/leviathan-crypto/wiki/utils |
| Argon2id integration | https://github.com/xero/leviathan-crypto/wiki/argon2id |
| CipherSuite interface | https://github.com/xero/leviathan-crypto/wiki/ciphersuite |
| SignatureSuite catalog | https://github.com/xero/leviathan-crypto/wiki/signaturesuite |

## Canonical example

`Seal` + `SerpentCipher` round-trip:

```typescript
import { init, Seal, SerpentCipher } from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const key  = SerpentCipher.keygen()
const blob = Seal.encrypt(SerpentCipher, key, plaintext)
try {
  const pt = Seal.decrypt(SerpentCipher, key, blob)
} catch {
  // wrong key, tampered blob, or corrupted bytes
}
```

Streaming: `Seal` → `SealStream` + `OpenStream`. PQ hybrid: `SerpentCipher` → `KyberSuite(new MlKem768(), SerpentCipher)`. Same call site, wire format, catch semantics.
