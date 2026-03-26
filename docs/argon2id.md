# Argon2id: Memory-Hardened Password Hashing and Key Derivation

> [!NOTE]
> leviathan-crypto does not wrap Argon2id. This document covers how to use the
> [`argon2id`](https://www.npmjs.com/package/argon2id) npm package directly and
> how to pair it with leviathan primitives for passphrase-based encryption.

## Why Argon2id

Password hashing is the last line of defense when a database is breached. If an
attacker obtains hashed passwords, the hash function determines how expensive it
is to recover each plaintext. Traditional hash functions — even iterated ones
like PBKDF2 — are fast on GPUs and custom hardware. An attacker with a few
thousand dollars of GPU hardware can test billions of PBKDF2-SHA256 candidates
per second. bcrypt improves on this with a 4 KiB memory requirement that limits
GPU parallelism, but 4 KiB is trivial by modern standards.

Argon2 was the winner of the Password Hashing Competition (PHC, 2013–2015),
selected from 24 submissions after two years of public analysis. It was designed
specifically to be **memory-hard**, computing the hash requires not just CPU
time but a large block of RAM that cannot be traded away. An attacker who tries
to use less memory must perform exponentially more computation, making GPU and
ASIC attacks economically impractical.

Argon2id is the recommended variant (RFC 9106): it uses Argon2i for the first
pass (resisting side-channel attacks) and Argon2d for subsequent passes
(resisting GPU attacks). It is the only Argon2 variant you should use for new
applications.

---

## Installation

```sh
npm i argon2id
```

The compiled WASM binaries are included. SIMD acceleration is used automatically
where available (all modern browsers and Node ≥ 18), with a scalar fallback for
environments that do not support it. Both produce identical output.

---

## Basic usage

With a bundler (Rollup, Webpack, Vite):

```typescript
import loadArgon2idWasm from 'argon2id';

const argon2id = await loadArgon2idWasm();

const hash = argon2id({
  password: new TextEncoder().encode('hunter2'),
  salt:     crypto.getRandomValues(new Uint8Array(16)),
  passes:   2,
  memorySize: 19456,  // KiB
  parallelism: 1,
  tagLength: 32,
});
// hash is a Uint8Array
```

Without a bundler (Node, or browsers using `setupWasm` directly):

```typescript
import setupWasm from 'argon2id/lib/setup.js';
import { readFileSync } from 'fs';

const argon2id = await setupWasm(
  importObj => WebAssembly.instantiate(readFileSync('node_modules/argon2id/dist/simd.wasm'), importObj),
  importObj => WebAssembly.instantiate(readFileSync('node_modules/argon2id/dist/no-simd.wasm'), importObj),
);
```

The hash function signature is the same either way.

---

## Parameter presets

These align with OWASP and RFC 9106 recommendations:

| Name | `memorySize` | `passes` | `parallelism` | `tagLength` | Use case |
|------|-------------|---------|---------------|-------------|----------|
| INTERACTIVE | 19456 KiB | 2 | 1 | 32 | Login forms, session tokens |
| SENSITIVE | 65536 KiB | 3 | 4 | 32 | Master passwords, high-value secrets |

**INTERACTIVE** (~200–500 ms on modern hardware) is the right default for user
login. **SENSITIVE** (~1–2 s, 64 MiB) is for situations where latency is
acceptable in exchange for significantly stronger resistance: master passwords,
recovery keys, encryption keys derived from a passphrase.

A function that requires 64 MiB of RAM per evaluation means a GPU with 8 GiB
of VRAM can only run ~128 evaluations in parallel regardless of shader core
count. PBKDF2 at any practical iteration count cannot approach this resistance.

---

## Password hashing and verification

```typescript
import loadArgon2idWasm from 'argon2id';
import { constantTimeEqual } from 'leviathan-crypto';

const argon2id = await loadArgon2idWasm();

// Registration — hash and store
const salt = crypto.getRandomValues(new Uint8Array(16));
const hash = argon2id({
  password:    new TextEncoder().encode(password),
  salt,
  passes:      2,
  memorySize:  19456,
  parallelism: 1,
  tagLength:   32,
});

// Store hash, salt, and params together. Salt is not secret.
db.store(userId, { hash, salt, passes: 2, memorySize: 19456, parallelism: 1 });

// Verification — recompute and compare
const stored = db.load(userId);
const candidate = argon2id({
  password:    new TextEncoder().encode(candidatePassword),
  salt:        stored.salt,
  passes:      stored.passes,
  memorySize:  stored.memorySize,
  parallelism: stored.parallelism,
  tagLength:   32,
});

// constantTimeEqual from leviathan-crypto prevents timing side-channels
const valid = constantTimeEqual(candidate, stored.hash);
```

> [!IMPORTANT]
> The `salt` **must** be stored alongside the hash. It is not secret, but without
> the original salt the hash cannot be recomputed and verification will always
> fail. Store `salt`, `passes`, `memorySize`, and `parallelism` together as a
> unit.

---

## Passphrase-based encryption with leviathan-crypto

Argon2id produces a root key from a passphrase. HKDF-SHA256 from leviathan then
expands that root key into the separate encryption and MAC keys that
`SerpentSeal` and `XChaCha20Poly1305` expect. Keeping the two steps separate
means the expensive Argon2id call happens once per passphrase, and HKDF handles
any further key material needed.

### With SerpentSeal

`SerpentSeal` takes a 64-byte key (32-byte enc key + 32-byte MAC key). HKDF
expands the 32-byte Argon2id output to 64 bytes:

```typescript
import loadArgon2idWasm from 'argon2id';
import { init, SerpentSeal, HKDF_SHA256 } from 'leviathan-crypto';

await init(['serpent', 'sha2']);
const argon2id = await loadArgon2idWasm();

// ── Encrypt ──────────────────────────────────────────────────────────────────

const argonSalt = crypto.getRandomValues(new Uint8Array(16));
const rootKey = argon2id({
  password:    new TextEncoder().encode(passphrase),
  salt:        argonSalt,
  passes:      2,
  memorySize:  19456,
  parallelism: 1,
  tagLength:   32,
});

const hkdf    = new HKDF_SHA256();
const fullKey = hkdf.derive(rootKey, argonSalt, new TextEncoder().encode('serpent-seal-v1'), 64);
hkdf.dispose();

const serpent    = new SerpentSeal();
const ciphertext = serpent.encrypt(fullKey, plaintext);
serpent.dispose();

// Store with ciphertext — all required for decryption
const envelope = { ciphertext, argonSalt };

// ── Decrypt ──────────────────────────────────────────────────────────────────

const rootKey2 = argon2id({
  password:    new TextEncoder().encode(passphrase),
  salt:        envelope.argonSalt,
  passes:      2,
  memorySize:  19456,
  parallelism: 1,
  tagLength:   32,
});

const hkdf2    = new HKDF_SHA256();
const fullKey2 = hkdf2.derive(rootKey2, envelope.argonSalt, new TextEncoder().encode('serpent-seal-v1'), 64);
hkdf2.dispose();

const serpent2 = new SerpentSeal();
const decrypted = serpent2.decrypt(fullKey2, envelope.ciphertext);
serpent2.dispose();
```

### With XChaCha20Poly1305

`XChaCha20Poly1305` takes a 32-byte key and a 24-byte nonce. The nonce is
generated fresh per encryption; only the Argon2id salt needs to be stored:

```typescript
import loadArgon2idWasm from 'argon2id';
import { init, XChaCha20Poly1305, HKDF_SHA256 } from 'leviathan-crypto';

await init(['chacha20', 'sha2']);
const argon2id = await loadArgon2idWasm();

// ── Encrypt ──────────────────────────────────────────────────────────────────

const argonSalt = crypto.getRandomValues(new Uint8Array(16));
const rootKey = argon2id({
  password:    new TextEncoder().encode(passphrase),
  salt:        argonSalt,
  passes:      2,
  memorySize:  19456,
  parallelism: 1,
  tagLength:   32,
});

// tagLength: 32 already matches XChaCha20Poly1305's expected key size
// HKDF is optional here but included for domain separation.
const hkdf = new HKDF_SHA256();
const key  = hkdf.derive(rootKey, argonSalt, new TextEncoder().encode('xchacha-v1'), 32);
hkdf.dispose();

const nonce = crypto.getRandomValues(new Uint8Array(24));
const xc    = new XChaCha20Poly1305();
const ct    = xc.encrypt(key, nonce, plaintext);
xc.dispose();

const envelope = { ct, nonce, argonSalt };

// ── Decrypt ──────────────────────────────────────────────────────────────────

const rootKey2 = argon2id({
  password:    new TextEncoder().encode(passphrase),
  salt:        envelope.argonSalt,
  passes:      2,
  memorySize:  19456,
  parallelism: 1,
  tagLength:   32,
});

const hkdf2 = new HKDF_SHA256();
const key2  = hkdf2.derive(rootKey2, envelope.argonSalt, new TextEncoder().encode('xchacha-v1'), 32);
hkdf2.dispose();

const xc2       = new XChaCha20Poly1305();
const decrypted = xc2.decrypt(key2, envelope.nonce, envelope.ct);
xc2.dispose();
```

> [!CAUTION]
> Never reuse an Argon2id salt across different passphrases or key derivation
> contexts. Generate a fresh random salt for each new encryption envelope. The
> salt is not secret — store it in plaintext alongside the ciphertext.

---

## Memory note

>[!IMPORTANT]
> Each call to `loadArgon2idWasm()` instantiates a separate WASM instance. The
> package's own documentation recommends reloading the module between hashes when
> the `memorySize` varies significantly, since WASM linear memory is not
> deallocated between calls. For a single `memorySize` used consistently (the
> common case), one `await loadArgon2idWasm()` call at startup is correct.

---

> ## Cross-References
>
> - [README.md](./README.md) — project overview and quick-start guide
> - [sha2.md](./sha2.md) — HKDF-SHA256 for key expansion from Argon2id root keys
> - [serpent.md](./serpent.md) — SerpentSeal: Serpent-256 authenticated encryption (pairs with Argon2id-derived keys)
> - [chacha20.md](./chacha20.md) — XChaCha20Poly1305: ChaCha20 authenticated encryption (pairs with Argon2id-derived keys)
> - [utils.md](./utils.md) — `randomBytes` for generating salts, `constantTimeEqual` for hash verification
> - [architecture.md](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
