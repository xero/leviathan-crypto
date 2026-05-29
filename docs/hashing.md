<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Hashing

The landing page for every hashing primitive in leviathan-crypto. It frames the three hash families the library ships, helps you pick the right one, and links the API docs, WASM implementation docs, and correctness audits for each.

> ### Table of Contents
> - [Overview](#overview)
> - [Choosing a hash](#choosing-a-hash)
> - [SHA-2](#sha-2)
> - [SHA-3 and SP 800-185](#sha-3-and-sp-800-185)
> - [BLAKE3](#blake3)
> - [Streaming and incremental hashing](#streaming-and-incremental-hashing)
> - [Message authentication](#message-authentication)
> - [Key derivation](#key-derivation)
> - [Extendable-output functions](#extendable-output-functions)
> - [Security notes](#security-notes)
> - [Related uses](#related-uses)
> - [Cross-references](#cross-references)

---

## Overview

A cryptographic hash function takes an input of any size and produces a fixed-size output called a **digest**. Even the smallest change to the input produces a completely different digest, which makes hash functions useful for verifying that data has not been tampered with. A hash is one-way: you cannot recover the input from the digest.

leviathan-crypto ships three hash families. Each runs entirely in WebAssembly; the TypeScript layer handles input validation and the JS/WASM boundary and never implements the algorithm.

**SHA-2.** The default workhorse, standardized in FIPS 180-4 (Secure Hash Standard). SHA-256 is the right choice unless a protocol or threat model tells you otherwise. Six variants ship, plus HMAC and HKDF built on top.

**SHA-3.** Standardized in FIPS 202 (SHA-3 Standard) and built on the Keccak sponge, a different mathematical foundation from SHA-2. It exists for defense in depth and for the SHAKE extendable-output functions. SP 800-185 (SHA-3 Derived Functions) adds cSHAKE and KMAC on the same sponge.

**BLAKE3.** A performance-tier tree-mode hash with keyed-hash and key-derivation modes. BLAKE3 is not a NIST-approved primitive. Reach for it for transcripts, content-addressed storage, and KDF-style work where the BLAKE2/BLAKE3 cryptanalytic posture is acceptable. Use SHA-2 or SHA-3 when an approved primitive is mandated.

---

## Choosing a hash

| **_I want to..._** | |
|---|---|
| Hash data with a sensible default | [`SHA256`](./sha2.md#sha256) |
| Hash with a NIST-approved primitive | [`SHA256`](./sha2.md#sha256), [`SHA512`](./sha2.md#sha512), or [`SHA3_256`](./sha3.md#sha3_256) |
| Hash as fast as possible | [`BLAKE3`](./blake3.md) (not NIST-approved) |
| Get length-extension immunity | any [SHA-3](./sha3.md) variant or [`BLAKE3`](./blake3.md); SHA-2 is vulnerable, so wrap it in [HMAC](#message-authentication) |
| Produce variable-length output | [`SHAKE128`](./sha3.md#shake128), [`SHAKE256`](./sha3.md#shake256), [`KMACXOF256`](./kmac.md#kmacxof256), or a [`BLAKE3OutputReader`](./blake3.md) |
| Authenticate a message with a key | [`HMAC_SHA256`](./sha2.md#hmac_sha256) or [`KMAC256`](./kmac.md#kmac256) |
| Derive keys from a shared secret | [`HKDF_SHA256`](./sha2.md#hkdf_sha256), [`BLAKE3DeriveKey`](./blake3.md), or [`CSHAKE256`](./kmac.md#cshake256) |
| Hash a password or passphrase | not these. Use **Argon2id**, see [argon2id.md](./argon2id.md) |
| Hash into a Merkle tree | [`Sha256Tree`](./merkle.md#sha256tree-and-blake3tree) or [`Blake3Tree`](./merkle.md#sha256tree-and-blake3tree) |
| Seed a CSPRNG accumulator | [`SHA256Hash`](./fortuna.md#api-reference), [`SHA3_256Hash`](./fortuna.md#api-reference), or [`BLAKE3Hash`](./fortuna.md#api-reference) |

---

## SHA-2

The SHA-2 family standardized in FIPS 180-4. Six fixed-output variants ship: SHA-256 and SHA-512 are the primary choices, SHA-384 and SHA-224 are truncated variants for protocol interop, and SHA-512/224 and SHA-512/256 use SHA-512 round logic with truncating IVs. HMAC and HKDF build keyed authentication and key derivation on the same compression functions.

| Module | Description |
|--------|-------------|
| [sha2.md](./sha2.md) | TypeScript API: `SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512`, `HKDF_SHA256`, `HKDF_SHA512` |
| [asm_sha2.md](./asm_sha2.md) | WASM implementation: compression functions, HMAC inner/outer padding |

---

## SHA-3 and SP 800-185

The SHA-3 family standardized in FIPS 202: four fixed-output hashes (SHA3-224 through SHA3-512) and two extendable-output functions (SHAKE128, SHAKE256), all built on the Keccak sponge. SP 800-185 adds cSHAKE and KMAC on the same primitive. SHA-3 is not a replacement for SHA-2; both are secure and NIST-standardized. SHA-3 gives you a hash on a different mathematical foundation, so a future weakness in one family does not touch the other.

| Module | Description |
|--------|-------------|
| [sha3.md](./sha3.md) | TypeScript API: `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, plus streaming variants (`SHA3_256Stream`, `SHA3_512Stream`, `SHAKE128Stream`, `SHAKE256Stream`) |
| [kmac.md](./kmac.md) | TypeScript API: `CSHAKE128`, `CSHAKE256`, `KMAC128`, `KMAC256`, `KMACXOF128`, `KMACXOF256` (SP 800-185) |
| [asm_sha3.md](./asm_sha3.md) | WASM implementation: Keccak permutation (1600-bit state), sponge construction |

**New streaming classes.** The SHA-3 family ships incremental absorb/squeeze classes: [`SHA3_256Stream`, `SHA3_512Stream`, `SHAKE128Stream`, and `SHAKE256Stream`](./sha3.md#streaming-classes). Feed data in chunks and finalize or squeeze when you are done, so you never hold the whole input in memory.

**`keccak` alias.** `'keccak'` is an alias for `'sha3'`. Same WASM binary, same instance slot; [`keccakInit()` and `sha3Init()`](./sha3.md#keccakinit-alias) are interchangeable. The `keccak` subpath exists for contexts where the Keccak name reads clearer, such as ML-KEM. See [init.md §keccak alias](./init.md#keccak-alias-for-ml-kem).

---

## BLAKE3

A SIMD-only BLAKE3 binding covering all three modes from the BLAKE3 specification (BLAKE3 §2.3, Modes): `hash`, `keyed_hash`, and `derive_key`. Each mode ships a one-shot class and a streaming class. The module is SIMD-only and fails loudly at `init()` on runtimes without WebAssembly SIMD.

| Module | Description |
|--------|-------------|
| [blake3.md](./blake3.md) | TypeScript API: `BLAKE3`, `BLAKE3Stream`, `BLAKE3KeyedHash`, `BLAKE3KeyedHashStream`, `BLAKE3DeriveKey`, `BLAKE3DeriveKeyStream`, `BLAKE3OutputReader`, plus the `BLAKE3Hash` Fortuna HashFn const |
| [asm_blake3.md](./asm_blake3.md) | WASM implementation: v128-internal `compress` and lane-parallel `compress4` (BLAKE3 §5.3, SIMD), §2.4 chunk machine, §2.5 tree assembly + root finalize, §2.6 XOF squeeze, all three §2.3 modes |

---

## Streaming and incremental hashing

When data arrives in chunks or is too large to buffer, use a streaming class instead of a one-shot call. The streaming surface differs by family.

**SHA-3.** Explicit incremental classes ship for the common variants: `SHA3_256Stream`, `SHA3_512Stream`, `SHAKE128Stream`, and `SHAKE256Stream`. See [sha3.md §Streaming Classes](./sha3.md#streaming-classes).

**BLAKE3.** Every mode has a streaming class: `BLAKE3Stream`, `BLAKE3KeyedHashStream`, and `BLAKE3DeriveKeyStream`, plus `BLAKE3OutputReader` for unbounded XOF reads. See [blake3.md](./blake3.md).

**SHA-2.** There is no separate `Stream` class. The one-shot `hash()` already streams large inputs through WASM in fixed-size chunks internally, so memory usage stays constant regardless of input size. Do not go looking for a `SHA256Stream`; call `hash()` and it handles large inputs for you.

---

## Message authentication

A Message Authentication Code (MAC) combines a secret key with a hash to produce a tag that proves both integrity and authenticity. The library ships two keyed constructions.

**HMAC.** RFC 2104 HMAC over SHA-2: [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), and [`HMAC_SHA512`](./sha2.md#hmac_sha512). HMAC has a formally proven security reduction and is the correct MAC even where length extension is not a concern. It is the default choice.

**KMAC.** The Keccak-based MAC from SP 800-185: [`KMAC128`](./kmac.md#kmac128) and [`KMAC256`](./kmac.md#kmac256), with built-in customization-string domain separation and a constant-time `verify` path. Use KMAC when you want a MAC on the SHA-3 family or defense in depth against a future weakness in SHA-2.

For the full decision between cSHAKE, KMAC, and HMAC, see [kmac.md §When to Use cSHAKE vs KMAC vs HMAC](./kmac.md#when-to-use-cshake-vs-kmac-vs-hmac).

---

## Key derivation

Deriving keys from a shared secret needs a Key Derivation Function (KDF), not a raw hash. Three options ship.

**HKDF.** RFC 5869 extract-then-expand over SHA-2: [`HKDF_SHA256`](./sha2.md#hkdf_sha256) and [`HKDF_SHA512`](./sha2.md#hkdf_sha512). This is the workhorse KDF used internally by the stream and ratchet layers.

**BLAKE3 derive_key.** [`BLAKE3DeriveKey`](./blake3.md) is a two-pass KDF with a domain-separating context string, suitable for application key derivation.

**cSHAKE.** [`CSHAKE128`](./kmac.md#cshake128) and [`CSHAKE256`](./kmac.md#cshake256) give a customized XOF without keying, for domain-separated output expansion under a context tag.

---

## Extendable-output functions

An extendable-output function (XOF) produces output of any length you ask for rather than a fixed-size digest. Useful for key stretching, nonce generation, and deriving several values from one stream.

**SHAKE.** [`SHAKE128`](./sha3.md#shake128) and [`SHAKE256`](./sha3.md#shake256) are the FIPS 202 XOFs. The only constraint is `outputLength >= 1`.

**KMACXOF.** [`KMACXOF128`](./kmac.md#kmacxof128) and [`KMACXOF256`](./kmac.md#kmacxof256) are KMAC in XOF mode, for variable-length keyed output.

**BLAKE3 XOF.** A [`BLAKE3OutputReader`](./blake3.md) squeezes unbounded output from any BLAKE3 mode.

---

## Security notes

> [!IMPORTANT]
> Read these before using any hash. Misusing hash functions is one of the most common sources of security vulnerabilities.

- **Hashing is not encryption.** A hash is one-way. You cannot recover the input from a digest. To protect data so it can be read later, use encryption, see [serpent.md](./serpent.md) or `XChaCha20Poly1305`.

- **Never hash passwords with a plain hash.** SHA-2, SHA-3, and BLAKE3 are all fast by design, which is exactly wrong for password storage. Use a memory-hardened function like Argon2id, see [argon2id.md](./argon2id.md).

- **SHA-2 is vulnerable to length extension.** Never build a MAC as `hash(secret || message)`. An attacker who sees `SHA256(secret || message)` can extend it without knowing the secret. SHA-3 and BLAKE3 are immune by construction, but HMAC is still the proven way to build a MAC. Use [`HMAC_SHA256`](./sha2.md#hmac_sha256) or [`KMAC256`](./kmac.md#kmac256).

- **Always compare tags in constant time.** Verifying a MAC tag with `===` leaks timing information that lets an attacker forge a tag one byte at a time. Use [`constantTimeEqual`](./utils.md#constanttimeequal), which always compares every byte.

---

## Related uses

Hashes feed several higher-level constructions in the library.

**Merkle trees.** The transparency-log substrate hashes leaves and nodes with [`Sha256Tree` or `Blake3Tree`](./merkle.md#sha256tree-and-blake3tree). See [merkle.md](./merkle.md).

**Fortuna CSPRNG.** The Fortuna accumulator takes a pluggable hash: [`SHA256Hash`, `SHA3_256Hash`, or `BLAKE3Hash`](./fortuna.md#api-reference). See [fortuna.md](./fortuna.md).

---

## Cross-references

| Document | Description |
|----------|-------------|
| [sha2_audit.md](./sha2_audit.md) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit.md](./sha3_audit.md) | Keccak permutation correctness, step verification, round constant derivation |
| [blake3_audit.md](./blake3_audit.md) | BLAKE3 tree-mode correctness, compress / compress4 equivalence, chunk machine, XOF snapshot integrity |
| [hmac_audit.md](./hmac_audit.md) | HMAC construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit.md](./hkdf_audit.md) | HKDF extract-then-expand, info field domain separation, stream key derivation |
| [lexicon.md](./lexicon.md) | Glossary of cryptographic terms: digest, sponge, XOF, MAC, KDF |
| [architecture.md](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
