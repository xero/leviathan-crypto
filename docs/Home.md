```
  ██     ▐█████ ██     ▐█▌  ▄█▌   ███▌ ▀███████▀▄██▌  ▐█▌  ███▌    ██▌   ▓▓
 ▐█▌     ▐█▌    ▓█     ▐█▌  ▓██  ▐█▌██    ▐█▌   ███   ██▌ ▐█▌██    ▓██   ██
 ██▌     ░███   ▐█▌    ██   ▀▀   ██ ▐█▌   ██   ▐██▌   █▓  ▓█ ▐█▌  ▐███▌  █▓
 ██      ██     ▐█▌    █▓  ▐██  ▐█▌  █▓   ██   ▐██▄▄ ▐█▌ ▐█▌  ██  ▐█▌██ ▐█▌
▐█▌     ▐█▌      ██   ▐█▌  ██   ██   ██  ▐█▌   ██▀▀████▌ ██   ██  ██ ▐█▌▐█▌
▐▒▌     ▐▒▌      ▐▒▌  ██   ▒█   ██▀▀▀██▌ ▐▒▌   ▒█    █▓░ ▒█▀▀▀██▌ ▒█  ██▐█
█▓ ▄▄▓█ █▓ ▄▄▓█   ▓▓ ▐▓▌  ▐▓▌  ▐█▌   ▐▒▌ █▓   ▐▓▌   ▐▓█ ▐▓▌   ▐▒▌▐▓▌  ▐███
▓██▀▀   ▓██▀▀      ▓█▓█   ▐█▌  ▐█▌   ▐▓▌ ▓█   ▐█▌   ▐█▓ ▐█▌   ▐▓▌▐█▌   ██▓
                    ▓█                               ▀▀        ▐█▌▌▌
```

# Leviathan Crypto Library

```bash
bun add leviathan-crypto
# or
npm install leviathan-crypto
```

No bundler is required. See [CDN usage](./cdn.md).

---

## AEAD

[`Seal`](./aead.md#api-reference), [`SealStream`](./aead.md#sealstream),
[`OpenStream`](./aead.md#openstream), and [`SealStreamPool`](./aead.md#sealstreampool)
are the primary API for authenticated encryption in leviathan-crypto.
They are cipher-agnostic: you pass a [`CipherSuite`](./ciphersuite.md) object
at construction and the implementation handles key derivation, nonce
management, and authentication for you.

**The classes form a natural progression:**
- [Seal](./aead.md#api-reference) handles data that fits in memory (>~66k).
- [SealStream](./aead.md#sealstream) and [OpenStream](./aead.md#openstream) handle
  data that arrives in chunks or is too large to buffer.
- [SealStreamPool](./aead.md#sealstreampool) parallelizes the chunked approach
  across Web Workers.

All four produce and consume the same [wire format](./aead.md#wire-format), so a
Seal blob can be opened by OpenStream and vice versa.

---

## Signatures

[`Sign`](./signing.md#sign), [`SignStream`](./signing.md#signstream),
and [`VerifyStream`](./signing.md#verifystream) are the primary API for
digital signatures in leviathan-crypto. They are scheme-agnostic: you pass
a [`SignatureSuite`](./signaturesuite.md) object at construction and the
implementation handles context binding, M' construction, and authentication
for you.

**The classes form a natural progression:**
- [Sign](./signing.md#sign) handles data that fits in memory.
- [SignStream](./signing.md#signstream) and [VerifyStream](./signing.md#verifystream)
  handle data that arrives in chunks or is too large to buffer.

All three produce and consume the same [wire format](./signing.md#wire-format), so
a Sign blob can be verified by VerifyStream and vice versa.

---

## Session primitives

The [ratchet module](./ratchet.md) provides Double-Ratchet KDF primitives
with post-quantum KEM steps, for consumers building forward-secret session
protocols (secure messengers, streaming key-rotation systems) whose needs
outgrow one-shot AEAD.

- [`ratchetInit`](./ratchet.md#ratchetinit) bootstraps the symmetric chains
  from a shared secret.
- [`KDFChain`](./ratchet.md#kdfchain) derives per-message keys with forward
  secrecy.
- [`kemRatchetEncap`](./ratchet.md#kemratchetencap) /
  [`kemRatchetDecap`](./ratchet.md#kemratchetdecap) perform the ML-KEM
  ratchet step for post-compromise security.
- [`SkippedKeyStore`](./ratchet.md#skippedkeystore) caches message keys for
  out-of-order delivery.

These are the primitives, not a full session. You compose them with your
transport, header format, and epoch orchestration. See the
[ratchet guide](./ratchet.md) for the construction.

---

## Find the right tool

| **_I want to..._** | |
|---|---|
| Encrypt data | [`Seal`](./aead.md#seal) with [`SerpentCipher`](./serpent.md#serpentcipher), [`XChaCha20Cipher`](./chacha20.md#xchacha20cipher), or [`AESGCMSIVCipher`](./aes.md#aesgcmsivcipher) |
| Encrypt a stream or large file | [`SealStream`](./aead.md#sealstream) to encrypt, [`OpenStream`](./aead.md#openstream) to decrypt |
| Encrypt in parallel | [`SealStreamPool`](./aead.md#sealstreampool) distributes chunks across Web Workers |
| Add post-quantum security | [`MlKemSuite`](./mlkem.md#mlkemsuite) wraps [`MlKem512`](./mlkem.md#parameter-sets), [`MlKem768`](./mlkem.md#parameter-sets), or [`MlKem1024`](./mlkem.md#parameter-sets) with any cipher suite |
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

*For raw primitives, low-level cipher access, and ASM internals see the [full API reference](./index.md).*

> [!TIP]
> New to crypto? We have a lot of technical jargon. Checkout the [lexicon](./lexicon.md)
> if you need a glossary of cryptographic terminology.

---

## Demos

We maintain a number of demo applications for the library

**`cli`** [ [npm](https://www.npmjs.com/package/lvthn) · [source](https://github.com/xero/leviathan-demos/tree/main/cli) · [readme](https://github.com/xero/leviathan-demos/blob/main/cli/README.md) ]

`lvthn` command-line file encryption tool supporting
Serpent-256-CBC+HMAC-SHA256, XChaCha20-Poly1305, and AES-256-GCM-SIV,
selectable via the `--cipher` flag. A single keyfile is compatible with all
three ciphers; the header byte determines decryption automatically. Encryption
and decryption distribute 64KB chunks across a worker pool sized to
`hardwareConcurrency`. Each worker owns an isolated WASM instance with no
shared memory between workers. The tool can export its own interactive
completions for a variety of shells.

```sh
bun add -g lvthn # or npm i -g lvthn
lvthn keygen --armor -o my.key
cat secret.txt | lvthn encrypt -k my.key --armor > secret.enc
```

**`COVCOM`** [ [demo](https://leviathan.3xi.club/covcom) · [source](https://github.com/xero/covcom/) · [readme](https://github.com/xero/covcom/blob/master/README.md) ]

Covert communications app suite for private group conversations. Invite, talk,
close the client, and the chat vanishes. Every message is encrypted with
XChaCha20 and signed with Ed25519. A BLAKE3 fingerprint on each key allows
peers to verify one another. SPQR's manual and epoch ratchets add forward
secrecy, while post-quantum ML-KEM-768 encapsulation keeps recorded
communications unreadable and secure against future cryptanalysis.

**`web`** [ [demo](https://leviathan.3xi.club/web) · [source](https://github.com/xero/leviathan-demos/tree/main/web) · [readme](https://github.com/xero/leviathan-demos/blob/main/web/README.md) ]

A self-contained browser encryption tool in a single HTML file. Encrypt text or
files with Serpent-256-CBC and scrypt key derivation, then share the armored
output. No server, no install, no network connection after initial load. The
code is written to be read. The Encrypt-then-MAC construction, HMAC input, and
scrypt parameters are all intentional examples worth studying.

**`tamper`** [ [demo](https://leviathan.3xi.club/tamper) · [source](https://github.com/xero/leviathan-demos/tree/main/tamper) · [readme](https://github.com/xero/leviathan-demos/blob/main/tamper/README.md) ]

A crypto attack-resilience demo. It runs a real two-party encrypted channel,
then lets you attack it: forge a replay and the sequence check rejects it,
tamper with a frame and the Poly1305 tag fails. Key exchange uses X25519 with
HKDF-SHA256, message encryption uses XChaCha20-Poly1305, and the relay server is
a dumb WebSocket pipe that never sees plaintext. The demo deconstructs the
protocol step by step with visual feedback for injection and replay attacks. For
a real, production-ready secure messenger built on the same library, see
[COVCOM](https://github.com/xero/covcom).

**`kyber`** [ [demo](https://leviathan.3xi.club/kyber) · [source](https://github.com/xero/leviathan-demos/tree/main/kyber) · [readme](https://github.com/xero/leviathan-demos/blob/main/kyber/README.md) ]

Post-quantum cryptography demo simulating a complete ML-KEM key encapsulation
ceremony between two browser-side clients. A live wire at the top of the page
logs every value that crosses the channel; importantly, the shared secret never
appears in the wire. After the ceremony completes, both sides independently
derive a symmetric key using HKDF-SHA256 and exchange messages encrypted with
XChaCha20-Poly1305. Each wire frame is expandable, revealing the raw nonce,
ciphertext, Poly1305 tag, and AAD.

**`jwt`** [ [demo](https://leviathan.3xi.club/jwt) · [source](https://github.com/xero/leviathan-demos/tree/main/jwt) · [readme](https://github.com/xero/leviathan-demos/blob/main/jwt/README.md) ]

Classical and post-quantum JSON Web Token signing demo in a single
self-contained HTML file. It signs the same claims across eleven algorithms:
EdDSA and ES256, the post-quantum ML-DSA and SLH-DSA families, and the leviathan
hybrid composites. Every algorithm runs through one uniform path on the `Sign`
suite API, with no per-algorithm branching. The token renders with its three
segments color-coded and a live byte readout, so the cost of quantum resistance
is visible: the same token grows from about 220 bytes under Ed25519 to past 66
kilobytes under SLH-DSA-SHAKE-256f. Tamper with the payload and verification
rejects it, because the signature covers the original bytes.

