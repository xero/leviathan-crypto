# Leviathan Crypto Library Security Policy

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="100" align="left">

- **[Version Support](#supported-versions)**
- **[Security Posture](#security-posture)**
- **[Cryptanalytic Audits](#cryptanalytic-reviews)**
- **[Vulnerability Reporting](#reporting-a-vulnerability)**

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.1.x  | ︎✓         |
| v1.0.x  | ✗         |

> [!WARNING]
> v1.0.x does not zero intermediate key material in HMAC and HKDF operations.
> Upgrading to v1.1.0 or later is strongly recommended.

## Security Posture

[`leviathan-crypto`](https://leviathan.3xi.club) is a cryptography library. Security is not an afterthought,
it is the primary design constraint at every layer of the stack.

### Algorithm Correctness

Every primitive in this library was implemented by hand in AssemblyScript
against the authoritative specification for that algorithm:
[FIPS 180-4][fips180] (SHA-2), [FIPS 202][fips202] (SHA-3),
[RFC 8439][rfc8439] (ChaCha20-Poly1305), [RFC 2104][rfc2104] (HMAC),
[RFC 5869][rfc5869] (HKDF), and the original
[Serpent-256 specification][serpent] and S-box reference. No algorithm was
ported from an existing implementation. The specs are always the source of truth.

All implementations are verified against published known-answer test vectors
from NIST, RFC appendices, NESSIE, and the Argon2 reference suite. Vectors
are immutable: if an implementation produces incorrect output, the
implementation is fixed and vectors are never adjusted to match code.

### Side-Channel Resistance

Serpent's S-boxes are implemented as Boolean gate circuits designed with no table
lookups, no data-dependent memory access, and no data-dependent branches. Every
bit is processed unconditionally on every block. This is the most
timing-safe cipher implementation approach available in a WASM runtime,
where JIT optimisation can otherwise introduce observable timing variation.

All security-sensitive comparisons (e.g. MAC verification, padding validation)
use XOR-accumulate patterns with no early return on mismatch.
[`constantTimeEqual`][utils] is the mandated comparison function throughout
the library and its [demos][demos].

### WASM Execution Model

All cryptographic computation runs in WebAssembly, isolated outside the
JavaScript JIT. WASM execution is deterministic and not subject to JIT
speculation or optimisation. Each primitive family compiles to its own
isolated binary with its own linear memory. For example, key material in
the Serpent module cannot interact with memory in the SHA-3 module,
even in principle.

### Cryptanalytic Reviews

All of our primitives undergo periodic cryptographic implementation reviews.

| Primitive | Audit Description |
|-----------|-------------------|
| [serpent_audit][serpent_audit] | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit][chacha_audit] | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension |
| [sha2_audit][sha2_audit] | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit][sha3_audit] | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| [hmac_audit][hmac_audit] | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit][hkdf_audit] | HKDF extract-then-expand, info field domain separation, SerpentStream key derivation |

#### Additional Serpent-256 research

The security margin of Serpent-256 has been independently researched and
documented. The best known attack on the full 32-round cipher, _"biclique
cryptanalysis"_, achieves a complexity of 2²⁵⁵·¹⁹ with 2⁴ chosen
ciphertexts. This provides less than one bit of advantage over exhaustive
key search and has zero practical impact. Independent research conducted
against this implementation improved on the published result by −0.20 bits
through systematic parameter search, confirming no structural weakness
beyond what the published literature describes.

See: [`xero/BicliqueFinder/biclique_research.md`][biclique]

### Authenticated Encryption by Default

Raw unauthenticated cipher modes (`SerpentCbc`, `SerpentCtr`) are exposed
for power users but are not the recommended entry point. The primary API
surfaces — `SerpentSeal`, `SerpentStream`, `SerpentStreamSealer` — are
authenticated by construction.

**`SerpentStreamSealer` satisfies the _Cryptographic Doom Principle_:**

MAC verification is the unconditional gate on the open path,
decryption is unreachable until that gate clears, and per-chunk
HKDF key derivation with position-bound info extends this
guarantee to full stream integrity.

### Dependency Management

The library has **zero** runtime dependencies by design.
`sideEffects: false` is enforced in `package.json`. Argon2id integration
is documented as an _optional_ external dependency.
See: [`leviathan-crypto/wiki/argon2id`][argon2id-wiki].

Build toolchain dependencies are pinned with exact version locks in
`bun.lock`. GitHub Actions workflows use [SHA-pinned action references][workflows]
throughout with no floating tags. Supply chain integrity is treated as a
first-class concern for a cryptography library.

### Explicit Initialisation

No class silently auto-initialises. The [`init()`][init] gate is mandatory and
explicit, giving consumers full control over when WASM modules are loaded
and ensuring no hidden initialisation costs or race conditions. Classes
throw immediately if used before initialisation rather than failing
silently.

### Agentic Development Contracts

All AI-assisted development on this repository operates under a strict
agentic contract defined in [`AGENTS.md`][agents]. The contract enforces
spec authority over planning documents, immutable test vectors, gate
discipline before extending any test suite, independent algorithm
derivation from published standards, and constant-time/wipe requirements
for all security-sensitive code paths. Agents are explicitly prohibited
from guessing cryptographic values or resolving spec ambiguities silently.

The contract has been verified against Claude, GitHub Copilot (VS Code),
OpenHands, Kilo Code, Cursor, Windsurf, and Aider. Configuration files for
each are present in the repository and all route to [`AGENTS.md`][agents]
as the single source of authority.

---

## Reporting a Vulnerability

> [!IMPORTANT]
> **_Please do not open a public issue for security vulnerabilities._**

### Private Advisory (preferred)

Use GitHub's private vulnerability reporting form:
[https://github.com/xero/leviathan-crypto/security/advisories/new][advisory]

This opens a private channel between you and the maintainer, and you will
receive a response promptly. If the vulnerability is confirmed,
we will collaborate to fully understand the issue, including a review of
proposed fixes, so you can track and validate firsthand. Before any public
advisory is published, we will agree on a coordinated disclosure timeline.
After disclosure, you are encouraged to publish your own write-up, blog post,
or research notes, for full hacker scene credit.

### Direct Contact

If you prefer to contact the maintainer directly:

- **Email:** x﹫xero.style — PGP: [`0xAC1D0000`][pgp]
- **Matrix:** x0﹫rx.haunted.computer

> [!NOTE]
> Encrypted communication is welcome and _preferred_ for sensitive reports.

### Scope

**Reports are in scope for:**

- Authentication bypass in AEAD constructions
- Key material exposure or improper zeroing
- Incorrect entropy or CSPRNG weaknesses in Fortuna
- Side-channel vulnerabilities (timing, memory access patterns)
- Correctness bugs in cryptographic implementations (wrong output against
  test vectors)
- Platform-specific behavioral differences (WASM execution, binary output,
  or timing characteristics that differ across operating systems or CPU
  architectures)
- Supply chain issues (dependency tampering, workflow compromise)
- Improper scope of exported symbols

**Out of scope:**

- Vulnerabilities in third-party packages not maintained by this project.
  This includes optional peer dependencies such as argon2id.
  Please report those directly to their maintainers.
- Issues requiring physical access to the user's device
- Theoretical attacks with no practical exploit path (e.g. complexity
  improvements that remain computationally infeasible)
- Issues in the demo applications that do not affect the core library.
  Please open an issue in the [`leviathan-demos`][demos] repository instead.

[fips180]:        https://csrc.nist.gov/publications/detail/fips/180/4/final
[fips202]:        https://csrc.nist.gov/publications/detail/fips/202/final
[rfc8439]:        https://www.rfc-editor.org/rfc/rfc8439
[rfc2104]:        https://www.rfc-editor.org/rfc/rfc2104
[rfc5869]:        https://www.rfc-editor.org/rfc/rfc5869
[serpent]:        https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
[utils]:          https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal
[demos]:          https://github.com/xero/leviathan-demos/
[serpent_audit]:  https://github.com/xero/leviathan-crypto/wiki/serpent_audit
[chacha_audit]:   https://github.com/xero/leviathan-crypto/wiki/chacha_audit
[sha2_audit]:     https://github.com/xero/leviathan-crypto/wiki/sha2_audit
[sha3_audit]:     https://github.com/xero/leviathan-crypto/wiki/sha3_audit
[hmac_audit]:     https://github.com/xero/leviathan-crypto/wiki/hmac_audit
[hkdf_audit]:     https://github.com/xero/leviathan-crypto/wiki/hkdf_audit
[biclique]:       https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md
[argon2id-wiki]:  https://github.com/xero/leviathan-crypto/wiki/argon2id
[workflows]:      https://github.com/xero/leviathan-crypto/blob/main/scripts/pin-actions.ts
[init]:           https://github.com/xero/leviathan-crypto/wiki/init
[agents]:         https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md
[advisory]:       https://github.com/xero/leviathan-crypto/security/advisories/new
[pgp]:            https://0w.nz/pgp.pub
