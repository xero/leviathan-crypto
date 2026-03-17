# Agent Instructions — Leviathan Crypto Library

This file is the contract for all AI-assisted development on this repository.
Read it in full before starting any work.

---

## What This Project Is

`leviathan-crypto` is a strictly-typed, zero-dependency WebAssembly cryptography
library for the web. All cryptographic computation runs in WASM (AssemblyScript),
outside the JavaScript JIT. The TypeScript layer provides the public API — input
validation, type safety, and developer ergonomics. It never implements
cryptographic algorithms.

Read `docs/architecture.md` before starting any implementation work. It defines
the module structure, the `init()` API contract, the class naming conventions,
the build pipeline, and the repository layout. If something in your task conflicts
with `docs/architecture.md`, `docs/architecture.md` wins — flag the conflict
rather than resolving it silently.

---

## Build & Test

```sh
bun run build        # build:asm → build:embed → build:ts → copy WASM
bun run test         # build:asm → build:embed → vitest run
bun run test:browser # build → playwright test (Chromium, Firefox, WebKit)
bun run test:all     # unit + browser
bun run lint         # eslint check
bun run lint:fix     # eslint autofix
```

**Note:** You can use npm if bun in unavailable. But bun is the preferred tool for speed.

---

## Ground Rules

These rules apply to every session, every file, every decision. They are not
suggestions. If a task asks you to do something that violates these rules, the
rules win.

### 1. The spec is the authority

When implementing any cryptographic primitive, the authoritative source is the
published standard:

- Serpent: AES submission (Ross Anderson, Eli Biham, Lars Knudsen)
- ChaCha20, Poly1305, ChaCha20-Poly1305: RFC 8439
- XChaCha20-Poly1305: draft-irtf-cfrg-xchacha
- SHA-256, SHA-384, SHA-512: FIPS 180-4
- SHA-3, SHAKE: FIPS 202
- HMAC: RFC 2104
- HMAC test vectors: RFC 4231

If any file in this repository states a cryptographic value (hash output, round
constant, test vector expected value) that differs from the published standard,
**the standard wins**. Flag the discrepancy. Do not silently use the wrong value.

> **Why this rule exists:** A planning document once contained a wrong expected
> value for SHA-256("abc"). An agent treated the planning document as
> authoritative, found that the implementation did not match, and corrupted the
> test vectors to make them pass — resulting in a test suite that validated a
> wrong implementation. The implementation was actually correct; the planning
> document was wrong.

### 2. Test vectors are immutable

Once a test vector is written and sourced from an authoritative reference, it
cannot be changed to make a failing test pass. If a test fails:

- Debug the implementation
- Verify the vector against the authoritative source independently
- If the vector is wrong (sourced incorrectly), fix the vector and document why
- Never change a vector to match implementation output without independent verification.
  If this occurs, you are required to produce a document explaining your findings
  and present it to the user post-session for review and acceptance.

A test suite that passes because vectors were adjusted to match the implementation
provides zero correctness assurance. It is worse than no tests.

### 3. Gate discipline

Every primitive family has a gate test — the simplest authoritative known-answer
test for that primitive. The gate is marked with a `// GATE` comment in the test
file.

**The gate must pass before any other tests in that family are written.**

If the gate fails, stop. Debug the implementation. Do not write round-trip tests,
streaming tests, or cross-check tests while the gate is failing — they will all
pass or fail for the wrong reasons.

If the gate passes on the first build, verify that the expected value was sourced
from the spec (not derived from the implementation output). A gate that passes
because the expected value was copied from the implementation output is not a gate.

### 4. Independent derivation

Each AssemblyScript primitive is implemented from the spec directly. Do not port
from an existing reference implementation. If a reference implementation exists
for cross-checking, use it **after** the independent implementation passes its
gate — never before.

This makes cross-checks a genuine correctness signal. If the WASM output matches
a reference for random inputs, that is meaningful evidence — because the two
implementations were written independently from the same spec. If you read the
reference first and port it, the cross-check tells you nothing except that you
copied it correctly.

### 5. Never embed cryptographic values in planning documents

Architecture documents, task files, and prompts describe structure and contracts —
not cryptographic values. Hash outputs, round constants, S-box entries, rotation
amounts, and test vector expected values belong only in:

- Test files (sourced directly from the authoritative spec)
- Source code (constants implemented from the spec, with spec section cited)

If you are writing a test and need an expected value, fetch it from the spec.
Do not use a value from a prompt or planning document without independent
verification.

### 6. The implementation, not the plan, is the product

Prompts and task files describe intent. The implementation must be correct
according to the spec, regardless of what the prompt says. If a prompt describes
an algorithm step incorrectly, implement the correct algorithm and note the
discrepancy. Do not implement a wrong algorithm because the prompt described it
that way.

---

## Code Style

- **Tabs, not spaces** for indentation (AssemblyScript and TypeScript)
- **Unix Line endings** follow what's defined in `.gitattributes`
- **Terse over verbose**: inline conditionals, short variable names, no
  unnecessary intermediate variables
- **No comments that restate the code**: comments explain *why*, not *what*
- **Spec citations in source**: when implementing a standard, cite the section.
  Example: `// FIPS 180-4 §4.1.2 — Ch function`
- **Exports are the public contract**: keep internal functions unexported;
  only export what the TypeScript layer needs to call
- **The ASCII art header** goes on every source file (see any existing file)

---

## Architecture Constraints

These are decisions already made. Do not relitigate them without raising it first.

- **Four WASM modules**: `serpent.wasm`, `chacha.wasm`, `sha2.wasm`, `sha3.wasm`.
  Each is independent — separate linear memory, separate buffer layout, separate
  AssemblyScript entry point.
- **Static buffers only**: no dynamic allocation (`memory.grow()` is not used).
  All buffers are fixed offsets in linear memory defined in `buffers.ts`.
- **Buffer layout starts at 0**: each module's layout is independent and starts
  at offset 0. There is no shared memory between modules.
- **TypeScript layer never implements crypto**: the `src/ts/` classes write inputs
  to WASM memory, call exported functions, read outputs. That is all they do.
- **`init()` is required**: no class silently auto-initializes. If a class is
  used before its module is loaded, it throws a clear error.
- **Class names have no `Wasm` suffix**: `Serpent`, not `SerpentWasm`.
  See `docs/architecture.md` for the full class name table.
- **`src/ts/embedded/` is gitignored**: these files are build artifacts generated
  by `scripts/embed-wasm.ts`. Do not create or edit them manually.
- **`sideEffects: false`** in package.json. Every module must be genuinely
  side-effect-free for tree-shaking.

---

## Memory and Security

- **`wipeBuffers()` must be called on dispose**: every WASM module exports
  `wipeBuffers()`. The TypeScript wrapper must call it in `dispose()`. Key
  material and intermediate state must not persist in WASM memory after an
  operation completes.
- **Constant-time operations**: MAC verification, padding validation, and any
  comparison of secret-derived values must use XOR-accumulate patterns. No early
  return on mismatch. No branch on secret bytes.
- **AEAD.decrypt() throws on authentication failure** — never returns null.
  Null returns are a footgun for callers who might forget to check.
- **No polyfill for `crypto.getRandomValues`**: fail loudly in environments
  that don't have it.
- **Authentication warnings**: unauthenticated modes (`SerpentCbc`, `SerpentCtr`)
  must carry JSDoc warnings. The README must document that these modes require
  pairing with HMAC (Encrypt-then-MAC) or replacement with `XChaCha20Poly1305`.

---

## Docs as Contract (not Authority)

`docs/*.md` describe what the library does — they are not authoritative on
cryptographic values or algorithm behavior. The spec is. If a doc contradicts
the spec, the spec wins and the doc is wrong.

However, docs ARE authoritative on API shape. If `docs/serpent.md` says
`serpentInit(mode?, opts?)` and the source says something different, that is
a discrepancy that needs to be flagged, not silently resolved in either direction.

---

## Key Files

- Architecture: `docs/architecture.md`
- Testing guide: `docs/testing.md`
- Test vectors: `test/vectors/` (tracked by `test/vectors/SHA256SUMS`)
- Per-module docs: `docs/*.md`

---

## Definition of Done

A task is complete when **all** of the following are true:

1. All tests pass — `bun run test` and `bun run test:browser`
2. The gate test for any new primitive is sourced from the authoritative spec
3. `wipeBuffers()` covers all new buffers
4. Documentation is updated (`docs/architecture.md` buffer layout table,
   `docs/testing.md` test counts, `README.md` primitives table)
5. No existing tests were modified to make new tests pass
6. The implementation matches the spec, not just the tests
7. Docs reflect the implementation — any public API addition, removal, or
   signature change has a matching update in the relevant `docs/*.md` file
   and `docs/architecture.md` if the module structure changed.

---

## Raising an Issue

**Never guess. Never hallucinate a value, a spec behavior, or an API decision.**

If you are ever in any of these situations:

- You cannot find an authoritative source for a value you need
- A test is failing and you cannot determine whether the bug is in the
  implementation, the test vector, or your understanding of the spec
- Two authoritative sources contradict each other
- The task as written is ambiguous and proceeding requires an assumption
  you are not confident in
- You have attempted to fix the same failure more than twice without success
- Anything else where the honest answer is "I am not sure"

**Do not guess. Do not proceed. Raise an issue.**

Create `ISSUE.md` in the repository root with:

```markdown
# Issue — [short title]

## Status
Blocked. Implementation work stopped at [file / function / test].

## What I was trying to do
[The specific task or step that hit the blocker]

## What I tried
[Each attempt, in order, with the result of each. Be specific — include
error messages, wrong output values, and what you expected instead.]

## Where I am stuck
[The specific question, ambiguity, or failure I cannot resolve.
If it involves a spec section, name the section.]

## What I need from you
[The specific information, clarification, or decision that would unblock me.]

## Relevant files
[List any source files, test files, or docs to look at]

## Relevant spec sections
[List any spec sections that are ambiguous, contradictory, or inaccessible]
```

Stop all work and present the issue. A detailed issue that stops work cleanly
is far more valuable than a completed task built on a guess.

---

## When Stuck (Before Raising an Issue)

- **Failing gate**: re-read the spec section for that primitive. The most common
  causes are wrong rotation amounts, wrong endianness, wrong padding, or wrong
  state indexing. Check each independently.
- **Passing tests, wrong output**: verify expected values were sourced from the
  spec, not derived from the implementation. Run the input through an independent
  tool (OpenSSL, Python hashlib, Node.js crypto).
- **Conflict between files**: this file > `docs/architecture.md` > task
  instructions > any other file. Raise conflicts rather than resolving them
  silently.
- **Uncertainty about a decision**: check `docs/architecture.md`. If it is not
  covered there, raise an issue rather than deciding unilaterally.
