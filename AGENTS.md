# Agent Instructions: Leviathan Crypto Library

This file is the contract for all AI-assisted development on this repository.
Read it in full before starting any work.

---

## What This Project Is

`leviathan-crypto` is a strictly-typed, zero-dependency WebAssembly cryptography
library for the web. All cryptographic computation runs in WASM (AssemblyScript),
outside the JavaScript JIT. The TypeScript layer provides the public API, input
validation, type safety, and developer ergonomics. It never implements
cryptographic algorithms.

Read `docs/architecture.md` before starting any implementation work. It defines
the module structure, the `init()` API contract, the class naming conventions,
the build pipeline, and the repository layout. If something in your task conflicts
with `docs/architecture.md`, `docs/architecture.md` wins, flag the conflict
rather than resolving it silently.

---

## Build & Test

Always run `bun i` first. Every session, no exceptions. Missing devDependencies
(eslint, playwright, tsx, etc.) have caused agents to waste time debugging tool
errors that were simply install problems. Don't be that agent.

Use these shorthands, they are the correct commands:

```sh
bun i       # install, always run first, every session
bun bake    # full build (asm → embed → ts → wasm copy → docs)
bun check   # full test suite, unit + browser, correct timeouts
bun fix     # eslint autofix, run before marking any task done
bun pin     # re-pin action SHAs, run after any workflow file change
```

**Never run `bun build` directly.** that invokes the Bun bundler, not the
project build. Use the shorthand aliases (`bun bake` / `bun check` / `bun fix`
/ `bun pin`) in agent sessions rather than the verbose `bun run build` /
`bun run test` / `bun run lint` / `bun run pin-actions`. The shorthand and the
verbose forms run identical dispatchers (`scripts/build.ts`, `scripts/check.ts`,
`scripts/lint.ts`, `scripts/pin-actions.ts`), favor the shorthand for terse,
consistent invocations. `bun check` does a full build, then runs lint + unit
+ e2e in parallel. Always capture output to a log file and inspect from there,
to avoid running it twice:
`bun check 2>&1 | tee /tmp/check.log; grep -E "passed|failed|error" /tmp/check.log`
The summary lines appear at the end. If failures are present, inspect with:
`grep -A 10 "FAIL" /tmp/check.log`

**Workflow file changes require `bun pin` before committing.** Any edit to a
`.github/workflows/*.yml` file must be followed by `bun pin` to re-pin action
SHAs. Never skip this step.

**`bun scripts/test.ts unit:group <name>` in CI workflow files is correct
and intentional.** Each `.github/workflows/unit-*.yml` invokes this command
for its respective group; per-group file lists, build prerequisites, and
timeouts live in `scripts/lib/test-groups.ts` as the single source of truth.
Do not replace these invocations with `bun check` when editing workflow
files, and do not edit workflow YAML to add or remove individual test paths;
group composition belongs in `test-groups.ts` (see test-suite editing
instructions below).

### Running tests during iteration

`bun check` is the umbrella. When iterating on a single test or one family,
use the targeted shorthands to skip the full suite:

```sh
bun unit test/unit/aes/aes_kat.test.ts       # one unit test file
bun e2e test/e2e/seal.spec.ts                # one e2e spec
bun run test unit:group aes                  # one CI test group locally
```

`bun unit` and `bun e2e` forward extra arguments to vitest and playwright
after running the necessary build prerequisites. `bun run test unit:group <name>`
reads the file list and build dependencies from `scripts/lib/test-groups.ts`
and runs the same composition as the corresponding `.github/workflows/unit-<name>.yml`
job. See [docs/development.md](./docs/development.md) for the full developer workflow.

Always run `bun check` before marking a task done. The targeted commands are
for iteration speed, not for final verification.

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
> test vectors to make them pass, resulting in a test suite that validated a
> wrong implementation. The implementation was actually correct; the planning
> document was wrong.

### 2. Test vectors are immutable

Once a test vector is written and sourced from an authoritative reference, it
cannot be changed to make a failing test pass. If a test fails:

- Debug the implementation
- Verify the vector against the authoritative source independently
- If the vector is wrong (sourced incorrectly), fix the vector and document why
- Never change a vector to match implementation output without independent
  verification. If this occurs, you are required to produce a document explaining
  your findings and present it to the user post-session for review and acceptance.

A test suite that passes because vectors were adjusted to match the implementation
provides zero correctness assurance. It is worse than no tests.

### 3. Gate discipline

Every primitive family has a gate test, the simplest authoritative known-answer
test for that primitive. The gate is marked with a `// GATE` comment in the test
file.

**The gate must pass before any other tests in that family are written.**

If the gate fails, stop. Debug the implementation. Do not write round-trip tests,
streaming tests, or cross-check tests while the gate is failing, they will all
pass or fail for the wrong reasons.

If the gate passes on the first build, verify that the expected value was sourced
from the spec (not derived from the implementation output). A gate that passes
because the expected value was copied from the implementation output is not a gate.

### 4. Independent derivation

Each AssemblyScript primitive is implemented from the spec directly. Do not port
from an existing reference implementation. If a reference implementation exists
for cross-checking, use it **after** the independent implementation passes its
gate, never before.

This makes cross-checks a genuine correctness signal. If the WASM output matches
a reference for random inputs, that is meaningful evidence, because the two
implementations were written independently from the same spec. If you read the
reference first and port it, the cross-check tells you nothing except that you
copied it correctly.

### 5. Never embed cryptographic values in planning documents

Architecture documents, task files, and prompts describe structure and contracts,
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
- **Unix line endings.** follow what's defined in `.gitattributes`
- **Terse over verbose**: inline conditionals, short variable names, no
  unnecessary intermediate variables
- **No comments that restate the code**: comments explain *why*, not *what*
- **Spec citations in source**: when implementing a standard, cite the section.
  Example: `// FIPS 180-4 §4.1.2, Ch function`
- **Exports are the public contract**: keep internal functions unexported;
  only export what the TypeScript layer needs to call
- **The ASCII art header** goes on every source file (see any existing file)
- **Run `bun fix` before committing**: lint errors are not the reviewer's problem

---

## Architecture Constraints

These are decisions already made. Do not relitigate them without raising it first.

- **Nine WASM binaries**: `serpent.wasm`, `chacha20.wasm`, `sha2.wasm`,
  `sha3.wasm`, `ct.wasm`, `kyber.wasm`, `aes.wasm`, `mldsa.wasm`,
  `slhdsa.wasm`. Each is independent: separate linear memory, separate
  buffer layout, separate AssemblyScript entry point. `ct.wasm` is an
  internal utility (SIMD constant-time compare, not a user-facing
  module). `'keccak'` is an alias for `'sha3'` in the TypeScript layer;
  it is not a separate module. No `keccak.wasm` exists or should be
  created. `slhdsa.wasm` embeds its own Keccak permutation (verbatim
  port from sha3-wasm) for the FIPS 205 internal hash primitives
  (F / H / T_l / PRF / PRFmsg / Hmsg); pure-mode SLH-DSA never touches
  the sha3 module, prehash SLH-DSA only touches sha3 for the running
  digest in the sign layer.
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
- **`src/ts/embedded/` is gitignored**: these files are build artifacts
  generated by `scripts/embed-wasm.ts` (WASM thunks) and
  `scripts/embed-workers.ts` (pool-worker IIFE bundles). Do not create or
  edit them manually.
- **`sideEffects: false`** in `package.json`. Every module must be genuinely
  side-effect-free for tree-shaking.
- **`stream/` is cipher-agnostic**: `SealStream`, `OpenStream`, and
  `SealStreamPool` take a `CipherSuite` object at construction. The two
  shipped implementations are `XChaCha20Cipher` and `SerpentCipher`. Do not
  add cipher-specific stream classes, the generic pattern replaces them.
- **Stream layer requires sha2**: HKDF-SHA256 is a stream-layer dependency,
  not a cipher choice. All stream classes validate `isInitialized('sha2')`
  and throw if not. This is separate from the cipher's own module requirements.
- **Pool workers bypass the module cache**: each worker instantiates its own
  WASM from pre-compiled `WebAssembly.Module` objects. They do not call
  `initModule()` or share the main-thread cache. Workers are spawned from
  blob URLs over an IIFE source bundled at lib build time
  (`src/ts/embedded/<cipher>-pool-worker.ts`); the
  `<cipher>/pool-worker.ts` files are the build inputs, not the runtime
  spawn entries.
- **`/embedded` subpath exports**: each module has a `*/embedded.ts` that
  re-exports the gzip+base64 blob as a named export (`serpentWasm`,
  `chacha20Wasm`, etc.). The `src/ts/embedded/` directory is the generated
  source; the per-module files re-export from it.
- **Single-use encrypt guards**: `SealStream.finalize()`, `SealStreamPool.seal()`,
  `ChaCha20Poly1305.encrypt()`, and `XChaCha20Poly1305.encrypt()` can only be
  called once per instance. This prevents nonce reuse.
- **Per-call WASM lifecycle in SignatureSuite factories**: suite consts under
  `src/ts/sign/suites/` instantiate the underlying primitive class per call,
  use it inside a `try`, and `dispose()` it in `finally`. No suite-level
  long-lived instance is held. This matches the static-method posture of
  KMAC and keeps suites stateless and reentrant. The Phase 2 SLH-DSA pure
  and prehash suites and the PQ-only hybrid suites follow this pattern;
  all future phase suite factories (ed25519, ecdsa-p256, hybrid-classical)
  do the same.
- **PQ-only hybrid suite factory pattern**: hybrid suite factories under
  `src/ts/sign/suites/hybrid-pq.ts` compose two underlying signature
  primitives (currently ML-DSA + SLH-DSA at matching NIST categories).
  Composite encoding is `pk_combined = pk_mldsa || pk_slhdsa` and
  `sig_combined = sig_mldsa || sig_slhdsa` with sizes catalog-known and
  no length prefixes. ML-DSA half always comes first by convention. The
  same `effective_ctx` is fed to both sub-signers; the per-hybrid unique
  `ctxDomain` (e.g. `'mldsa44-slhdsa128f-envelope-v3'`) prevents
  cross-suite and cross-hybrid forgery. `verifyPrehashed` ALWAYS runs
  both sub-verifies; no early-return on the first half's result.
  Signature subarrays returned from the wire-format split must NOT be
  wiped on verify failure, they are subarrays of caller-owned data.
- **Internal factories + external consts in `src/ts/sign/suites/`**: PascalCase
  factory functions (e.g. `MldsaPureSuite`, `MldsaPrehashSuite`) build the
  suite objects and stay unexported. Each catalog entry is then exported as
  a named `const`, one per format byte. The factories must not become public,
  the catalog's format-byte allocations are locked and consumers cannot mint
  custom suites with reserved bytes.
- **ctxDomain construction**: every SignatureSuite carries a built-in
  `{scheme}-envelope-v3` (or `{scheme}-prehash-envelope-v3` for prehash, or
  `{scheme1}-{scheme2}-envelope-v3` for hybrids) string. The suite's sign /
  verify methods wrap user_ctx into effective_ctx via
  `buildEffectiveCtx(ctxDomain, user_ctx)` before calling the underlying
  primitive. Wire format carries the raw user_ctx, never effective_ctx.
  Suite-level ctxDomain ≤ 32 bytes (factory-validated, throws plain `Error`).
  Per-call user_ctx ≤ 200 bytes (throws `SigningError('sig-ctx-too-long')`).
- **SignatureSuite vs StreamableSignatureSuite at the type level**: pure-mode
  suites (catalog category 0x0X) implement `SignatureSuite` only and cannot
  be passed to `SignStream` / `VerifyStream` (compile-time error). Prehash
  and hybrid suites implement `StreamableSignatureSuite` (extends
  `SignatureSuite`) and expose `signPrehashed` / `verifyPrehashed`. The
  type-level wall keeps "sign in pure mode" and "sign via streaming
  prehash" from collapsing into the same call site by accident.
- **SHA3 streaming classes (`SHA3_256Stream`, `SHA3_512Stream`)**: Phase 1
  added these alongside the existing one-shot `SHA3_256` / `SHA3_512`.
  Lifecycle mirrors SHAKE128 / SHAKE256: `_acquireModule('sha3')` at
  construction, `_releaseModule` on `dispose()` or `finalize()`, exclusivity
  enforced via the standard guard. Future phase work that adds streaming
  prehashes for SHA-2 (Ed25519ph, ECDSA-P256 prehash) should add analogous
  `SHA256Stream` / `SHA512Stream` to the sha2 module using the same
  discipline.
- **SHAKE streaming classes (`SHAKE128Stream`, `SHAKE256Stream`)**: Phase 2
  added these to the sha3 module alongside the unbounded `SHAKE128` /
  `SHAKE256` XOF classes. `outputLen` is bound at construction; `update`
  / `finalize` shape mirrors `SHA3_256Stream`. Required substrate for
  `createRunningHash('shake-128' | 'shake-256')` in the sign layer; used
  by SLH-DSA prehash suites and PQ-only hybrid suites.
- **Phase 2 test groups**: SLH-DSA primitive and signature-layer tests
  live in three new CI groups in `scripts/lib/test-groups.ts`:
  `slhdsa` (10-min timeout, primitive plus prehash/validation),
  `slhdsa-acvp` (20-min timeout, the ACVP corpus, isolated because it
  is the slowest), and `sign-hybrid` (15-min timeout, `UNIT_FULL` build
  targets, sign-layer SLH-DSA and PQ-only hybrid suite tests). The
  split keeps any single group inside its `timeout-minutes`; consult
  the recorded per-group runtimes before considering consolidation.

---

## Test File Maintenance

Any time a unit or e2e test file is added or removed, two things must happen.
Both are required. Neither is optional.

### 1. Update `docs/test-suite.md`

- **Test Counts table** (top of file): update the unit or e2e count and the
  total. Get the test count for the new file from the `bun check` log:
  `grep -E "test/unit/path/to/file" /tmp/check.log` or count `it(`/`test(`
  calls directly in the file.
- **Unit Tests or E2E Tests table**: add or remove the corresponding row.
  Match the format of existing rows, file path, description, vector/test
  count, gate column.

### 2. Update CI (unit tests only)

Playwright discovers e2e specs automatically. No CI change is needed for e2e.

For unit tests:

- Open `scripts/lib/test-groups.ts` and find the `UNIT_GROUPS` entry whose
  `name` matches the test family (e.g. `aes`, `mldsa`, `kyber`). To locate
  the right group when unsure: `grep -l "test/unit/family" scripts/lib/test-groups.ts`.
- Add or remove the test file path from that group's `files` array.
- No workflow file edit is needed when adding a test to an existing group;
  the corresponding `.github/workflows/unit-<family>.yml` already calls
  `bun scripts/test.ts unit:group <name>`, which reads the file list from
  `test-groups.ts` at run time.

**Adding a new unit group.** If the new tests belong to a primitive family
with no existing group, do both: (1) add a new `UNIT_GROUPS` entry to
`scripts/lib/test-groups.ts` with `name`, `files`, `buildTargets`, and
`timeoutMin`; (2) create a new `unit-<family>.yml` workflow. Read an existing
workflow file first and match its structure exactly, job name format,
timeout settings, step order, `bun i` precondition, and the
`bun scripts/test.ts unit:group <name>` invocation. Then wire it into
`test-suite.yml` following the same pattern as the other unit jobs. Run
`bun pin` when done.

---

## Memory and Security

- **`wipeBuffers()` must be called on dispose**: every WASM module exports
  `wipeBuffers()`. The TypeScript wrapper must call it in `dispose()`. Key
  material and intermediate state must not persist in WASM memory after an
  operation completes.
- **Constant-time operations**: MAC verification, padding validation, and any
  comparison of secret-derived values must use XOR-accumulate patterns. No early
  return on mismatch. No branch on secret bytes.
- **AEAD `decrypt()` throws on authentication failure.** never returns null.
  Null returns are a footgun for callers who might forget to check.
- **No polyfill for `crypto.getRandomValues`**: fail loudly in environments
  that don't have it.
- **Authentication warnings**: unauthenticated modes (`SerpentCbc`, `SerpentCtr`)
  must carry JSDoc warnings. The README must document that these modes require
  pairing with HMAC (Encrypt-then-MAC) or replacement with `XChaCha20Poly1305`.

---

## Docs as Contract (not Authority)

`docs/*.md` describe what the library does, they are not authoritative on
cryptographic values or algorithm behavior. The spec is. If a doc contradicts
the spec, the spec wins and the doc is wrong.

However, docs ARE authoritative on API shape. If `docs/serpent.md` says
`SerpentCipher` has `formatEnum: 0x02` and the source says something different,
that is a discrepancy that must be flagged, not silently resolved in either
direction.

`docs/CLAUDE_consumer.md` ships inside the npm package. It is read by AI
assistants consuming this library. It must be kept in sync with any public API
change, if a class is added, removed, renamed, or its signature changes,
`CLAUDE_consumer.md` gets updated in the same commit.

---

## Key Files

- Architecture: `docs/architecture.md`
- Test suite reference: `docs/test-suite.md`
- Test vectors: `test/vectors/` (tracked by `test/vectors/SHA256SUMS`)
- Per-module docs: `docs/*.md`
- Consumer AI guide: `docs/CLAUDE_consumer.md`

---

## Definition of Done

A task is complete when **all** of the following are true:

1. `bun check` passes, all unit and e2e tests green
2. `bun fix` has been run, no lint errors remain
3. The gate test for any new primitive is sourced from the authoritative spec
4. `wipeBuffers()` covers all new buffers
5. No existing tests were modified to make new tests pass
6. The implementation matches the spec, not just the tests
7. Any test file added or removed has matching updates in `docs/test-suite.md`:
   both the Test Counts table and the per-file row in the Unit or E2E table
8. Any unit test file added or removed has matching updates in the appropriate
   `unit-*.yml` workflow, followed by `bun pin`
9. Any public API addition, removal, or signature change has matching updates
   in the relevant `docs/*.md` file. included but not limited to:
   - `docs/CLAUDE_consumer.md` agentic documentation help (always)
   - `docs/exports.md` any export changed
   - `docs/architecture.md` if the module structure changed
   - `docs/aead.md` if the streaming API or wire format changed

**Release tasks additionally require:**

10. `SECURITY.md` supported versions table updated
11. `CHANGELOG` entry added with breaking changes, migration table if applicable,
   and added/fixed/removed summary
12. `npm pack --dry-run` run and output reviewed, confirm deleted files are
    absent, no unexpected files included
13. Version bump in `package.json` is **not** part of any task, it is handled
    by the release workflow at tag time. Never touch `package.json` version.

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
- You have attempted to fix the same failure **more than twice** without success
- Anything else where the honest answer is "I am not sure"

**Stop. Do not guess. Do not proceed. Raise an issue.**

Two failed attempts at the same problem is the limit. On the third attempt you
are guessing. Create `ISSUE.md` in the repository root:

```markdown
# Issue, [short title]

## Status
Blocked. Implementation work stopped at [file / function / test].

## What I was trying to do
[The specific task or step that hit the blocker]

## What I tried
[Each attempt, in order, with the result of each. Be specific, include
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
