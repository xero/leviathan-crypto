<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Development

Developer workflow for leviathan-crypto: building, testing, linting. For the internal build pipeline architecture see [architecture.md](./architecture.md). For the test corpus structure see [test-suite.md](./test-suite.md).

> ### Table of Contents
> - [First-time setup](#first-time-setup)
> - [The full check](#the-full-check)
> - [Targeted commands](#targeted-commands)
> - [Build targets](#build-targets)
> - [Output locations](#output-locations)
> - [Troubleshooting](#troubleshooting)
> - [Cross-References](#cross-references)

---

## First-time setup

Clone the repository and install dependencies. Bun is the only required toolchain.

```sh
bun i
```

For end-to-end tests you also need Playwright and its browser engines. Run this once per machine, after `bun i`. It installs Playwright globally and downloads the Chromium, Firefox, and WebKit browser binaries Playwright drives.

```sh
bun run test e2e:install
```

The `e2e:install` step mirrors the CI Docker image, so a local install matches what the test suite runs against in CI.

---

## The full check

```sh
bun check
```

`bun check` is the primary verification command. It performs a full clean build, then runs lint, unit tests, and end-to-end tests in parallel as separate processes. Each child task streams its output with a colored prefix tag, and the run ends with a per-task summary:

```
  ✓ lint    8.4s
  ✓ unit  142.7s
  ✓ e2e   213.1s

  total 213.4s
```

Exit code reflects the worst child. A failing task does not stop its siblings, so a single run reports every problem at once. Parallelization drops the average run time from ~5min to ~1min.

---

## Targeted commands

For the common case where you do not need to rerun the full suite, use the targeted shorthands. Each one performs only the build steps it requires, then runs its tool.

**`bun bake`.** Full build only. Walks the build dependency graph defined in `scripts/lib/build-graph.ts` and produces `build/`, `dist/`, the embedded blobs, and the root `CLAUDE.md`. Useful before publishing locally or testing a built bundle in a downstream project.

**`bun fix`.** ESLint with `--fix` applied. Run this before considering any work complete; lint errors fail CICD tests.

**`bun unit <file>`.** Run a single unit test. Builds the asm, embed, embed-workers, and ts targets first. Forwards any extra arguments to vitest.

```sh
bun unit test/unit/aes/aes_kat.test.ts
bun unit test/unit/aes/                       # all files under one directory
```

**`bun e2e <file>`.** Run a single e2e spec. Builds everything first. Forwards any extra arguments to playwright.

```sh
bun e2e test/e2e/seal.spec.ts
bun e2e test/e2e/seal.spec.ts --project=chromium
```

**`bun run test unit:group <name>`.** Run one CI test group locally. Builds the group's declared prerequisites, then runs the file list from `scripts/lib/test-groups.ts`. Group names match the `.github/workflows/unit-*.yml` suffixes: `core`, `serpent`, `chacha20`, `stream`, `kyber`, `hashing`, `montecarlo-cbc`, `montecarlo-ecb`, `nessie`, `ratchet`, `aes`, `aes-siv`, `aes-mct`, `mldsa`.

```sh
bun run test unit:group aes
```

**`bun pin`.** Re-pin every GitHub Action reference in `.github/workflows/*.yml` to a commit SHA. Run after any workflow edit, before committing.

---

## Build targets

`bun bake` runs every target. When you only changed part of the codebase and want a faster rebuild, run a single target with `bun bake <target>`.

| Target          | Inputs                                    | Outputs                                            | When to use                                                          |
| --------------- | ----------------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------- |
| `asm`           | `src/asm/*/index.ts`                      | `build/*.wasm`                                     | Edits to AssemblyScript sources                                      |
| `embed`         | `build/*.wasm`                            | `src/ts/embedded/<module>.ts`, `src/ts/ct-wasm.ts` | After `asm` rebuilds                                                 |
| `embed-workers` | `src/ts/<cipher>/pool-worker.ts`          | `src/ts/embedded/<cipher>-pool-worker.ts`          | Edits to pool worker sources                                         |
| `ts`            | `src/ts/**`                               | `dist/`                                            | Edits to TypeScript sources without an asm rebuild                   |
| `wasm-copy`     | `build/*.wasm`                            | `dist/*.wasm`                                      | URL-loaded consumer testing                                          |
| `claude-md`     | `docs/CLAUDE_consumer.md`                 | `CLAUDE.md` at repo root                           | After consumer-doc edits                                             |
| `docs`          | `docs/*.md` and SVGs                      | `dist/docs/`                                       | Verifying the doc subset that ships in the npm package               |

Each target cleans its own outputs before writing. Force is the only mode; there is no staleness check and no `--force` flag.

---

## Output locations

```
build/                 raw .wasm + asc-emitted .js/.d.ts (gitignored)
dist/                  published npm package contents (gitignored)
src/ts/embedded/       generated TS thunks: gz+b64 blobs + pool-worker IIFE strings (gitignored)
src/ts/ct-wasm.ts      generated raw byte array for the ct module (gitignored)
CLAUDE.md              copy of docs/CLAUDE_consumer.md, ships in the npm tarball
```

Every generated path is gitignored. Treat them as build artifacts. Never hand-edit anything under `src/ts/embedded/` or `src/ts/ct-wasm.ts`; the next `bun bake` overwrites them.

---

## Troubleshooting

**Stale output after a branch switch or a partial run.** Nuke the build outputs and rebuild from scratch.

```sh
rm -rf build dist src/ts/embedded src/ts/ct-wasm.ts CLAUDE.md
bun bake
```

**Narrowing a failure to one test group.** When `bun check` shows a unit failure, run that group alone to iterate without the e2e overhead.

```sh
bun run test unit:group aes
```

**A single test fails inconsistently.** Run it directly with the verbose reporter that `bun unit` passes by default.

```sh
bun unit test/unit/stream/seal.test.ts
```

**ESLint or TypeScript complains after a dependency bump.** `bun fix` handles the autofixable subset. Anything left is a real issue.

---

> ## Cross-References
>
> - [index](./README.md), Project documentation index
> - [architecture](./architecture.md), Repository structure, module relationships, and build pipeline internals
> - [test-suite](./test-suite.md), Test corpus structure, vector provenance, and gate discipline
> - [Agent Instructions](../AGENTS.md), Contract for AI-assisted development on this repository
