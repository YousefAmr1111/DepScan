# PROJECT_RULES

Binding rules for the `depscan` monorepo. These rules are read before starting any
prompt work and are not optional.

---

## 1. Architecture

### 1.1 The one rule that matters

**The deterministic engine decides whether a vulnerability exists. The LLM only
explains and suggests fixes.**

- A finding exists **only** because deterministic code produced it: a matched advisory
  id, a semver range comparison, a lockfile read, a reproducible rule.
- An LLM may rephrase a finding, explain the impact, or propose a remediation. It may
  never create, remove, downgrade, or re-rank a finding.
- If a fix proposal cannot be verified by code, it is advice, not a finding.
- Every finding must be traceable to the deterministic input that produced it. If you
  cannot point at the exact rule/range/advisory, the finding is a bug.

### 1.2 Packages

| Package              | Name                 | Responsibility                                                                                                                                 | Must not                                                                          |
| -------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `packages/core`      | `@depscan/core`      | The analysis engine: parse manifests/lockfiles, match advisories, compare versions, score, and emit the report model. All decisions live here. | Touch the filesystem outside its inputs, print, or depend on `cli`/`dashboard`.   |
| `packages/cli`       | `@depscan/cli`       | Command definitions, argument parsing, and presentation. Thin. It may import `core` and nothing else project-internal.                         | Contain analysis logic, or reimplement matching/scoring that `core` already owns. |
| `packages/dashboard` | `@depscan/dashboard` | Renders `report.json` that `core` already produced.                                                                                            | Re-analyse, re-score, re-rank, or fetch anything. It is a viewer.                 |

### 1.3 Dependency direction

```
cli  ──depends on──▶  core
dashboard ──reads──▶  report.json   (data only, no core import required)
```

- Dependencies point one way only: `cli → core`. Never `core → cli`, never a cycle.
- The dashboard's only input is the serialised report. If it needs a new field, add the
  field to the report model in `core`; do not compute it in the dashboard.

### 1.4 The report contract

`core` owns `report.json`. The shape lives in `packages/core/src/types.ts`
(`Report`, `Vulnerability`, `Severity`), is mirrored by the JSON Schema in
`packages/core/src/report-schema.ts`, and is enforced at runtime by
`validateReport`. It is versioned via `schemaVersion`.

- Consumers (CLI output, dashboard) read the report; they do not redefine it.
- Schema changes are additive and bump `schemaVersion`.
- Nothing in the report may be produced by an LLM. Explanations are a separate,
  clearly-marked section so that they can be regenerated without touching findings.

### 1.5 Determinism

- Same inputs ⇒ byte-identical findings. No clock, randomness, or network in engine
  code paths that produce findings.
- Timestamps are supplied by the caller, not read from the clock inside the engine.
- Sort every collection before it reaches the report.

---

## 2. Conventions

### 2.1 Commits

- **Small commits.** One logical change per commit.
- **One feature per commit.** A commit that adds a feature does not also reformat,
  rename, or "fix" unrelated things.
- Conventional Commit subjects: `feat:`, `fix:`, `test:`, `refactor:`, `chore:`, `docs:`.
- Never commit a broken build. `pnpm build` and `pnpm test` pass before every commit.
- Never commit secrets, `.env` files, or real scan targets with private data.

### 2.2 Tests

- **Tests ship with every feature.** A feature without tests is unfinished.
- **No network calls in unit tests.** Tests use fixtures, in-memory inputs, and mocks.
  If a test needs the internet, it is an integration test and must be opt-in, named
  `*.integration.test.ts`, and skipped by default.
- Tests assert behaviour, not implementation details.
- One behaviour per test; test names read as sentences describing the rule.

### 2.3 TypeScript

- TypeScript everywhere, `strict` plus the extras in `tsconfig.base.json`.
- No `any`. Use `unknown` and narrow. No non-null assertions without a stated reason.
- No implicit dependency additions; a new third-party dependency needs a stated reason.

### 2.4 Before you finish any prompt

```bash
pnpm install   # clean install
pnpm build     # compiles, no errors
pnpm test      # all suites pass
pnpm lint      # zero errors
```

Then write `reports/P<NN>-report.md` using the template in §3.

---

## 3. REPORT TEMPLATE

After **every** prompt, write `reports/P<NN>-report.md` (NN = zero-padded prompt
number, e.g. `P01`, `P02`). Do not skip it, do not rename it, do not drop sections.
Use these exact section headings, in this order:

```markdown
# P<NN> — <short prompt title>

## Summary

<3–6 sentences: what was asked, what now exists, current state of the repo.>

## Files created/changed

| Path              | Status  | Purpose              |
| ----------------- | ------- | -------------------- |
| `path/to/file.ts` | created | one-line description |

## Decisions made and why

- **Decision.** Why it was made, and what was rejected.

## How to verify

<Exact commands in a fenced code block, each followed by the expected output
copied from an actual run. Copy-pasteable.>

## Test results

- Suite: N tests, N passed, 0 failed
- Coverage notes if relevant

## Problems or deviations from the prompt

<Anything that did not match the prompt, why, and the impact. "None" is a valid
answer — but only if it is true.>

## Ready for P<NN+1>? (yes/no and why)

<yes|no — one short justification, plus what P<NN+1> must know or build on.>
```

### 3.1 Report rules

- The report is committed together with the work it describes.
- "How to verify" must contain commands that actually work as written, with real
  expected output copied from the run — never invented output.
- "Problems or deviations" must not be silently omitted. Record dead ends, version
  pinning, and anything deferred to a later prompt.
- "Ready for P<NN+1>?" is a real gate. If the answer is `no`, state exactly what must
  be fixed before the next prompt starts.

```

```
