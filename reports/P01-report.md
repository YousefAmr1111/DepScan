# P01 — Repository layout repair and QA baseline

## Summary

The repository was audited against the proposal and the requested Youssef quality role. The monorepo configuration was repaired so the actual `core`, `cli`, and `dashboard` directories are recognised as workspace projects. The core and CLI packages now format, lint, and build successfully. The test runner starts correctly, but the suite remains red because the committed fixture corpus is incomplete: the `vulnerable-npm` project and report fixtures are missing, and `transitive-npm` is missing its manifest. The CLI analyze command and dashboard remain unimplemented, as assigned to other team roles.

## Files created/changed

| Path                                | Status  | Purpose                                                                          |
| ----------------------------------- | ------- | -------------------------------------------------------------------------------- |
| `pnpm-workspace.yaml`               | changed | Points pnpm at the actual root-level packages.                                   |
| `tsconfig.json`                     | changed | References the actual core and CLI build projects.                               |
| `core/tsconfig.json`                | changed | Uses the repository root TypeScript base config.                                 |
| `cli/tsconfig.json`                 | changed | Uses the repository root TypeScript base config.                                 |
| `eslint.config.js`                  | changed | Applies the untyped config override to both package Vitest configs.              |
| `core/src/fixture-projects.test.ts` | changed | Resolves committed fixture projects from the repository root.                    |
| `core/src/test-helpers.ts`          | changed | Resolves projects, OSV recordings, and report fixtures from the repository root. |
| `pnpm-lock.yaml`                    | changed | Refreshed for the repaired workspace layout.                                     |
| `reports/P01-report.md`             | created | Records this QA audit and baseline.                                              |

## Decisions made and why

- **Keep the existing root-level package layout.** The source folders are `core`, `cli`, and `dashboard`, so the workspace and TypeScript references were corrected to match the repository rather than moving files into a new `packages` directory.
- **Correct fixture paths instead of duplicating fixtures.** The committed fixtures already live under the repository-level `fixtures` directory; tests now reference that single source of truth.
- **Do not invent missing ground truth or report fixtures.** Their contents must be independently verified, which is part of Youssef's quality and evaluation responsibility.
- **Do not implement CLI or dashboard behaviour in this prompt.** The proposal assigns CLI integration to Fares and dashboard work to Mohamed.

## How to verify

```text
pnpm install --no-frozen-lockfile
Done in 3m 13s using pnpm v11.25.0

pnpm verify
Checking formatting...
All matched files use Prettier code style!
$ eslint .
$ pnpm -r run build
Scope: 3 of 4 workspace projects
$ tsc -b tsconfig.build.json
$ tsc -b tsconfig.build.json
$ pnpm -r run test
Scope: 3 of 4 workspace projects
$ vitest run
Test Files  8 failed | 9 passed (17)
Tests  113 failed | 214 passed (327)
```

## Test results

- Suite: 327 tests, 214 passed, 113 failed
- Format: passed
- Lint: passed
- Build: passed
- Main failure category: missing fixture projects and report JSON fixtures

## Problems or deviations from the prompt

The repository has no Git metadata, so this report cannot be committed as required by the project rules. The fixture corpus is incomplete: `fixtures/projects/vulnerable-npm` is absent, `fixtures/projects/transitive-npm/package.json` is absent, and `fixtures/reports/clean.json` plus `fixtures/reports/with-vulnerabilities.json` are absent. The CLI `analyze` command and dashboard are still placeholders. These are recorded for follow-up rather than silently filled with invented data.

## Ready for P02? (no and why)

no — the repository configuration is repaired, but the fixture corpus and report fixtures must be restored or created from independently verified evidence before the QA baseline can pass. P02 should resolve the missing fixture inputs and document their verification source.
