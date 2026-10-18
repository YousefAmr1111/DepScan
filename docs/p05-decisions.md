# P05 decisions (fixed)

Decisions that are **already made** for P05. Implement them exactly as written. Each one
exists because the P03 fixtures prove the naive alternative produces the wrong answer.

This file is binding. If P05 needs to deviate, change this file first and say why in
`reports/P05-report.md`.

---

## 1. Severity mapping

Applied in this order, first match wins.

| Order | Source                                                         | Mapping                                                                  |
| ----- | -------------------------------------------------------------- | ------------------------------------------------------------------------ |
| 1     | GitHub rating (`database_specific.severity` in the OSV record) | `CRITICAL → critical`, `HIGH → high`, `MODERATE → medium`, `LOW → low`   |
| 2     | CVSS base score, when no GitHub rating is present              | `>= 9.0 → critical`, `7.0–8.9 → high`, `4.0–6.9 → medium`, `< 4.0 → low` |
| 3     | Neither available                                              | `low`, plus the reason code `severity_unknown`                           |

**Never invent a score.** If an advisory carries no rating and no CVSS vector, the severity
is `low` and the report says why. A guessed `critical` is indistinguishable from a real
one once it is in the report.

CVSS base score means the numeric score from the CVSS vector, not the vector string.

> **P05 deviation.** CVSS v3.0 and v3.1 are parsed and scored exactly. A CVSS **4.0**
> vector returns no score, so a record that only carries v4 falls through to case 3 and is
> reported as `low` with `severity_unknown`. The v4 base score is defined by a macrovector
> lookup table that cannot be derived from the vector string, and approximating it would be
> inventing a number. Six of the recorded fixture advisories are v4-only, and all six have a
> GitHub rating, so no fixture severity depends on this. Revisit when a trustworthy v4
> implementation is available.

### Risk coverage

`validateReport` requires one `risk` entry per vulnerability **only when the report contains
any risk entries**. An empty `risk` array is accepted and means priority scoring is not
implemented; a partially scored report is rejected. `matchVulnerabilities` therefore writes
no `risk` at all, and a consumer must not read `risk: []` as "no risk".

## 2. Id canonicalisation

- A finding's id is a **single CVE id** when the record names one. Every other identifier
  goes into `aliases`: `PYSEC-*`, `SNYK-*`, `CGA-*`, the other GHSA ids of a duplicated
  advisory, and so on — except the id of another finding, which is never repeated as an
  alias.
- Records that name **no** CVE are grouped by a shared GHSA id, and the group's id is the
  smallest GHSA id in it.
- If a record has **neither** a CVE nor a GHSA alias, report it as a **documented exception**
  in the scan output. Do not fail the whole run, and do not invent an id.

Why it matters: `Vulnerability.id` in the P02 schema only accepts `CVE-*` or `GHSA-*`, and
the `python-basic` fixture returns `PYSEC-2021-142` for CVE-2020-14343. An engine that
writes the PYSEC id produces a report that fails its own schema.

## 3. One row per (CVE id, package@version)

A finding is the pair **(CVE id, package@version)**. Not one row per OSV record, not one row
per package, and **never one row for two different CVEs**.

| Fixture        | OSV records returned | Rows expected in the report |
| -------------- | -------------------- | --------------------------- |
| clean-npm      | 0                    | 0                           |
| vulnerable-npm | 10                   | 10                          |
| transitive-npm | 1                    | 1                           |
| python-basic   | 38                   | 19                          |

> **P05b correction.** This section previously said one row per _canonical id_, which meant
> "first CVE alias". Two lodash advisories each name **two** CVE ids, so that rule folded
> CVE-2026-4800 into CVE-2021-23337 and CVE-2026-2950 into CVE-2025-13465, and the merged
> row carried a `fixedVersion` computed across two different vulnerabilities. A finding is
> now per CVE id, which is why vulnerable-npm moved from 8 rows to 10.

Why a merge is needed at all: PyPI returns every advisory twice (a GHSA record and a PYSEC
record for the same CVE), so those records must collapse. That merge happens through the
GHSA id, never through a shared first CVE.

### Merging records that name the same CVE

Only records that name the same CVE contribute to that CVE's finding. Within one finding:

- **severity** — the highest under §1, the conservative choice.
- **fixedVersion** — the lowest fixed version above the installed one, from those records
  only. `lodash@4.17.20` gives CVE-2021-23337 fixed in 4.17.21 and CVE-2025-13465 fixed in
  4.17.23, each computed without the other CVE's records.
- **affectedRange** — every range of those records that contains the installed version.
- **aliases** — the union of those records' identifiers, minus the finding's own id and minus
  the ids of sibling findings.

---

## What P05 must not do

- Do not write `suggestions`. The LLM layer owns that section, and
  `suggestions[].provider === 'llm'` is engine-forbidden.
- Do not compute `priorityScore` without a deterministic rule. If the scoring formula is
  not implemented, `risk` stays empty; an invented score is worse than none.
- Do not report a package that is not installed, and do not merge two installed versions
  of the same package. `clean-npm` installs `ms@2.1.2` and `ms@2.1.3` side by side.
- Do not take `depth` from lockfile paths. npm hoists; `color-name@1.1.4` sits at
  `node_modules/color-name` but is three hops from the manifest. Use the graph.
