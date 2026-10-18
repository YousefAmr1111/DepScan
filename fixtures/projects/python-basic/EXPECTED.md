# EXPECTED — python-basic

Ground truth for the `python-basic` fixture. Four pinned PyPI packages, three of them
carrying known advisories. A scan must find **19 distinct vulnerabilities** and must
report nothing for `chardet==3.0.4`.

## How this was verified

Each pinned version was queried against the OSV.dev API
(`POST https://api.osv.dev/v1/query`, `ecosystem: "PyPI"`) on **2026-10-08**, and each
advisory record was then fetched individually from `GET https://api.osv.dev/v1/vulns/{id}`
to read its ranges and severity. Nothing here is unverified. Severities are the GitHub
ratings OSV returns in `database_specific.severity`; mapping them onto the report enum is
an open engine decision, and `MODERATE` is expected to become `medium`.

## Files

- `requirements.txt` — four exact pins. There is no lockfile or hashes file, so a scan can
  only see these four packages. Transitive dependencies of `requests` (for example
  `urllib3`, which is also pinned here, or `certifi` and `chardet`) are not resolvable from
  a requirements file alone.

## Package inventory (4 packages, all direct)

| Pin in requirements.txt | Version | isDirect | Findings |
| ----------------------- | ------- | -------- | -------- |
| `PyYAML==5.3.1`         | 5.3.1   | true     | 1        |
| `requests==2.19.1`      | 2.19.1  | true     | 5        |
| `urllib3==1.24.1`       | 1.24.1  | true     | 13       |
| `chardet==3.0.4`        | 3.0.4   | true     | 0        |

## Expected advisories — PyYAML 5.3.1 (1 distinct, 2 OSV records)

| Canonical id   | Other ids                           | Affected range (PyPI/pyyaml) | Fixed in | Rating   | Why                                                                                               |
| -------------- | ----------------------------------- | ---------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------- |
| CVE-2020-14343 | GHSA-8q59-q68h-6hv4, PYSEC-2021-142 | `>=0 <5.4`                   | 5.4      | CRITICAL | Arbitrary code execution through `yaml.load`; CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

## Expected advisories — requests 2.19.1 (5 distinct, 10 OSV records)

| Canonical id   | Other ids                            | Affected range (PyPI/requests) | Fixed in | Rating   | Why                                                                                                             |
| -------------- | ------------------------------------ | ------------------------------ | -------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| CVE-2018-18074 | GHSA-x84v-xcm2-53pg, PYSEC-2018-28   | `>=0 <2.20.0`                  | 2.20.0   | HIGH     | Authorization header leaked to a third party on redirect; CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`   |
| CVE-2023-32681 | GHSA-j8r2-6x86-q33q, PYSEC-2023-74   | `>=2.3.0 <2.31.0`              | 2.31.0   | MODERATE | `Proxy-Authorization` header leaked on cross-host redirect; CVSS `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N` |
| CVE-2024-35195 | GHSA-9wx4-h78v-vm56, PYSEC-2026-1873 | `>=0 <2.32.0`                  | 2.32.0   | MODERATE | `verify=False` not re-verified after the first request; CVSS `CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N`     |
| CVE-2024-47081 | GHSA-9hjg-9r4m-mvj7, PYSEC-2026-1872 | `>=0 <2.32.4`                  | 2.32.4   | MODERATE | `.netrc` credentials leaked via a malicious URL; CVSS `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N`            |
| CVE-2026-25645 | GHSA-gc5v-m9x4-r6x2, PYSEC-2026-2275 | `>=0 <2.33.0`                  | 2.33.0   | MODERATE | Insecure temp-file reuse in `extract_zipped_paths`; CVSS `CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N`         |

## Expected advisories — urllib3 1.24.1 (13 distinct, 26 OSV records)

| Canonical id   | Other ids                            | Affected range (PyPI/urllib3)          | Fixed in | Rating   | Why                                                                                                                          |
| -------------- | ------------------------------------ | -------------------------------------- | -------- | -------- | ---------------------------------------------------------------------------------------------------------------------------- |
| CVE-2018-25091 | GHSA-gwvm-45gx-3cf8, PYSEC-2023-207  | `>=0 <1.24.2`                          | 1.24.2   | MODERATE | `Authorization` header forwarded on redirect; CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`                            |
| CVE-2019-11236 | GHSA-r64q-w8jr-g9qp, PYSEC-2019-132  | `>=0 <1.24.3`                          | 1.24.3   | MODERATE | CRLF injection in `request` method; CVSS `CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`                                      |
| CVE-2019-11324 | GHSA-mh33-7rrq-662w, PYSEC-2019-133  | `>=0 <1.24.2`                          | 1.24.2   | HIGH     | Improper certificate validation; CVSS `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`                                         |
| CVE-2020-26137 | GHSA-wqvq-5m8c-6g24, PYSEC-2020-148  | `>=0 <1.25.9`                          | 1.25.9   | MODERATE | CRLF injection in `urllib.request`; CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`                                      |
| CVE-2023-43804 | GHSA-v845-jxx5-vc9f, PYSEC-2023-192  | `>=0 <1.26.17` (also `>=2.0.0 <2.0.6`) | 1.26.17  | HIGH     | `Cookie` header not stripped on cross-origin redirects; CVSS `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N`                  |
| CVE-2023-45803 | GHSA-g4mx-q9vg-27p4, PYSEC-2023-212  | `>=0 <1.26.18` (also `>=2.0.0 <2.0.7`) | 1.26.18  | MODERATE | Request body not stripped after a 303 redirect; CVSS `CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N`                          |
| CVE-2024-37891 | GHSA-34jh-p97f-mpxf, PYSEC-2026-1995 | `>=0 <1.26.19` (also `>=2.0.0 <2.2.2`) | 1.26.19  | MODERATE | `Proxy-Authorization` not stripped on cross-origin redirect; CVSS `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N`             |
| CVE-2025-50181 | GHSA-pq67-6m6q-mj2v, PYSEC-2026-1999 | `>=0 <2.5.0`                           | 2.5.0    | MODERATE | Redirects not disabled when retries are off; CVSS `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`                             |
| CVE-2025-66418 | GHSA-gm62-xv2j-4w53, PYSEC-2026-1998 | `>=1.24 <2.6.0`                        | 2.6.0    | HIGH     | Unbounded number of links in the decompression chain; CVSS `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H` |
| CVE-2025-66471 | GHSA-2xpw-w6gg-jr37, PYSEC-2026-1994 | `>=1.0 <2.6.0`                         | 2.6.0    | HIGH     | Streaming API mishandles highly compressed data; CVSS `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H`      |
| CVE-2026-21441 | GHSA-38jv-5279-wg99, PYSEC-2026-1996 | `>=1.22 <2.6.3`                        | 2.6.3    | HIGH     | Decompression-bomb safeguards bypassed on redirect; CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`                      |
| CVE-2026-44431 | GHSA-qccp-gfcp-xxvc, PYSEC-2026-141  | `>=1.23 <2.7.0`                        | 2.7.0    | HIGH     | Sensitive headers forwarded across origins in proxied redirects; CVSS `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`         |
| CVE-2026-97689 | GHSA-vxq7-64xx-v4gw, PYSEC-2026-4177 | `>=1.10.3 <2.8.0`                      | 2.8.0    | HIGH     | Unbounded chunk-size line buffered in memory; CVSS `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H`         |

## Expected advisories — chardet 3.0.4

None. OSV returned no advisories for this version.

## Expected report numbers

| Field                        | Expected                                                     |
| ---------------------------- | ------------------------------------------------------------ |
| `stats.totalPackages`        | 4                                                            |
| `stats.directPackages`       | 4                                                            |
| `stats.transitivePackages`   | 0                                                            |
| `stats.totalVulnerabilities` | 19                                                           |
| `stats.bySeverity`           | critical 1, high 8, medium 10, low 0 (after MODERATE→medium) |

## Notes for the engine

- **PyPI doubles every advisory.** Each CVE comes back as a GHSA record _and_ a PYSEC
  record, so 38 OSV records resolve to 19 vulnerabilities. Any engine that treats OSV
  records as findings will report 38 and be wrong.
- **The report `id` pattern rejects `PYSEC-*`.** `Vulnerability.id` must be canonicalised
  to the `CVE-*` id (preferred) or the `GHSA-*` id, with the rest in `aliases`. An engine
  that writes `PYSEC-2021-142` as the id produces a report that fails its own schema.
- Multiple advisories for one installed version means `Vulnerability` is one row per
  (id, package) pair, not one row per package. The three affected packages yield 1 + 5 + 13
  rows.
- `ecosystem` for this fixture is `pypi` and `manifestPath` is `requirements.txt`.
- This fixture pins `urllib3` directly even though `requests` requires it, precisely so the
  analyzer has a version to compare against without a resolver.
