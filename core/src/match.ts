import { compareVersions } from './package-key.js';
import { createOsvHttp, type OsvHttp } from './osv-http.js';
import { createFileCache, OsvCacheMissError, cacheKeyFor, type OsvCache } from './osv-cache.js';
import type { OsvAffected, OsvEvent, OsvQuery, OsvVulnerability } from './osv-types.js';
import { decideSeverity, type SeverityDecision } from './severity-map.js';
import type { Ecosystem, PackageEntry, Severity, Vulnerability } from './types.js';
import { normalizePythonName } from './python-parse.js';

export const OSV_SOURCE = 'osv.dev';

/** Joins the several affected ranges of one advisory into one readable string. */
export const SEPARATOR = ' || ';

export interface UnidentifiedAdvisory {
  readonly package: string;
  readonly version: string;
  readonly recordId: string | null;
  readonly summary: string;
}

export interface MatchOptions {
  readonly ecosystem: Ecosystem;
  readonly http?: OsvHttp;
  readonly cache?: OsvCache;
  /** Read only the cache. A miss throws `OsvCacheMissError`. */
  readonly offline?: boolean;
  /** Called for every advisory record with neither a CVE nor a GHSA id. */
  readonly onUnidentifiedAdvisory?: (info: UnidentifiedAdvisory) => void;
}

/** The ecosystem name osv.dev uses, which is not the one the report uses. */
export function osvEcosystemName(ecosystem: Ecosystem): string {
  return ecosystem === 'pypi' ? 'PyPI' : 'npm';
}

/** The name to query with. PyPI treats `-`, `_` and `.` as equal and publishes normalised names. */
export function osvLookupName(ecosystem: Ecosystem, name: string): string {
  return ecosystem === 'pypi' ? normalizePythonName(name) : name;
}

/** Every CVE id a record names, its own id included. */
export function recordCveIds(record: OsvVulnerability): readonly string[] {
  return [record.id, ...(record.aliases ?? [])]
    .filter((id): id is string => typeof id === 'string' && id.startsWith('CVE-'))
    .filter((id, index, all) => all.indexOf(id) === index);
}

/** Every GHSA id a record names, its own id included. */
export function recordGhsaIds(record: OsvVulnerability): readonly string[] {
  return [record.id, ...(record.aliases ?? [])]
    .filter((id): id is string => typeof id === 'string' && id.startsWith('GHSA-'))
    .filter((id, index, all) => all.indexOf(id) === index);
}

interface RangeSegment {
  readonly from: string | null;
  readonly to: string | null;
  /** true for `fixed` (exclusive), false for `last_affected` or `limit` (inclusive). */
  readonly toIsExclusive: boolean;
}

function segmentsOf(events: readonly OsvEvent[]): RangeSegment[] {
  const segments: RangeSegment[] = [];
  let current: { from: string | null; to: string | null; toIsExclusive: boolean } | null = null;

  for (const event of events) {
    if (event.introduced !== undefined) {
      current = {
        from: event.introduced === '0' ? null : event.introduced,
        to: null,
        toIsExclusive: true,
      };
      segments.push(current);
      continue;
    }
    if (current === null) {
      current = { from: null, to: null, toIsExclusive: true };
      segments.push(current);
    }
    if (event.fixed !== undefined) {
      current.to = event.fixed;
      current.toIsExclusive = true;
    } else if (event.last_affected !== undefined) {
      current.to = event.last_affected;
      current.toIsExclusive = false;
    } else if (event.limit !== undefined) {
      current.to = event.limit;
      current.toIsExclusive = false;
    }
  }

  return segments;
}

function segmentMatches(segment: RangeSegment, version: string): boolean {
  if (segment.from !== null && compareVersions(version, segment.from) < 0) {
    return false;
  }
  if (segment.to === null) {
    return true;
  }
  const comparison = compareVersions(version, segment.to);
  return segment.toIsExclusive ? comparison < 0 : comparison <= 0;
}

function formatSegment(segment: RangeSegment): string {
  const lower = segment.from === null ? '>=0' : `>=${segment.from}`;
  if (segment.to === null) {
    return lower;
  }
  return `${lower} ${segment.toIsExclusive ? '<' : '<='}${segment.to}`;
}

function affectedEntriesFor(
  record: OsvVulnerability,
  ecosystem: string,
  name: string,
): readonly OsvAffected[] {
  return (record.affected ?? []).filter(
    (affected) =>
      (affected.package?.ecosystem ?? '').toLowerCase() === ecosystem.toLowerCase() &&
      (affected.package?.name ?? '').toLowerCase() === name.toLowerCase(),
  );
}

/**
 * Every range that contains the installed version, for the queried package. GIT ranges are
 * skipped: their `fixed` event is a commit sha, which is not a version a user can install.
 */
function matchingRanges(
  record: OsvVulnerability,
  ecosystem: string,
  name: string,
  version: string,
): readonly (readonly OsvEvent[])[] {
  const ranges: (readonly OsvEvent[])[] = [];

  for (const affected of affectedEntriesFor(record, ecosystem, name)) {
    for (const range of affected.ranges ?? []) {
      if (range.type === 'GIT') {
        continue;
      }
      const events = range.events ?? [];
      const segments = segmentsOf(events);
      if (segments.some((segment) => segmentMatches(segment, version))) {
        ranges.push(events);
      }
    }
  }

  return ranges;
}

/**
 * Every distinct segment that contains the installed version. Two OSV records for one
 * CVE usually repeat the same range, sometimes split differently, so segments are
 * collected and de-duplicated rather than whole range strings.
 */
function formatRanges(ranges: readonly (readonly OsvEvent[])[], version: string): string {
  const texts = new Set<string>();
  for (const events of ranges) {
    for (const segment of segmentsOf(events)) {
      if (segmentMatches(segment, version)) {
        texts.add(formatSegment(segment));
      }
    }
  }
  return [...texts].sort().join(SEPARATOR);
}

/** The lowest fixed version above the installed one, or null when there is no fix. */
function lowestFixedVersion(
  ranges: readonly (readonly OsvEvent[])[],
  version: string,
): string | null {
  const candidates = new Set<string>();

  for (const events of ranges) {
    for (const segment of segmentsOf(events)) {
      if (!segmentMatches(segment, version) || segment.to === null || !segment.toIsExclusive) {
        continue;
      }
      if (compareVersions(segment.to, version) > 0) {
        candidates.add(segment.to);
      }
    }
  }

  return [...candidates].sort(compareVersions)[0] ?? null;
}

const ADVISORY_URL_PRIORITY = ['ADVISORY', 'WEB'] as const;

function advisoryUrlFor(record: OsvVulnerability): string | null {
  for (const type of ADVISORY_URL_PRIORITY) {
    const match = (record.references ?? []).find(
      (reference) => reference.type === type && typeof reference.url === 'string',
    );
    if (match?.url !== undefined) {
      return match.url;
    }
  }
  return null;
}

function summaryFor(record: OsvVulnerability, id: string): string {
  const summary = record.summary?.trim();
  if (summary !== undefined && summary.length > 0) {
    return summary;
  }
  const details = record.details?.trim();
  if (details !== undefined && details.length > 0) {
    return details.length > 300 ? `${details.slice(0, 297)}...` : details;
  }
  return `No summary available for ${id}.`;
}

function severityRank(severity: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity];
}

/** Keeps the highest severity decision, and the CVSS score that came with it. */
function mergeDecisions(decisions: readonly SeverityDecision[]): SeverityDecision {
  const sorted = [...decisions].sort(
    (left, right) => severityRank(left.severity) - severityRank(right.severity),
  );
  const winner = sorted[0];
  if (winner !== undefined && winner.cvss !== null) {
    return winner;
  }
  return {
    ...(winner ?? { severity: 'low' satisfies Severity, reason: 'severity_unknown' }),
    cvss: null,
  };
}

interface FindingInput {
  readonly id: string;
  readonly records: readonly OsvVulnerability[];
  /** Canonical ids of the other findings for this package, so they are not repeated as aliases. */
  readonly siblingIds: ReadonlySet<string>;
  readonly packageName: string;
  readonly version: string;
  readonly ecosystem: string;
  readonly queryName: string;
}

function buildVulnerability(input: FindingInput): Vulnerability {
  const aliases = new Set<string>();
  const decisions: SeverityDecision[] = [];
  const ranges: (readonly OsvEvent[])[] = [];

  for (const record of input.records) {
    for (const alias of [record.id, ...(record.aliases ?? [])]) {
      if (
        typeof alias === 'string' &&
        alias.length > 0 &&
        alias !== input.id &&
        !input.siblingIds.has(alias)
      ) {
        aliases.add(alias);
      }
    }
    decisions.push(
      decideSeverity(
        typeof record.database_specific?.['severity'] === 'string'
          ? record.database_specific['severity']
          : undefined,
        (record.severity ?? [])
          .filter((entry) => typeof entry.score === 'string')
          .map((entry) => entry.score ?? ''),
      ),
    );
    ranges.push(...matchingRanges(record, input.ecosystem, input.queryName, input.version));
  }

  const merged = mergeDecisions(decisions);
  const preferred = input.records.find((record) => record.id === input.id) ?? input.records[0];

  return {
    id: input.id,
    aliases: [...aliases].sort(),
    package: input.packageName,
    installedVersion: input.version,
    severity: merged.severity,
    cvss: merged.cvss,
    summary: summaryFor(preferred ?? { id: input.id }, input.id),
    affectedRange: formatRanges(ranges, input.version) || 'unknown',
    fixedVersion: lowestFixedVersion(ranges, input.version),
    advisoryUrl: advisoryUrlFor(preferred ?? { id: input.id }),
    source: OSV_SOURCE,
  };
}

function sortFindings(left: Vulnerability, right: Vulnerability): number {
  const bySeverity = severityRank(left.severity) - severityRank(right.severity);
  if (bySeverity !== 0) return bySeverity;
  if (left.package !== right.package) return left.package < right.package ? -1 : 1;
  const byVersion = compareVersions(left.installedVersion, right.installedVersion);
  if (byVersion !== 0) return byVersion;
  return left.id.localeCompare(right.id);
}

/**
 * Groups records that carry no CVE by shared GHSA id: two records belong together when
 * they name a GHSA id in common, however many ids each carries. The group's id is the
 * smallest GHSA id in the component, so it does not depend on record order.
 */
function groupBySharedGhsa(records: readonly OsvVulnerability[]): Map<string, OsvVulnerability[]> {
  const parents = records.map((_record, index) => index);
  const find = (index: number): number => {
    let root = index;
    while (parents[root] !== root) {
      root = parents[root] ?? root;
    }
    return root;
  };
  const union = (left: number, right: number): void => {
    const a = find(left);
    const b = find(right);
    if (a !== b) {
      parents[b] = a;
    }
  };

  const byGhsa = new Map<string, number[]>();
  records.forEach((record, index) => {
    for (const ghsa of recordGhsaIds(record)) {
      byGhsa.set(ghsa, [...(byGhsa.get(ghsa) ?? []), index]);
    }
  });
  for (const indexes of byGhsa.values()) {
    for (const index of indexes.slice(1)) {
      union(indexes[0] ?? 0, index);
    }
  }

  const components = new Map<string, OsvVulnerability[]>();
  records.forEach((record, index) => {
    const members = components.get(String(find(index))) ?? [];
    members.push(record);
    components.set(String(find(index)), members);
  });

  const groups = new Map<string, OsvVulnerability[]>();
  for (const members of components.values()) {
    const id = members.flatMap(recordGhsaIds).sort()[0] ?? '';
    groups.set(id, [...(groups.get(id) ?? []), ...members]);
  }

  return groups;
}

/**
 * Groups the advisories for one installed package into findings.
 *
 * One finding per distinct CVE id. Records are never merged across different CVEs, even
 * when osv.dev attaches several CVE ids to the same advisory: CVE-2021-23337 and
 * CVE-2026-4800 are two vulnerabilities that osv.dev lists together, and each one computes
 * its own `fixedVersion` and `affectedRange` from only the records that name it. Records
 * that carry no CVE at all are grouped by a shared GHSA id instead, which is how the PyPI
 * GHSA and PYSEC copies of one advisory still collapse into a single finding.
 */
function findingsForPackage(
  entry: PackageEntry,
  ecosystem: Ecosystem,
  vulns: readonly OsvVulnerability[],
  onUnidentifiedAdvisory: ((info: UnidentifiedAdvisory) => void) | undefined,
): Vulnerability[] {
  const osvEcosystem = osvEcosystemName(ecosystem);
  const queryName = osvLookupName(ecosystem, entry.name);
  const groups = new Map<string, OsvVulnerability[]>();
  const withoutCve: OsvVulnerability[] = [];

  for (const record of vulns) {
    const cveIds = recordCveIds(record);

    if (cveIds.length > 0) {
      for (const cve of cveIds) {
        const existing = groups.get(cve) ?? [];
        existing.push(record);
        groups.set(cve, existing);
      }
      continue;
    }

    if (recordGhsaIds(record).length > 0) {
      withoutCve.push(record);
      continue;
    }

    onUnidentifiedAdvisory?.({
      package: entry.name,
      version: entry.version,
      recordId: typeof record.id === 'string' ? record.id : null,
      summary: summaryFor(record, 'this advisory'),
    });
  }

  for (const [id, records] of groupBySharedGhsa(withoutCve)) {
    groups.set(id, [...(groups.get(id) ?? []), ...records]);
  }

  const siblingIds = new Set(groups.keys());

  return [...groups.entries()].map(([id, records]) =>
    buildVulnerability({
      id,
      records,
      siblingIds,
      packageName: entry.name,
      version: entry.version,
      ecosystem: osvEcosystem,
      queryName,
    }),
  );
}

function queryFor(entry: PackageEntry, ecosystem: Ecosystem): OsvQuery {
  return {
    ecosystem: osvEcosystemName(ecosystem),
    name: osvLookupName(ecosystem, entry.name),
    version: entry.version,
  };
}

/**
 * Matches installed packages against osv.dev and returns findings in the report shape:
 * one row per (canonical id, package@version), sorted deterministically.
 */
export async function matchVulnerabilities(
  packages: readonly PackageEntry[],
  options: MatchOptions,
): Promise<readonly Vulnerability[]> {
  const cache = options.cache ?? createFileCache();
  const http = options.http ?? createOsvHttp();
  const offline = options.offline ?? false;

  const uniqueQueries = new Map<string, OsvQuery>();
  for (const entry of packages) {
    const query = queryFor(entry, options.ecosystem);
    uniqueQueries.set(cacheKeyFor(query), query);
  }

  const answers = new Map<string, readonly OsvVulnerability[]>();
  const missing: OsvQuery[] = [];

  for (const [key, query] of uniqueQueries) {
    const lookup = cache.get(query);
    if (lookup.status === 'hit') {
      answers.set(key, lookup.vulns);
    } else {
      missing.push(query);
    }
  }

  if (offline && missing.length > 0) {
    throw new OsvCacheMissError(missing.map(cacheKeyFor).sort());
  }

  if (missing.length > 0) {
    missing.sort((left, right) => cacheKeyFor(left).localeCompare(cacheKeyFor(right)));
    const fetched = await http.queryBatch(missing);

    missing.forEach((query, index) => {
      const vulns = fetched[index] ?? [];
      answers.set(cacheKeyFor(query), vulns);
      cache.set(query, vulns);
    });
  }

  const findings: Vulnerability[] = [];
  for (const entry of packages) {
    const key = cacheKeyFor(queryFor(entry, options.ecosystem));
    findings.push(
      ...findingsForPackage(
        entry,
        options.ecosystem,
        answers.get(key) ?? [],
        options.onUnidentifiedAdvisory,
      ),
    );
  }

  return findings.sort(sortFindings);
}
