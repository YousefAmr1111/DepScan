import { describe, expect, it } from 'vitest';

import {
  countBySeverity,
  createMemoryCache,
  matchVulnerabilities,
  parseNpm,
  parsePython,
  validateReport,
  type Ecosystem,
  type Report,
  type Severity,
  type Vulnerability,
} from './index.js';
import {
  loadOsvRecordings,
  projectFixtureDir,
  readProjectFixtureFile,
  recordingDate,
  recordingHttp,
  seedCache,
  type ProjectFixtureName,
} from './test-helpers.js';

interface ExpectedAdvisory {
  readonly id: string;
  readonly otherIds: readonly string[];
  readonly fixedVersion: string | null;
  readonly rating: string;
}

const RATING_TO_SEVERITY: Readonly<Record<string, Severity>> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  LOW: 'low',
};

/**
 * The advisory tables in EXPECTED.md are the ground truth written by hand in P03. Reading
 * them here means a drift in the matcher fails against the document, not against a copy of
 * the document.
 */
function expectedAdvisories(fixture: ProjectFixtureName): ExpectedAdvisory[] {
  const rows: ExpectedAdvisory[] = [];

  for (const line of readProjectFixtureFile(fixture, 'EXPECTED.md').split('\n')) {
    const cells = line.split('|').map((cell) => cell.trim());
    const id = cells[1];
    if (id === undefined || !/^(CVE|GHSA)-\d/.test(id)) {
      continue;
    }
    const otherIds = (cells[2] ?? '')
      .split(',')
      .map((value) => value.trim().replaceAll('`', ''))
      .filter((value) => value.length > 0);
    const fixedCell = cells[4] ?? '';
    const version = /\d+(?:\.\d+)+/.exec(fixedCell.replaceAll('`', ''));
    rows.push({
      id,
      otherIds,
      fixedVersion: version === null ? null : version[0],
      rating: (cells[5] ?? '').toUpperCase(),
    });
  }

  return rows;
}

async function matchFixture(
  fixture: ProjectFixtureName,
  ecosystem: Ecosystem,
): Promise<readonly Vulnerability[]> {
  const project =
    ecosystem === 'npm'
      ? parseNpm(projectFixtureDir(fixture))
      : parsePython(projectFixtureDir(fixture));

  const recordings = loadOsvRecordings();
  const cache = createMemoryCache();
  seedCache(cache, recordings);

  return matchVulnerabilities(project.packages, {
    ecosystem,
    cache,
    offline: true,
    http: recordingHttp(recordings),
  });
}

function reportFrom(
  fixture: ProjectFixtureName,
  ecosystem: Ecosystem,
  findings: readonly Vulnerability[],
): Report {
  const packages =
    ecosystem === 'npm'
      ? parseNpm(projectFixtureDir(fixture)).packages
      : parsePython(projectFixtureDir(fixture)).packages;
  const manifestPath = ecosystem === 'npm' ? 'package.json' : 'requirements.txt';

  return {
    schemaVersion: 2,
    meta: {
      tool: { name: 'depscan', version: '0.0.0-test' },
      generatedAt: '2026-10-08T00:00:00Z',
      projectName: 'fixture',
      ecosystem,
      manifestPath,
      unresolved: [],
      warnings: [],
    },
    packages,
    vulnerabilities: [...findings],
    risk: [],
    suggestions: [],
    stats: {
      totalPackages: packages.length,
      directPackages: packages.filter((entry) => entry.isDirect).length,
      transitivePackages: packages.filter((entry) => !entry.isDirect).length,
      totalVulnerabilities: findings.length,
      bySeverity: countBySeverity(findings),
      unresolvedCount: 0,
    },
  };
}

const NPM_FIXTURES = ['clean-npm', 'vulnerable-npm', 'transitive-npm'] as const;

describe.each(NPM_FIXTURES)('%s matches its EXPECTED.md advisories', (fixture) => {
  it('finds exactly the advisories the ground truth lists', async () => {
    const findings = await matchFixture(fixture, 'npm');
    const expected = expectedAdvisories(fixture);

    expect([...findings.map((finding) => finding.id)].sort()).toEqual(
      expected.map((advisory) => advisory.id).sort(),
    );
  });

  it('agrees with every fixed version in the ground truth', async () => {
    const findings = await matchFixture(fixture, 'npm');

    for (const advisory of expectedAdvisories(fixture)) {
      const finding = findings.find((entry) => entry.id === advisory.id);
      expect(`${advisory.id}:${finding?.fixedVersion ?? 'null'}`).toBe(
        `${advisory.id}:${advisory.fixedVersion ?? 'null'}`,
      );
    }
  });

  it('agrees with every severity rating in the ground truth', async () => {
    const findings = await matchFixture(fixture, 'npm');

    for (const advisory of expectedAdvisories(fixture)) {
      const finding = findings.find((entry) => entry.id === advisory.id);
      expect(`${advisory.id}:${finding?.severity}`).toBe(
        `${advisory.id}:${RATING_TO_SEVERITY[advisory.rating] ?? 'unknown'}`,
      );
    }
  });

  it('puts every other identifier in aliases and never in id', async () => {
    const findings = await matchFixture(fixture, 'npm');

    for (const advisory of expectedAdvisories(fixture)) {
      const finding = findings.find((entry) => entry.id === advisory.id);
      for (const other of advisory.otherIds) {
        expect(finding?.aliases).toContain(other);
        expect(finding?.id).not.toBe(other);
      }
    }
  });

  it('produces a report that passes validateReport', async () => {
    const findings = await matchFixture(fixture, 'npm');
    const result = validateReport(reportFrom(fixture, 'npm', findings));

    expect(result.ok).toBe(true);
  });
});

describe('python-basic matches its EXPECTED.md advisories', () => {
  it('finds exactly the 19 advisories the ground truth lists', async () => {
    const findings = await matchFixture('python-basic', 'pypi');
    const expected = expectedAdvisories('python-basic');

    expect(expected).toHaveLength(19);
    expect([...findings.map((finding) => finding.id)].sort()).toEqual(
      expected.map((advisory) => advisory.id).sort(),
    );
  });

  it('produces the severity tally the ground truth promises', async () => {
    const findings = await matchFixture('python-basic', 'pypi');

    expect(countBySeverity(findings)).toEqual({
      critical: 1,
      high: 8,
      medium: 10,
      low: 0,
    });
  });

  it('agrees with every fixed version in the ground truth', async () => {
    const findings = await matchFixture('python-basic', 'pypi');

    for (const advisory of expectedAdvisories('python-basic')) {
      const finding = findings.find((entry) => entry.id === advisory.id);
      expect(`${advisory.id}:${finding?.fixedVersion ?? 'null'}`).toBe(
        `${advisory.id}:${advisory.fixedVersion ?? 'null'}`,
      );
    }
  });

  it('keeps every PYSEC identifier in aliases and never as the id', async () => {
    const findings = await matchFixture('python-basic', 'pypi');

    expect(findings.every((finding) => finding.id.startsWith('CVE-'))).toBe(true);
    const pysecAliases = findings.flatMap((finding) =>
      finding.aliases.filter((alias) => alias.startsWith('PYSEC-')),
    );
    expect(pysecAliases.length).toBeGreaterThan(0);
    expect(findings.some((finding) => finding.id.startsWith('PYSEC-'))).toBe(false);
  });

  it('produces a report that passes validateReport', async () => {
    const findings = await matchFixture('python-basic', 'pypi');

    expect(validateReport(reportFrom('python-basic', 'pypi', findings)).ok).toBe(true);
  });
});

describe('lodash@4.17.20 with the recorded osv.dev data', () => {
  it('reports five findings, one per distinct CVE', async () => {
    const findings = (await matchFixture('vulnerable-npm', 'npm')).filter(
      (finding) => finding.package === 'lodash',
    );

    expect(findings.map((finding) => finding.id).sort()).toEqual([
      'CVE-2020-28500',
      'CVE-2021-23337',
      'CVE-2025-13465',
      'CVE-2026-2950',
      'CVE-2026-4800',
    ]);
  });

  it('reports CVE-2021-23337 and CVE-2026-4800 as two separate findings', async () => {
    const findings = (await matchFixture('vulnerable-npm', 'npm')).filter(
      (finding) => finding.package === 'lodash',
    );

    expect(findings.filter((finding) => finding.id === 'CVE-2021-23337')).toHaveLength(1);
    expect(findings.filter((finding) => finding.id === 'CVE-2026-4800')).toHaveLength(1);
  });

  it('gives each of them its own fixedVersion from the records that name that CVE', async () => {
    const findings = await matchFixture('vulnerable-npm', 'npm');
    const fixed = (id: string): string | null =>
      findings.find((finding) => finding.id === id)?.fixedVersion ?? null;

    expect(fixed('CVE-2020-28500')).toBe('4.17.21');
    expect(fixed('CVE-2021-23337')).toBe('4.17.21');
    expect(fixed('CVE-2026-4800')).toBe('4.17.21');
    expect(fixed('CVE-2025-13465')).toBe('4.17.23');
    expect(fixed('CVE-2026-2950')).toBe('4.17.23');
  });

  it('never lists one finding id in another finding aliases', async () => {
    const findings = (await matchFixture('vulnerable-npm', 'npm')).filter(
      (finding) => finding.package === 'lodash',
    );
    const ids = findings.map((finding) => finding.id);

    for (const finding of findings) {
      expect(finding.aliases.filter((alias) => ids.includes(alias))).toEqual([]);
    }
  });

  it('keeps the GHSA ids as aliases of the CVE they belong to', async () => {
    const findings = (await matchFixture('vulnerable-npm', 'npm')).filter(
      (finding) => finding.package === 'lodash',
    );
    const aliasesOf = (id: string): readonly string[] =>
      findings.find((finding) => finding.id === id)?.aliases ?? [];

    expect(aliasesOf('CVE-2021-23337')).toEqual(['GHSA-35jh-r3h4-6jhm', 'GHSA-r5fr-rjxr-66jc']);
    expect(aliasesOf('CVE-2020-28500')).toEqual(['GHSA-29mw-wpgm-hmr9']);
  });
});

describe('distinct vulnerability counts promised by EXPECTED.md', () => {
  it.each([
    ['clean-npm', 'npm', 0],
    ['vulnerable-npm', 'npm', 10],
    ['transitive-npm', 'npm', 1],
    ['python-basic', 'pypi', 19],
  ] as const)('%s yields %i findings', async (fixture, ecosystem, count) => {
    expect(await matchFixture(fixture, ecosystem)).toHaveLength(count);
  });
});

describe('finding shape across every fixture', () => {
  it('fills every field the report schema requires', async () => {
    for (const [fixture, ecosystem] of [
      ['vulnerable-npm', 'npm'],
      ['transitive-npm', 'npm'],
      ['python-basic', 'pypi'],
    ] as const) {
      for (const finding of await matchFixture(fixture, ecosystem)) {
        expect(finding.id).toMatch(/^(CVE|GHSA)-/u);
        expect(finding.package.length).toBeGreaterThan(0);
        expect(finding.installedVersion.length).toBeGreaterThan(0);
        expect(finding.summary.length).toBeGreaterThan(0);
        expect(finding.affectedRange.length).toBeGreaterThan(0);
        expect(finding.source).toBe('osv.dev');
        expect(finding.advisoryUrl === null || finding.advisoryUrl.startsWith('https://')).toBe(
          true,
        );
      }
    }
  });

  it('names the transitive package, not the direct one', async () => {
    const findings = await matchFixture('transitive-npm', 'npm');

    expect(findings).toHaveLength(1);
    expect(findings[0]?.package).toBe('ansi-regex');
    expect(findings[0]?.installedVersion).toBe('4.1.0');
  });

  it('reports the PyPI package name as written in requirements.txt', async () => {
    const findings = await matchFixture('python-basic', 'pypi');

    expect(findings.map((finding) => finding.package)).toContain('PyYAML');
  });
});

describe('osv.dev recordings', () => {
  it('were taken on a single recorded date', () => {
    expect(recordingDate()).toBe('2026-10-08');
  });
});
