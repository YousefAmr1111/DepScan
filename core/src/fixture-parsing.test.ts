import { describe, expect, it } from 'vitest';

import {
  buildTree,
  computeStats,
  packageId,
  parseNpm,
  parsePython,
  validateReport,
  type PackageEntry,
  type Report,
} from './index.js';
import {
  projectFixtureDir,
  readProjectFixtureFile,
  type ProjectFixtureName,
} from './test-helpers.js';

type Expectation = readonly [name: string, version: string, isDirect: boolean, depth: number];

const NPM_EXPECTATIONS: Readonly<
  Record<'clean-npm' | 'vulnerable-npm' | 'transitive-npm', readonly Expectation[]>
> = {
  'clean-npm': [
    ['ansi-styles', '4.3.0', false, 1],
    ['chalk', '4.1.2', true, 0],
    ['color-convert', '2.0.1', false, 2],
    ['color-name', '1.1.4', false, 3],
    ['debug', '4.3.4', true, 0],
    ['has-flag', '4.0.0', false, 2],
    ['lru-cache', '6.0.0', false, 1],
    ['ms', '2.1.2', false, 1],
    ['ms', '2.1.3', true, 0],
    ['semver', '7.6.0', true, 0],
    ['supports-color', '7.2.0', false, 1],
    ['yallist', '4.0.0', false, 2],
  ],
  'vulnerable-npm': [
    ['lodash', '4.17.20', true, 0],
    ['minimist', '1.2.5', true, 0],
    ['qs', '5.2.0', true, 0],
  ],
  'transitive-npm': [
    ['ansi-regex', '4.1.0', false, 1],
    ['strip-ansi', '5.2.0', true, 0],
  ],
};

const PYTHON_EXPECTATIONS: readonly Expectation[] = [
  ['PyYAML', '5.3.1', true, 0],
  ['chardet', '3.0.4', true, 0],
  ['requests', '2.19.1', true, 0],
  ['urllib3', '1.24.1', true, 0],
];

/** The numbers each EXPECTED.md promises, read back out of the markdown. */
function expectedNumbers(name: ProjectFixtureName): Readonly<Record<string, number>> {
  const markdown = readProjectFixtureFile(name, 'EXPECTED.md');
  const numbers: Record<string, number> = {};

  for (const match of markdown.matchAll(/`(stats\.\w+)`\s*\|\s*(\d+)/gu)) {
    const [, key = '', value = ''] = match;
    numbers[key] = Number.parseInt(value, 10);
  }

  return numbers;
}

function summary(packages: readonly PackageEntry[]): readonly Expectation[] {
  return packages.map((entry) => [entry.name, entry.version, entry.isDirect, entry.depth]);
}

function reportFor(packages: readonly PackageEntry[]): Report {
  const meta = {
    tool: { name: 'depscan' as const, version: '0.0.0-test' },
    generatedAt: '2026-10-08T00:00:00Z',
    projectName: 'fixture',
    ecosystem: 'npm' as const,
    manifestPath: 'package.json',
    unresolved: [],
    warnings: [],
  };

  return {
    schemaVersion: 2,
    meta,
    packages,
    vulnerabilities: [],
    risk: [],
    suggestions: [],
    stats: computeStats(packages, [], 0),
  };
}

describe.each(['clean-npm', 'vulnerable-npm', 'transitive-npm'] as const)(
  '%s matches its EXPECTED.md inventory',
  (name) => {
    const project = parseNpm(projectFixtureDir(name));

    it('lists the same packages, versions, direct flags and depths', () => {
      expect(summary(project.packages)).toEqual(NPM_EXPECTATIONS[name]);
    });

    it('agrees with the totals stated in EXPECTED.md', () => {
      const promised = expectedNumbers(name);
      const stats = computeStats(project.packages, []);

      expect(stats.totalPackages).toBe(promised['stats.totalPackages']);
      expect(stats.directPackages).toBe(promised['stats.directPackages']);
      expect(stats.transitivePackages).toBe(promised['stats.transitivePackages']);
    });

    it('produces packages that satisfy the report.json package schema', () => {
      const result = validateReport(reportFor(project.packages));

      expect(result.ok).toBe(true);
    });

    it('builds a tree with one root per direct dependency', () => {
      const tree = buildTree(project.packages);
      const direct = project.packages.filter((entry) => entry.isDirect).length;

      expect(tree.rootIds).toHaveLength(direct);
      expect(tree.nodes.size).toBe(project.packages.length);
    });
  },
);

describe('python-basic matches its EXPECTED.md inventory', () => {
  const project = parsePython(projectFixtureDir('python-basic'));

  it('lists the same packages, versions, direct flags and depths', () => {
    expect(summary(project.packages)).toEqual(PYTHON_EXPECTATIONS);
  });

  it('agrees with the totals stated in EXPECTED.md', () => {
    const promised = expectedNumbers('python-basic');
    const stats = computeStats(project.packages, []);

    expect(stats.totalPackages).toBe(promised['stats.totalPackages']);
    expect(stats.directPackages).toBe(promised['stats.directPackages']);
    expect(stats.transitivePackages).toBe(promised['stats.transitivePackages']);
  });

  it('produces packages that satisfy the report.json package schema', () => {
    const result = validateReport({
      ...reportFor(project.packages),
      meta: {
        tool: { name: 'depscan', version: '0.0.0-test' },
        generatedAt: '2026-10-08T00:00:00Z',
        projectName: 'python-basic',
        ecosystem: 'pypi',
        manifestPath: 'requirements.txt',
        unresolved: project.unresolved,
        warnings: project.warnings,
      },
    });

    expect(result.ok).toBe(true);
  });
});

describe('fixture package graphs are self-consistent', () => {
  it('never names a parent that is missing from the package list', () => {
    for (const name of ['clean-npm', 'vulnerable-npm', 'transitive-npm'] as const) {
      const project = parseNpm(projectFixtureDir(name));
      const known = new Set(project.packages.map((entry) => packageId(entry.name, entry.version)));

      for (const entry of project.packages) {
        for (const parent of entry.parents) {
          expect(known.has(parent)).toBe(true);
        }
      }
    }
  });

  it('gives every transitive package at least one parent and depth 1 or more', () => {
    for (const name of ['clean-npm', 'vulnerable-npm', 'transitive-npm'] as const) {
      for (const entry of parseNpm(projectFixtureDir(name)).packages) {
        if (!entry.isDirect) {
          expect(entry.parents.length).toBeGreaterThan(0);
          expect(entry.depth).toBeGreaterThanOrEqual(1);
        }
      }
    }
  });
});
