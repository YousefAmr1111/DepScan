import { afterAll, describe, expect, it } from 'vitest';

import { isProjectParseError, packageId, parseNpm, parsePython } from './index.js';
import { cleanupTempProjects, createTempProject, projectFixtureDir } from './test-helpers.js';

afterAll(cleanupTempProjects);

function ids(packages: { readonly name: string; readonly version: string }[]): string[] {
  return packages.map((entry) => packageId(entry.name, entry.version));
}

const MANIFEST = JSON.stringify({
  name: 'fixture-temp',
  version: '1.0.0',
  dependencies: { a: '1.0.0' },
});

function lock(packages: Record<string, unknown>, lockfileVersion = 3): string {
  return JSON.stringify({
    name: 'fixture-temp',
    version: '1.0.0',
    lockfileVersion,
    requires: true,
    packages,
  });
}

describe('parseNpm against the fixture projects', () => {
  it('reads the project name from the manifest', () => {
    expect(parseNpm(projectFixtureDir('clean-npm')).projectName).toBe('fixture-clean-npm');
  });

  it('reports the manifest path as the project-relative package.json', () => {
    expect(parseNpm(projectFixtureDir('clean-npm')).manifestPath).toBe('package.json');
  });

  it('reads every installed package keyed by name@version', () => {
    expect(ids(parseNpm(projectFixtureDir('clean-npm')).packages)).toEqual([
      'ansi-styles@4.3.0',
      'chalk@4.1.2',
      'color-convert@2.0.1',
      'color-name@1.1.4',
      'debug@4.3.4',
      'has-flag@4.0.0',
      'lru-cache@6.0.0',
      'ms@2.1.2',
      'ms@2.1.3',
      'semver@7.6.0',
      'supports-color@7.2.0',
      'yallist@4.0.0',
    ]);
  });

  it('keeps both installed versions of ms as separate entries', () => {
    const ms = parseNpm(projectFixtureDir('clean-npm')).packages.filter(
      (entry) => entry.name === 'ms',
    );

    expect(ms).toHaveLength(2);
    expect(ms.map((entry) => `${entry.version}:${entry.isDirect}:${entry.depth}`)).toEqual([
      '2.1.2:false:1',
      '2.1.3:true:0',
    ]);
  });

  it('marks only manifest dependencies as direct', () => {
    const direct = parseNpm(projectFixtureDir('clean-npm'))
      .packages.filter((entry) => entry.isDirect)
      .map((entry) => packageId(entry.name, entry.version));

    expect(direct).toEqual(['chalk@4.1.2', 'debug@4.3.4', 'ms@2.1.3', 'semver@7.6.0']);
  });

  it('derives parents from the dependency graph', () => {
    const parents = parseNpm(projectFixtureDir('clean-npm'))
      .packages.filter((entry) => entry.parents.length > 0)
      .map((entry) => `${packageId(entry.name, entry.version)} <- ${entry.parents.join(',')}`);

    expect(parents).toEqual([
      'ansi-styles@4.3.0 <- chalk@4.1.2',
      'color-convert@2.0.1 <- ansi-styles@4.3.0',
      'color-name@1.1.4 <- color-convert@2.0.1',
      'has-flag@4.0.0 <- supports-color@7.2.0',
      'lru-cache@6.0.0 <- semver@7.6.0',
      'ms@2.1.2 <- debug@4.3.4',
      'supports-color@7.2.0 <- chalk@4.1.2',
      'yallist@4.0.0 <- lru-cache@6.0.0',
    ]);
  });

  it('computes depth as the shortest distance from the manifest, not from lockfile paths', () => {
    // color-name@1.1.4 lives at node_modules/color-name, hoisted, but is three hops deep.
    const byId = new Map(
      parseNpm(projectFixtureDir('clean-npm')).packages.map((entry) => [
        packageId(entry.name, entry.version),
        entry.depth,
      ]),
    );

    expect(byId.get('color-name@1.1.4')).toBe(3);
    expect(byId.get('ms@2.1.2')).toBe(1);
  });

  it('reports no orphans and no warnings for the fixture projects', () => {
    for (const name of ['clean-npm', 'vulnerable-npm', 'transitive-npm'] as const) {
      const project = parseNpm(projectFixtureDir(name));

      expect(project.orphans).toEqual([]);
      expect(project.warnings).toEqual([]);
    }
  });

  it('marks the vulnerable transitive package as transitive', () => {
    const [ansiRegex] = parseNpm(projectFixtureDir('transitive-npm')).packages.filter(
      (entry) => entry.name === 'ansi-regex',
    );

    expect(ansiRegex?.isDirect).toBe(false);
    expect(ansiRegex?.depth).toBe(1);
    expect(ansiRegex?.parents).toEqual(['strip-ansi@5.2.0']);
  });
});

describe('parseNpm lockfile handling', () => {
  it('supports lockfileVersion 2 and ignores the legacy dependencies section', () => {
    const dir = createTempProject({
      'package.json': MANIFEST,
      'package-lock.json': lock(
        {
          '': { name: 'fixture-temp', dependencies: { a: '1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { b: '1.0.0' } },
          'node_modules/b': { version: '1.0.0' },
        },
        2,
      ),
    });

    expect(ids(parseNpm(dir).packages)).toEqual(['a@1.0.0', 'b@1.0.0']);
  });

  it('treats devDependencies as direct dependencies', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({
        name: 'fixture-temp',
        devDependencies: { a: '1.0.0' },
      }),
      'package-lock.json': lock({
        '': { name: 'fixture-temp', devDependencies: { a: '1.0.0' } },
        'node_modules/a': { version: '1.0.0', dev: true },
      }),
    });

    expect(parseNpm(dir).packages[0]?.isDirect).toBe(true);
  });

  it('marks a dev-only lockfile entry as dev', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({
        name: 'fixture-temp',
        dependencies: { a: '1.0.0', b: '1.0.0' },
      }),
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0', b: '1.0.0' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/b': { version: '1.0.0', dev: true },
      }),
    });

    expect(parseNpm(dir).packages.map((entry) => `${entry.name}:${String(entry.isDev)}`)).toEqual([
      'a:false',
      'b:true',
    ]);
  });

  it('reports isDev null for a python requirement, which has no dev distinction', () => {
    const dir = createTempProject({ 'requirements.txt': 'requests==2.19.1\n' });

    expect(parsePython(dir).packages[0]?.isDev).toBeNull();
  });

  it('prefers the nested copy of a dependency over a hoisted one of the same name', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({
        name: 'fixture-temp',
        dependencies: { a: '1.0.0', b: '2.0.0' },
      }),
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0', b: '2.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { b: '1.0.0' } },
        'node_modules/b': { version: '2.0.0' },
        'node_modules/a/node_modules/b': { version: '1.0.0' },
      }),
    });

    const packages = parseNpm(dir).packages;

    expect(ids(packages)).toEqual(['a@1.0.0', 'b@1.0.0', 'b@2.0.0']);
    expect(packages.find((entry) => entry.version === '1.0.0' && entry.name === 'b')).toMatchObject(
      {
        isDirect: false,
        depth: 1,
        parents: ['a@1.0.0'],
      },
    );
    expect(packages.find((entry) => entry.name === 'b' && entry.version === '2.0.0')).toMatchObject(
      {
        isDirect: true,
        depth: 0,
      },
    );
  });

  it('merges two locations of the same version into one entry with both parents', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({
        name: 'fixture-temp',
        dependencies: { a: '1.0.0', b: '1.0.0' },
      }),
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0', b: '1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { shared: '1.0.0' } },
        'node_modules/b': { version: '1.0.0', dependencies: { shared: '1.0.0' } },
        'node_modules/shared': { version: '1.0.0' },
      }),
    });

    const shared = parseNpm(dir).packages.filter((entry) => entry.name === 'shared');

    expect(shared).toHaveLength(1);
    expect(shared[0]?.parents).toEqual(['a@1.0.0', 'b@1.0.0']);
  });

  it('reports an unreachable lockfile entry as an orphan', () => {
    const dir = createTempProject({
      'package.json': MANIFEST,
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/ghost': { version: '9.9.9' },
      }),
    });

    const project = parseNpm(dir);

    expect(project.orphans).toEqual(['ghost@9.9.9']);
    expect(ids(project.packages)).toEqual(['a@1.0.0']);
  });

  it('warns instead of failing when a manifest dependency is missing from the lockfile', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({
        name: 'fixture-temp',
        dependencies: { a: '1.0.0', gone: '1.0.0' },
      }),
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0' } },
        'node_modules/a': { version: '1.0.0' },
      }),
    });

    const project = parseNpm(dir);

    expect(project.warnings).toEqual(['manifest dependency "gone" is not in the lockfile']);
    expect(ids(project.packages)).toEqual(['a@1.0.0']);
  });

  it('warns when a dependency of a locked package is not installed', () => {
    const dir = createTempProject({
      'package.json': MANIFEST,
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { missing: '^1.0.0' } },
      }),
    });

    expect(parseNpm(dir).warnings).toEqual(['"missing" required by "a" is not installed']);
  });

  it('skips symlinked workspace entries that have no version of their own', () => {
    const dir = createTempProject({
      'package.json': MANIFEST,
      'package-lock.json': lock({
        '': { name: 'fixture-temp', dependencies: { a: '1.0.0' } },
        'node_modules/a': { version: '1.0.0' },
        'packages/local': { link: true, resolved: 'packages/local' },
      }),
    });

    expect(ids(parseNpm(dir).packages)).toEqual(['a@1.0.0']);
  });
});

describe('parseNpm typed errors', () => {
  it('reports a missing manifest', () => {
    const dir = createTempProject({ 'package-lock.json': lock({}) });

    expect(() => parseNpm(dir)).toThrowError(/missing-manifest/u);
  });

  it('reports a missing lockfile', () => {
    const dir = createTempProject({ 'package.json': MANIFEST });

    expect(() => parseNpm(dir)).toThrowError(/missing-lockfile/u);
  });

  it('exposes the code and path on the error', () => {
    const dir = createTempProject({ 'package.json': MANIFEST });

    try {
      parseNpm(dir);
      expect.unreachable('parseNpm should have thrown');
    } catch (error) {
      expect(isProjectParseError(error)).toBe(true);
      if (isProjectParseError(error)) {
        expect(error.code).toBe('missing-lockfile');
        expect(error.path).toContain('package-lock.json');
      }
    }
  });

  it('reports a manifest that is not valid JSON', () => {
    const dir = createTempProject({
      'package.json': '{ not json',
      'package-lock.json': lock({}),
    });

    expect(() => parseNpm(dir)).toThrowError(/malformed-manifest/u);
  });

  it('reports a manifest whose dependencies are not strings', () => {
    const dir = createTempProject({
      'package.json': JSON.stringify({ name: 'x', dependencies: { a: 1 } }),
      'package-lock.json': lock({}),
    });

    expect(() => parseNpm(dir)).toThrowError(/"dependencies\.a" must be a string/u);
  });

  it('reports a lockfile without a packages map', () => {
    const dir = createTempProject({
      'package.json': MANIFEST,
      'package-lock.json': JSON.stringify({ lockfileVersion: 3 }),
    });

    expect(() => parseNpm(dir)).toThrowError(/"packages" must be an object/u);
  });

  it('reports an unsupported lockfile version', () => {
    const dir = createTempProject({
      'package.json': MANIFEST,
      'package-lock.json': lock({ '': {} }, 1),
    });

    expect(() => parseNpm(dir)).toThrowError(/unsupported-lockfile-version/u);
  });
});
