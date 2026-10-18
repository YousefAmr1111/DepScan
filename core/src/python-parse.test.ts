import { afterAll, describe, expect, it } from 'vitest';

import { normalizePythonName, packageId, parsePython } from './index.js';
import { cleanupTempProjects, createTempProject, projectFixtureDir } from './test-helpers.js';

afterAll(cleanupTempProjects);

function requirements(body: string): string {
  return createTempProject({ 'requirements.txt': body });
}

describe('parsePython against the python-basic fixture', () => {
  it('reads the project name from the directory name', () => {
    expect(parsePython(projectFixtureDir('python-basic')).projectName).toBe('python-basic');
  });

  it('reports the manifest path as the project-relative requirements.txt', () => {
    expect(parsePython(projectFixtureDir('python-basic')).manifestPath).toBe('requirements.txt');
  });

  it('reads every pinned requirement as a direct package at depth 0', () => {
    const packages = parsePython(projectFixtureDir('python-basic')).packages;

    expect(packages.map((entry) => packageId(entry.name, entry.version))).toEqual([
      'PyYAML@5.3.1',
      'chardet@3.0.4',
      'requests@2.19.1',
      'urllib3@1.24.1',
    ]);
    expect(packages.every((entry) => entry.isDirect && entry.depth === 0)).toBe(true);
  });

  it('reports no transitive packages, because a requirements file cannot resolve them', () => {
    expect(
      parsePython(projectFixtureDir('python-basic')).packages.every((e) => e.parents.length === 0),
    ).toBe(true);
  });

  it('reports nothing unresolved and no warnings', () => {
    const project = parsePython(projectFixtureDir('python-basic'));

    expect(project.unresolved).toEqual([]);
    expect(project.warnings).toEqual([]);
  });

  it('keeps the package name exactly as written in the manifest', () => {
    const project = parsePython(projectFixtureDir('python-basic'));

    expect(project.packages.find((entry) => entry.name === 'PyYAML')?.version).toBe('5.3.1');
  });
});

describe('parsePython unresolved requirements', () => {
  it('reports a version range instead of guessing', () => {
    const project = parsePython(requirements('flask>=1.0.2\n'));

    expect(project.packages).toEqual([]);
    expect(project.unresolved).toEqual([
      { raw: 'flask>=1.0.2', name: 'flask', specifier: '>=1.0.2', line: 1, reason: 'not-pinned' },
    ]);
  });

  it('reports a bare package name as not pinned', () => {
    expect(parsePython(requirements('requests\n')).unresolved[0]).toMatchObject({
      name: 'requests',
      specifier: '',
      reason: 'not-pinned',
    });
  });

  it('reports a wildcard pin as unresolved', () => {
    expect(parsePython(requirements('urllib3==1.26.*\n')).unresolved[0]).toMatchObject({
      name: 'urllib3',
      specifier: '==1.26.*',
      reason: 'wildcard-pin',
    });
  });

  it('reports multiple pins for one requirement as unresolved', () => {
    expect(parsePython(requirements('requests==2.19.1,==2.20.0\n')).unresolved[0]).toMatchObject({
      reason: 'multiple-pins',
    });
  });

  it('reports a direct URL reference as unresolved', () => {
    expect(
      parsePython(requirements('pkg @ https://example.com/pkg-1.0.tar.gz\n')).unresolved[0],
    ).toMatchObject({
      name: 'pkg',
      specifier: '@ https://example.com/pkg-1.0.tar.gz',
      reason: 'url-reference',
    });
  });

  it('reports an editable install as unresolved', () => {
    expect(parsePython(requirements('-e .\n')).unresolved[0]).toMatchObject({
      name: '',
      specifier: '.',
      reason: 'editable',
    });
  });

  it('reports an include directive as unresolved', () => {
    expect(parsePython(requirements('-r other.txt\n')).unresolved[0]).toMatchObject({
      reason: 'include-directive',
    });
  });

  it('reports an option line as unresolved', () => {
    expect(
      parsePython(requirements('--index-url https://example.com/simple\n')).unresolved[0],
    ).toMatchObject({
      name: '',
      reason: 'option-line',
    });
  });

  it('keeps the original line number for each unresolved requirement', () => {
    const project = parsePython(
      requirements('requests==2.19.1\n\nflask>=1.0\n# comment\nurllib3\n'),
    );

    expect(project.unresolved.map((entry) => entry.line)).toEqual([3, 5]);
  });

  it('ignores comments and blank lines', () => {
    const project = parsePython(requirements('# a comment\n\n   \nrequests==2.19.1\n'));

    expect(project.packages).toHaveLength(1);
    expect(project.unresolved).toEqual([]);
  });

  it('strips a trailing comment from a pinned requirement', () => {
    expect(
      parsePython(requirements('requests==2.19.1  # pinned by security\n')).packages,
    ).toHaveLength(1);
  });

  it('accepts extras and whitespace around a pin', () => {
    const project = parsePython(requirements('celery[redis] == 5.2.7\n'));

    expect(project.packages[0]).toMatchObject({ name: 'celery', version: '5.2.7' });
  });

  it('warns that an environment marker is ignored', () => {
    const project = parsePython(requirements('tomli==2.0.1 ; python_version < "3.11"\n'));

    expect(project.packages).toHaveLength(1);
    expect(project.warnings[0]).toContain('environment marker');
  });

  it('warns when the same pin appears twice', () => {
    const project = parsePython(requirements('requests==2.19.1\nrequests==2.19.1\n'));

    expect(project.packages).toHaveLength(1);
    expect(project.warnings).toEqual(['"requests@2.19.1" is pinned more than once']);
  });

  it('reports a missing requirements file as a typed error', () => {
    const dir = createTempProject({ 'README.md': 'nothing here' });

    expect(() => parsePython(dir)).toThrowError(/missing-requirements/u);
  });

  it('reports a line with no package name as malformed', () => {
    expect(() => parsePython(requirements('==1.0.0\n'))).toThrowError(/malformed-requirements/u);
  });

  it('never fails on a line it can partially read, it reports it as unresolved', () => {
    const project = parsePython(requirements('this is not a requirement\n'));

    expect(project.packages).toEqual([]);
    expect(project.unresolved[0]).toMatchObject({ name: 'this', reason: 'not-pinned' });
  });
});

describe('normalizePythonName', () => {
  it('lowercases a package name', () => {
    expect(normalizePythonName('PyYAML')).toBe('pyyaml');
  });

  it('collapses dashes, underscores and dots, which PyPI treats as equal', () => {
    expect(normalizePythonName('ruamel.yaml')).toBe('ruamel-yaml');
    expect(normalizePythonName('ruamel_yaml')).toBe('ruamel-yaml');
    expect(normalizePythonName('ruamel-yaml')).toBe('ruamel-yaml');
  });
});
