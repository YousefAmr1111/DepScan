import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const PROJECTS_DIR = fileURLToPath(new URL('../../fixtures/projects/', import.meta.url));

const NPM_FIXTURES = ['clean-npm', 'vulnerable-npm', 'transitive-npm'] as const;

const PYTHON_FIXTURES = ['python-basic'] as const;

const ALL_FIXTURES = [...NPM_FIXTURES, ...PYTHON_FIXTURES];

interface NpmManifest {
  readonly name: string;
  readonly dependencies: Readonly<Record<string, string>>;
  readonly overrides?: Readonly<Record<string, string>>;
}

interface NpmLockfile {
  readonly lockfileVersion: number;
  readonly packages: Readonly<Record<string, { readonly version?: string }>>;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

function projectDir(name: string): string {
  return join(PROJECTS_DIR, name);
}

function expectedMarkdown(name: string): string {
  return readFileSync(join(projectDir(name), 'EXPECTED.md'), 'utf8');
}

function npmManifest(name: string): NpmManifest {
  return readJson(join(projectDir(name), 'package.json')) as NpmManifest;
}

function npmLockfile(name: string): NpmLockfile {
  return readJson(join(projectDir(name), 'package-lock.json')) as NpmLockfile;
}

function directDependencies(name: string): Readonly<Record<string, string>> {
  return npmManifest(name).dependencies;
}

/** Every path under `dir`, so a stray installed tree can be detected. */
function pathsUnder(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    found.push(full);
    if (entry.isDirectory()) found.push(...pathsUnder(full));
  }
  return found;
}

describe('fixture projects', () => {
  it('ships exactly the four fixture projects', () => {
    expect(readdirSync(PROJECTS_DIR).sort()).toEqual([...ALL_FIXTURES].sort());
  });

  it.each(ALL_FIXTURES)('%s has an EXPECTED.md with content', (name) => {
    expect(existsSync(join(projectDir(name), 'EXPECTED.md'))).toBe(true);
    expect(expectedMarkdown(name).length).toBeGreaterThan(200);
  });

  it.each(ALL_FIXTURES)('%s states how it was verified', (name) => {
    expect(expectedMarkdown(name)).toContain('osv.dev');
    expect(expectedMarkdown(name)).not.toContain('UNVERIFIED');
  });

  it.each(ALL_FIXTURES)('%s has no installed dependencies', (name) => {
    const installed = pathsUnder(projectDir(name)).filter((path) =>
      path.includes(`${'node_modules'}`),
    );

    expect(installed).toEqual([]);
  });

  it.each(NPM_FIXTURES)('%s pins every direct dependency to an exact version', (name) => {
    const versions = Object.values(directDependencies(name));

    expect(versions.length).toBeGreaterThan(0);
    for (const version of versions) {
      expect(version).toMatch(/^\d+\.\d+\.\d+$/u);
    }
  });

  it.each(NPM_FIXTURES)('%s locks every direct dependency at the pinned version', (name) => {
    const lock = npmLockfile(name);

    expect(lock.lockfileVersion).toBe(3);
    for (const [dependency, pinned] of Object.entries(directDependencies(name))) {
      expect(lock.packages[`node_modules/${dependency}`]?.version).toBe(pinned);
    }
  });

  it.each(NPM_FIXTURES)('%s EXPECTED.md lists every direct dependency', (name) => {
    const markdown = expectedMarkdown(name);

    for (const [dependency, pinned] of Object.entries(directDependencies(name))) {
      expect(markdown).toContain(`${dependency}@${pinned}`);
    }
  });

  it.each(NPM_FIXTURES)('%s EXPECTED.md explains any npm overrides', (name) => {
    const overrides = npmManifest(name).overrides;

    if (overrides === undefined) {
      return;
    }
    expect(expectedMarkdown(name)).toContain('overrides');
    for (const version of Object.values(overrides)) {
      expect(expectedMarkdown(name)).toContain(version);
    }
  });

  it.each(PYTHON_FIXTURES)('%s pins every requirement exactly', (name) => {
    const lines = readFileSync(join(projectDir(name), 'requirements.txt'), 'utf8')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(line).toMatch(/^[A-Za-z0-9._-]+==[A-Za-z0-9._-]+$/u);
    }
  });

  it.each(PYTHON_FIXTURES)('%s EXPECTED.md lists every pinned requirement', (name) => {
    const markdown = expectedMarkdown(name);
    const pins = readFileSync(join(projectDir(name), 'requirements.txt'), 'utf8')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    for (const pin of pins) {
      expect(markdown).toContain(pin);
    }
  });
});
