import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { OsvCache } from './osv-cache.js';
import { cacheKeyFor } from './osv-cache.js';
import type { OsvHttp } from './osv-http.js';
import type { OsvQuery, OsvVulnerability } from './osv-types.js';
import type { Report } from './types.js';

export const PROJECTS_DIR = fileURLToPath(new URL('../../fixtures/projects/', import.meta.url));

export const OSV_RECORDINGS_DIR = fileURLToPath(new URL('../../fixtures/osv/', import.meta.url));

export type ReportFixtureName = 'clean' | 'with-vulnerabilities';

export type ProjectFixtureName = 'clean-npm' | 'vulnerable-npm' | 'transitive-npm' | 'python-basic';

export function projectFixtureDir(name: ProjectFixtureName): string {
  return join(PROJECTS_DIR, name);
}

export function readProjectFixtureFile(name: ProjectFixtureName, file: string): string {
  return readFileSync(join(projectFixtureDir(name), file), 'utf8');
}

/** Recursively removes `readonly` so a test can mutate a fixture in place. */
export type Mutable<T> = {
  -readonly [K in keyof T]: T[K] extends readonly (infer U)[]
    ? Mutable<U>[]
    : T[K] extends object
      ? Mutable<T[K]>
      : T[K];
};

export function loadReportFixture(name: ReportFixtureName): unknown {
  return JSON.parse(
    readFileSync(
      fileURLToPath(new URL(`../../fixtures/reports/${name}.json`, import.meta.url)),
      'utf8',
    ),
  ) as unknown;
}

/** A deep copy of a fixture that tests may corrupt on purpose. */
export function draftReport(name: ReportFixtureName): Mutable<Report> {
  return structuredClone(loadReportFixture(name)) as Mutable<Report>;
}

function asRecord(target: unknown): Record<string, unknown> {
  if (typeof target !== 'object' || target === null) {
    throw new TypeError('target must be an object');
  }
  return target as Record<string, unknown>;
}

/** Writes a property without fighting the readonly report types. */
export function setProp(target: unknown, key: string, value: unknown): void {
  asRecord(target)[key] = value;
}

export function omitProp(target: unknown, key: string): void {
  delete asRecord(target)[key];
}

const temporaryProjects: string[] = [];

/**
 * Writes a throwaway project to the OS temp directory. Used for the cases the committed
 * fixtures cannot cover, such as a malformed manifest or a lockfile v2.
 */
export function createTempProject(files: Readonly<Record<string, string>>): string {
  const dir = mkdtempSync(join(tmpdir(), 'depscan-'));
  temporaryProjects.push(dir);
  for (const [name, contents] of Object.entries(files)) {
    const path = join(dir, name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, contents, 'utf8');
  }
  return dir;
}

export function cleanupTempProjects(): void {
  for (const dir of temporaryProjects.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

interface RecordingEnvelope {
  readonly request: {
    readonly endpoint: string;
    readonly ecosystem: string;
    readonly name: string;
    readonly version: string;
  };
  readonly recordedAt: string;
  readonly response: { readonly vulns?: readonly OsvVulnerability[] };
}

export type OsvRecordings = ReadonlyMap<string, readonly OsvVulnerability[]>;

/**
 * The osv.dev responses recorded once for this repository. Tests must never touch the
 * network, so every matcher test is driven from these files.
 */
export function loadOsvRecordings(): OsvRecordings {
  const recordings = new Map<string, readonly OsvVulnerability[]>();

  for (const file of readdirSync(OSV_RECORDINGS_DIR)) {
    const envelope = JSON.parse(
      readFileSync(join(OSV_RECORDINGS_DIR, file), 'utf8'),
    ) as RecordingEnvelope;
    const key = cacheKeyFor({
      ecosystem: envelope.request.ecosystem,
      name: envelope.request.name,
      version: envelope.request.version,
    });
    recordings.set(key, envelope.response.vulns ?? []);
  }

  return recordings;
}

/** The date the recordings were taken, so a stale recording is obvious in test output. */
export function recordingDate(): string {
  const files = readdirSync(OSV_RECORDINGS_DIR).sort();
  const first = files[0];
  if (first === undefined) {
    throw new Error('no osv recordings found');
  }
  const envelope = JSON.parse(readFileSync(join(OSV_RECORDINGS_DIR, first), 'utf8')) as {
    readonly recordedAt: string;
  };
  return envelope.recordedAt.slice(0, 10);
}

/** An OsvHttp that answers from the recordings and fails loudly on anything unrecorded. */
export function recordingHttp(
  recordings: OsvRecordings,
  onQuery?: (query: OsvQuery) => void,
): OsvHttp {
  return {
    queryBatch(queries: readonly OsvQuery[]): Promise<readonly OsvVulnerability[][]> {
      return Promise.resolve(
        queries.map((query) => {
          onQuery?.(query);
          const vulns = recordings.get(cacheKeyFor(query));
          if (vulns === undefined) {
            throw new Error(`no recorded osv.dev response for ${cacheKeyFor(query)}`);
          }
          return vulns;
        }),
      );
    },
  };
}

/** Fills a cache with the recorded responses, as an earlier online run would have. */
export function seedCache(cache: OsvCache, recordings: OsvRecordings): void {
  for (const [key, vulns] of recordings) {
    const separator = key.lastIndexOf('@');
    const name = key.slice(key.indexOf('__') + 2, separator);
    cache.set(
      { ecosystem: key.slice(0, key.indexOf('__')), name, version: key.slice(separator + 1) },
      vulns,
    );
  }
}
