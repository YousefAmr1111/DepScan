import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import {
  DEFAULT_CACHE_TTL_MS,
  cacheKeyFor,
  createFileCache,
  createMemoryCache,
  defaultCacheDir,
  isOsvCacheMissError,
  matchVulnerabilities,
  type OsvCacheLookup,
  type OsvCacheMissError,
} from './index.js';
import {
  cleanupTempProjects,
  createTempProject,
  loadOsvRecordings,
  recordingHttp,
  seedCache,
} from './test-helpers.js';

afterAll(cleanupTempProjects);

const QUERY = { ecosystem: 'npm', name: 'lodash', version: '4.17.20' } as const;
const RECORDED = [{ id: 'CVE-2021-23337', aliases: ['GHSA-35jh-r3h4-6jhm'] }];

function cacheIn(dir: string, now: () => number, ttlMs = DEFAULT_CACHE_TTL_MS) {
  return createFileCache({ dir, now, ttlMs });
}

function lookupFor(dir: string, now: () => number, ttlMs = DEFAULT_CACHE_TTL_MS): OsvCacheLookup {
  return cacheIn(dir, now, ttlMs).get(QUERY);
}

describe('cacheKeyFor', () => {
  it('names the ecosystem, package and version', () => {
    expect(cacheKeyFor(QUERY)).toBe('npm__lodash@4.17.20');
  });
});

describe('createFileCache', () => {
  it('returns a hit for an entry it just wrote', () => {
    const dir = createTempProject({});
    const cache = cacheIn(dir, () => 1_000_000);
    cache.set(QUERY, RECORDED);

    const lookup = cache.get(QUERY);
    expect(lookup.status).toBe('hit');
    expect(lookup.status === 'hit' ? lookup.vulns : []).toHaveLength(1);
  });

  it('stores the raw response next to when it was recorded', () => {
    const dir = createTempProject({});
    cacheIn(dir, () => 1_700_000_000_000).set(QUERY, RECORDED);

    const stored = JSON.parse(readFileSync(join(dir, 'npm__lodash@4.17.20.json'), 'utf8')) as {
      readonly recordedAt: number;
      readonly vulns: readonly unknown[];
      readonly key: string;
    };

    expect(stored.key).toBe('npm__lodash@4.17.20');
    expect(stored.recordedAt).toBe(1_700_000_000_000);
    expect(stored.vulns).toHaveLength(1);
  });

  it('reports a missing entry as absent', () => {
    expect(lookupFor(createTempProject({}), () => 0)).toEqual({ status: 'miss', reason: 'absent' });
  });

  it('reports an entry older than the ttl as expired', () => {
    const dir = createTempProject({});
    const ttlMs = 1000;
    cacheIn(dir, () => 0, ttlMs).set(QUERY, RECORDED);

    expect(lookupFor(dir, () => ttlMs + 1, ttlMs)).toEqual({ status: 'miss', reason: 'expired' });
  });

  it('still serves an entry that is exactly at the ttl', () => {
    const dir = createTempProject({});
    const ttlMs = 1000;
    cacheIn(dir, () => 0, ttlMs).set(QUERY, RECORDED);

    expect(lookupFor(dir, () => ttlMs, ttlMs).status).toBe('hit');
  });

  it('reports a corrupt entry as unreadable instead of crashing', () => {
    const dir = createTempProject({});
    writeFileSync(join(dir, 'npm__lodash@4.17.20.json'), '{ not json', 'utf8');

    expect(lookupFor(dir, () => 0)).toEqual({ status: 'miss', reason: 'unreadable' });
  });

  it('reports an entry without vulns as unreadable', () => {
    const dir = createTempProject({});
    writeFileSync(join(dir, 'npm__lodash@4.17.20.json'), '{"recordedAt":0}', 'utf8');

    expect(lookupFor(dir, () => 0)).toEqual({ status: 'miss', reason: 'unreadable' });
  });

  it('defaults to 24 hours', () => {
    expect(createFileCache().ttlMs).toBe(24 * 60 * 60 * 1000);
  });

  it('keeps the default cache directory under the user home', () => {
    expect(defaultCacheDir()).toMatch(/depscan/u);
  });
});

describe('createMemoryCache', () => {
  it('serves what was stored', () => {
    const cache = createMemoryCache({ 'npm__lodash@4.17.20': RECORDED });

    expect(cache.get(QUERY).status).toBe('hit');
    expect(cache.get({ ...QUERY, name: 'other' })).toEqual({ status: 'miss', reason: 'absent' });
  });
});

describe('matchVulnerabilities cache behaviour', () => {
  it('queries osv.dev only for packages that are not cached', async () => {
    const recordings = loadOsvRecordings();
    const cache = createMemoryCache();
    cache.set(
      { ecosystem: 'npm', name: 'minimist', version: '1.2.5' },
      recordings.get('npm__minimist@1.2.5') ?? [],
    );

    const asked: string[] = [];
    const findings = await matchVulnerabilities(
      [
        { name: 'lodash', version: '4.17.20', isDirect: true, depth: 0, parents: [], isDev: false },
        { name: 'minimist', version: '1.2.5', isDirect: true, depth: 0, parents: [], isDev: false },
      ],
      {
        ecosystem: 'npm',
        cache,
        http: recordingHttp(recordings, (q) => asked.push(cacheKeyFor(q))),
      },
    );

    expect(asked).toEqual(['npm__lodash@4.17.20']);
    expect(findings.map((finding) => finding.id)).toContain('CVE-2021-23337');
    expect(findings.map((finding) => finding.id)).toContain('CVE-2021-44906');
  });

  it('writes fetched responses into the cache for the next run', async () => {
    const recordings = loadOsvRecordings();
    const cache = cacheIn(createTempProject({}), () => 1_000_000);

    await matchVulnerabilities(
      [{ name: 'minimist', version: '1.2.5', isDirect: true, depth: 0, parents: [], isDev: false }],
      { ecosystem: 'npm', cache, http: recordingHttp(recordings) },
    );

    expect(cache.get({ ecosystem: 'npm', name: 'minimist', version: '1.2.5' }).status).toBe('hit');
  });

  it('makes no request at all when everything is cached', async () => {
    const recordings = loadOsvRecordings();
    const dir = createTempProject({});
    const cache = cacheIn(dir, () => 1_000_000);
    seedCache(cache, recordings);

    let calls = 0;
    const findings = await matchVulnerabilities(
      [{ name: 'lodash', version: '4.17.20', isDirect: true, depth: 0, parents: [], isDev: false }],
      {
        ecosystem: 'npm',
        cache,
        http: recordingHttp(recordings, () => {
          calls += 1;
        }),
      },
    );

    expect(calls).toBe(0);
    expect(findings).toHaveLength(5);
  });

  it('refuses to fall back to the network in offline mode', async () => {
    const recordings = loadOsvRecordings();
    let calls = 0;

    const error = await matchVulnerabilities(
      [{ name: 'lodash', version: '4.17.20', isDirect: true, depth: 0, parents: [], isDev: false }],
      {
        ecosystem: 'npm',
        offline: true,
        cache: createMemoryCache(),
        http: recordingHttp(recordings, () => {
          calls += 1;
        }),
      },
    ).catch((thrown: unknown) => thrown);

    expect(isOsvCacheMissError(error)).toBe(true);
    expect(error.missingKeys).toEqual(['npm__lodash@4.17.20']);
    expect(error.message).toContain('Run once online');
    expect(calls).toBe(0);
  });

  it('names every missing key when nothing is cached', async () => {
    const error = await matchVulnerabilities(
      [
        { name: 'lodash', version: '4.17.20', isDirect: true, depth: 0, parents: [], isDev: false },
        { name: 'qs', version: '5.2.0', isDirect: true, depth: 0, parents: [], isDev: false },
      ],
      {
        ecosystem: 'npm',
        offline: true,
        cache: createMemoryCache(),
        http: recordingHttp(new Map()),
      },
    ).catch((thrown: unknown) => thrown);

    expect((error as OsvCacheMissError).missingKeys).toEqual([
      'npm__lodash@4.17.20',
      'npm__qs@5.2.0',
    ]);
  });

  it('succeeds offline when the cache is warm', async () => {
    const recordings = loadOsvRecordings();
    const cache = createMemoryCache();
    seedCache(cache, recordings);

    const findings = await matchVulnerabilities(
      [
        {
          name: 'ansi-regex',
          version: '4.1.0',
          isDirect: false,
          depth: 1,
          parents: [],
          isDev: false,
        },
      ],
      { ecosystem: 'npm', offline: true, cache },
    );

    expect(findings.map((finding) => finding.id)).toEqual(['CVE-2021-3807']);
  });

  it('asks for one query per installed version, not per package name', async () => {
    const recordings = loadOsvRecordings();
    const asked: string[] = [];

    await matchVulnerabilities(
      [
        { name: 'ms', version: '2.1.2', isDirect: false, depth: 1, parents: [], isDev: false },
        { name: 'ms', version: '2.1.3', isDirect: true, depth: 0, parents: [], isDev: false },
      ],
      {
        ecosystem: 'npm',
        cache: createMemoryCache(),
        http: recordingHttp(recordings, (q) => asked.push(cacheKeyFor(q))),
      },
    );

    expect(asked).toEqual(['npm__ms@2.1.2', 'npm__ms@2.1.3']);
  });
});
