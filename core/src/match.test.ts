import { describe, expect, it } from 'vitest';

import {
  OSV_SOURCE,
  createMemoryCache,
  matchVulnerabilities,
  osvEcosystemName,
  osvLookupName,
  recordCveIds,
  recordGhsaIds,
  type OsvVulnerability,
  type UnidentifiedAdvisory,
} from './index.js';
import { loadOsvRecordings, recordingHttp } from './test-helpers.js';

function packageEntry(name: string, version: string) {
  return { name, version, isDirect: true, depth: 0, parents: [], isDev: false as const };
}

/** A synthetic advisory, so the rules can be tested without depending on recordings. */
function advisory(overrides: Partial<OsvVulnerability> = {}): OsvVulnerability {
  return {
    id: 'GHSA-35jh-r3h4-6jhm',
    aliases: ['CVE-2021-23337'],
    summary: 'Command injection in lodash',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      },
    ],
    references: [{ type: 'WEB', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }],
    ...overrides,
  };
}

async function match(records: readonly OsvVulnerability[], name = 'lodash', version = '4.17.20') {
  const cache = createMemoryCache();
  cache.set({ ecosystem: 'npm', name, version }, records);
  return matchVulnerabilities([packageEntry(name, version)], {
    ecosystem: 'npm',
    cache,
    offline: true,
  });
}

describe('osvEcosystemName', () => {
  it('uses the ecosystem name osv.dev expects', () => {
    expect(osvEcosystemName('npm')).toBe('npm');
    expect(osvEcosystemName('pypi')).toBe('PyPI');
  });
});

describe('osvLookupName', () => {
  it('normalises a PyPI name', () => {
    expect(osvLookupName('pypi', 'PyYAML')).toBe('pyyaml');
    expect(osvLookupName('pypi', 'ruamel.yaml')).toBe('ruamel-yaml');
  });

  it('leaves an npm name alone', () => {
    expect(osvLookupName('npm', 'lodash')).toBe('lodash');
  });
});

describe('recordCveIds', () => {
  it('reads every CVE a record names, without duplicates', () => {
    expect(
      recordCveIds({ id: 'GHSA-a', aliases: ['CVE-2021-23337', 'CVE-2026-4800', 'PYSEC-1'] }),
    ).toEqual(['CVE-2021-23337', 'CVE-2026-4800']);
  });

  it('includes a CVE that is the record id itself', () => {
    expect(recordCveIds({ id: 'CVE-2021-23337', aliases: [] })).toEqual(['CVE-2021-23337']);
  });

  it('returns an empty list for a record with no CVE', () => {
    expect(recordCveIds({ id: 'PYSEC-2021-142' })).toEqual([]);
  });
});

describe('recordGhsaIds', () => {
  it('reads the GHSA ids of a record', () => {
    expect(recordGhsaIds({ id: 'GHSA-a', aliases: ['CVE-2021-23337', 'GHSA-b'] })).toEqual([
      'GHSA-a',
      'GHSA-b',
    ]);
  });
});

describe('matchVulnerabilities record shape', () => {
  it('produces a finding in the report shape', async () => {
    const [finding] = await match([advisory()]);

    expect(finding).toMatchObject({
      id: 'CVE-2021-23337',
      aliases: ['GHSA-35jh-r3h4-6jhm'],
      package: 'lodash',
      installedVersion: '4.17.20',
      severity: 'high',
      affectedRange: '>=0 <4.17.21',
      fixedVersion: '4.17.21',
      advisoryUrl: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
      source: OSV_SOURCE,
      summary: 'Command injection in lodash',
    });
    expect(finding?.cvss?.score).toBe(7.2);
  });

  it('never puts the canonical id in its own aliases', async () => {
    const [finding] = await match([advisory()]);

    expect(finding?.aliases).not.toContain('CVE-2021-23337');
  });
});

describe('matchVulnerabilities range handling', () => {
  it('reports a range that contains the installed version', async () => {
    const [finding] = await match([
      advisory({
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'npm' },
            ranges: [
              {
                type: 'SEMVER',
                events: [
                  { introduced: '6.0.0' },
                  { fixed: '6.0.1' },
                  { introduced: '4.0.0' },
                  { fixed: '4.17.21' },
                ],
              },
            ],
          },
        ],
      }),
    ]);

    expect(finding?.affectedRange).toBe('>=4.0.0 <4.17.21');
  });

  it('ignores a range that does not contain the installed version', async () => {
    const [finding] = await match([
      advisory({
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '5.0.0' }, { fixed: '5.1.0' }] }],
          },
        ],
      }),
    ]);

    expect(finding?.affectedRange).toBe('unknown');
    expect(finding?.fixedVersion).toBeNull();
  });

  it('ignores GIT ranges, whose fixed event is a commit sha', async () => {
    const [finding] = await match([
      advisory({
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'npm' },
            ranges: [
              {
                type: 'GIT',
                events: [
                  { introduced: '0' },
                  { fixed: '3469357cff396a26c363f8c1b5a91dde28ba4b1c' },
                ],
              },
            ],
          },
        ],
      }),
    ]);

    expect(finding?.affectedRange).toBe('unknown');
    expect(finding?.fixedVersion).toBeNull();
  });

  it('ignores an affected entry for another ecosystem', async () => {
    const [finding] = await match([
      advisory({
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'PyPI' },
            ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }],
          },
        ],
      }),
    ]);

    expect(finding?.fixedVersion).toBeNull();
  });

  it('reports last_affected as an inclusive upper bound and no fix', async () => {
    const [finding] = await match(
      [
        advisory({
          affected: [
            {
              package: { name: 'lodash', ecosystem: 'npm' },
              ranges: [
                { type: 'SEMVER', events: [{ introduced: '4.0.0' }, { last_affected: '4.5.1' }] },
              ],
            },
          ],
        }),
      ],
      'lodash',
      '4.4.0',
    );

    expect(finding?.affectedRange).toBe('>=4.0.0 <=4.5.1');
    expect(finding?.fixedVersion).toBeNull();
  });
});

describe('matchVulnerabilities record identity', () => {
  const duplicate = advisory({
    id: 'GHSA-r5fr-rjxr-66jc',
    aliases: ['CVE-2021-23337'],
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.18.0' }] }],
      },
    ],
  });

  it('emits one row for two records naming the same CVE', async () => {
    expect(await match([advisory(), duplicate])).toHaveLength(1);
  });

  it('emits two rows when two records name different CVEs', async () => {
    const other = advisory({
      id: 'GHSA-other',
      aliases: ['CVE-2020-99999'],
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '5.0.0' }] }],
        },
      ],
    });

    expect(await match([advisory(), other])).toHaveLength(2);
  });

  it('gives each finding its own fixedVersion, taken only from records naming its CVE', async () => {
    const other = advisory({
      id: 'GHSA-other',
      aliases: ['CVE-2020-99999'],
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '5.0.0' }] }],
        },
      ],
    });

    const findings = await match([advisory(), duplicate, other]);

    expect(
      findings.map((finding) => `${finding.id}:${finding.fixedVersion ?? 'null'}`).sort(),
    ).toEqual(['CVE-2020-99999:5.0.0', 'CVE-2021-23337:4.17.21']);
  });

  it('emits one row per CVE when a single record names two of them', async () => {
    const twoCves = advisory({
      id: 'GHSA-two',
      aliases: ['CVE-2021-23337', 'CVE-2026-4800'],
    });

    const findings = await match([twoCves]);

    expect(findings.map((finding) => finding.id)).toEqual(['CVE-2021-23337', 'CVE-2026-4800']);
  });

  it('never lists one finding id inside another finding aliases', async () => {
    const twoCves = advisory({
      id: 'GHSA-two',
      aliases: ['CVE-2021-23337', 'CVE-2026-4800'],
    });

    for (const finding of await match([twoCves])) {
      expect(finding.aliases).toEqual(['GHSA-two']);
    }
  });

  it('groups records without a CVE by a shared GHSA id', async () => {
    const ghsaTwin = {
      id: 'GHSA-b',
      aliases: ['GHSA-a', 'PYSEC-1'],
      summary: 'no cve here',
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
        },
      ],
    };
    const primary = { ...ghsaTwin, id: 'GHSA-a', aliases: ['GHSA-b', 'PYSEC-2'] };

    const findings = await match([primary, ghsaTwin]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe('GHSA-a');
  });

  it('unions the aliases of two records naming the same CVE', async () => {
    const [finding] = await match([advisory(), duplicate]);

    expect(finding?.aliases).toEqual(['GHSA-35jh-r3h4-6jhm', 'GHSA-r5fr-rjxr-66jc']);
  });

  it('takes the lowest fixed version above the installed one within one finding', async () => {
    const [finding] = await match([advisory(), duplicate]);

    expect(finding?.fixedVersion).toBe('4.17.21');
  });

  it('keeps both ranges of the records that name its CVE', async () => {
    const [finding] = await match([advisory(), duplicate]);

    expect(finding?.affectedRange).toBe('>=0 <4.17.21 || >=4.0.0 <4.18.0');
  });

  it('takes the highest severity among the records of one finding', async () => {
    const lowTwin = advisory({
      id: 'PYSEC-2021-142',
      aliases: ['CVE-2021-23337'],
      database_specific: { severity: 'MODERATE' },
    });

    const [finding] = await match([lowTwin, advisory()]);

    expect(finding?.severity).toBe('high');
  });
});

describe('matchVulnerabilities advisories without a usable id', () => {
  it('reports an advisory with neither CVE nor GHSA instead of inventing an id', async () => {
    const reported: UnidentifiedAdvisory[] = [];
    const cache = createMemoryCache();
    cache.set({ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, [
      { id: 'PYSEC-2021-142', summary: 'No CVE or GHSA for this one' },
    ]);

    const findings = await matchVulnerabilities([packageEntry('lodash', '4.17.20')], {
      ecosystem: 'npm',
      cache,
      offline: true,
      onUnidentifiedAdvisory: (info) => reported.push(info),
    });

    expect(findings).toEqual([]);
    expect(reported).toEqual([
      {
        package: 'lodash',
        version: '4.17.20',
        recordId: 'PYSEC-2021-142',
        summary: 'No CVE or GHSA for this one',
      },
    ]);
  });
});

describe('matchVulnerabilities severity and ordering', () => {
  function cacheWith(records: readonly OsvVulnerability[]) {
    const cache = createMemoryCache();
    cache.set({ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, records);
    return cache;
  }

  it('returns the most severe findings first', async () => {
    const cache = cacheWith([
      advisory({
        id: 'GHSA-a',
        aliases: ['CVE-2020-11111'],
        database_specific: { severity: 'LOW' },
      }),
      advisory({
        id: 'GHSA-b',
        aliases: ['CVE-2020-22222'],
        database_specific: { severity: 'CRITICAL' },
      }),
      advisory({
        id: 'GHSA-c',
        aliases: ['CVE-2020-33333'],
        database_specific: { severity: 'HIGH' },
      }),
    ]);

    const findings = await matchVulnerabilities([packageEntry('lodash', '4.17.20')], {
      ecosystem: 'npm',
      cache,
      offline: true,
    });

    expect(findings.map((finding) => finding.severity)).toEqual(['critical', 'high', 'low']);
  });

  it('ignores a rating it does not recognise and falls back to the CVSS score', async () => {
    const cache = cacheWith([
      advisory({
        id: 'GHSA-a',
        aliases: ['CVE-2020-11111'],
        database_specific: { severity: 'SEVERE' },
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      }),
    ]);

    const [finding] = await matchVulnerabilities([packageEntry('lodash', '4.17.20')], {
      ecosystem: 'npm',
      cache,
      offline: true,
    });

    expect(finding?.severity).toBe('critical');
    expect(finding?.cvss?.score).toBe(9.8);
  });

  it('reports low for an advisory with no rating and no score, without inventing one', async () => {
    const cache = cacheWith([
      {
        id: 'GHSA-a',
        aliases: ['CVE-2020-11111'],
        summary: 'no score anywhere',
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
          },
        ],
      },
    ]);

    const [finding] = await matchVulnerabilities([packageEntry('lodash', '4.17.20')], {
      ecosystem: 'npm',
      cache,
      offline: true,
    });

    expect(finding?.severity).toBe('low');
    expect(finding?.cvss).toBeNull();
  });
});

describe('matchVulnerabilities against a PyPI recording', () => {
  it('matches on the normalised name and reports the name as written', async () => {
    const recordings = loadOsvRecordings();
    const findings = await matchVulnerabilities([packageEntry('PyYAML', '5.3.1')], {
      ecosystem: 'pypi',
      cache: createMemoryCache(),
      http: recordingHttp(recordings),
    });

    expect(findings.map((finding) => finding.id)).toEqual(['CVE-2020-14343']);
    expect(findings[0]?.package).toBe('PyYAML');
    expect(findings[0]?.aliases).toContain('PYSEC-2021-142');
  });
});
