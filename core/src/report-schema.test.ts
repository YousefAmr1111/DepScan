import { describe, expect, it } from 'vitest';

import { ECOSYSTEMS, REPORT_SCHEMA, validateJsonSchema, validateReport } from './index.js';
import { draftReport, loadReportFixture, omitProp, setProp } from './test-helpers.js';

function issuesFor(input: unknown): string[] {
  const result = validateReport(input);
  if (result.ok) {
    return [];
  }
  return result.issues.map((issue) => `${issue.path} ${issue.message}`);
}

/** Schema shape only, without the cross-section invariants validateReport adds. */
function schemaIssuesFor(input: unknown): string[] {
  return validateJsonSchema(input, REPORT_SCHEMA).map((issue) => `${issue.path} ${issue.message}`);
}

describe('report schema metadata', () => {
  it('declares JSON Schema draft 2020-12', () => {
    expect(REPORT_SCHEMA.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
  });

  it('pins schemaVersion to 2', () => {
    const report = draftReport('clean');
    setProp(report, 'schemaVersion', 1);

    expect(issuesFor(report)[0]).toContain('must be 2');
  });

  it('supports exactly the npm and pypi ecosystems', () => {
    expect(ECOSYSTEMS).toEqual(['npm', 'pypi']);
    expect(REPORT_SCHEMA.$defs?.meta?.properties?.ecosystem).toBeDefined();
  });
});

describe('report fixtures', () => {
  it('accepts the hand-written clean report', () => {
    expect(issuesFor(loadReportFixture('clean'))).toEqual([]);
  });

  it('accepts the hand-written report with vulnerabilities', () => {
    expect(issuesFor(loadReportFixture('with-vulnerabilities'))).toEqual([]);
  });

  it('models one ecosystem per fixture', () => {
    const clean = draftReport('clean');
    const vulnerable = draftReport('with-vulnerabilities');

    expect(clean.meta.ecosystem).toBe('npm');
    expect(vulnerable.meta.ecosystem).toBe('pypi');
  });
});

describe('meta validation', () => {
  it('requires the unresolved requirements array', () => {
    const report = draftReport('clean');
    omitProp(report.meta, 'unresolved');

    expect(issuesFor(report)[0]).toContain('missing required property "unresolved"');
  });

  it('requires the warnings array', () => {
    const report = draftReport('clean');
    omitProp(report.meta, 'warnings');

    expect(issuesFor(report)[0]).toContain('missing required property "warnings"');
  });

  it('accepts an unresolved requirement with a known reason', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'unresolved', [
      { raw: 'flask>=1.0', name: 'flask', specifier: '>=1.0', line: 3, reason: 'not-pinned' },
    ]);

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('rejects an unresolved requirement with an unknown reason', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'unresolved', [
      { raw: 'flask', name: 'flask', specifier: '', line: 1, reason: 'because' },
    ]);

    expect(issuesFor(report)[0]).toContain('/meta/unresolved/0/reason');
  });

  it('rejects an unresolved requirement with line zero', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'unresolved', [
      { raw: 'flask', name: 'flask', specifier: '', line: 0, reason: 'not-pinned' },
    ]);

    expect(issuesFor(report)[0]).toContain('/meta/unresolved/0/line');
  });

  it('rejects a warning that is not a string', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'warnings', [42]);

    expect(issuesFor(report)[0]).toContain('/meta/warnings/0');
  });

  it('requires the tool name to be depscan', () => {
    const report = draftReport('clean');
    setProp(report.meta.tool, 'name', 'other-scanner');

    expect(issuesFor(report)[0]).toContain('must be "depscan"');
  });

  it('requires an ISO-8601 UTC generatedAt', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'generatedAt', '2026-02-14 09:30');

    expect(issuesFor(report)[0]).toContain('/meta/generatedAt');
  });

  it('rejects unknown ecosystems', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'ecosystem', 'cargo');

    expect(issuesFor(report)[0]).toContain('must be one of "npm", "pypi"');
  });

  it('rejects a manifest path with backslashes', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'manifestPath', 'services\\api\\requirements.txt');

    expect(issuesFor(report)[0]).toContain('/meta/manifestPath');
  });
});

describe('package validation', () => {
  it('requires a name@version reference for every parent', () => {
    const report = draftReport('clean');
    setProp(report.packages[4], 'parents', ['cookie']);

    expect(issuesFor(report)[0]).toContain('/packages/4/parents/0');
  });

  it('rejects a negative depth', () => {
    const report = draftReport('clean');
    setProp(report.packages[0], 'depth', -1);

    expect(issuesFor(report)[0]).toContain('must be >= 0');
  });

  it('rejects duplicate aliases', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'aliases', ['GHSA-8q59-q68h-6hv4', 'GHSA-8q59-q68h-6hv4']);

    expect(issuesFor(report)[0]).toContain('must be unique');
  });
});

describe('vulnerability validation', () => {
  it('accepts the four documented severities only', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'severity', 'info');

    expect(issuesFor(report)[0]).toContain('must be one of "critical", "high", "medium", "low"');
  });

  it('rejects an advisory id that is neither CVE nor GHSA', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'id', 'DEP-0001');

    expect(issuesFor(report)[0]).toContain('/vulnerabilities/0/id');
  });

  it('accepts a null cvss score', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[3], 'cvss', null);

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('rejects a cvss score above ten', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'cvss', { score: 12, vector: 'CVSS:3.1/AV:N' });

    expect(issuesFor(report).some((issue) => issue.includes('must be <= 10'))).toBe(true);
  });

  it('rejects a fixedVersion that is neither a version nor null', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'fixedVersion', 54);

    expect(issuesFor(report)[0]).toContain('/vulnerabilities/0/fixedVersion');
  });

  it('accepts a null fixedVersion for an advisory with no patch', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'fixedVersion', null);

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('rejects an advisory url that is not https', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'advisoryUrl', 'http://example.com/advisory');

    expect(issuesFor(report)[0]).toContain('/vulnerabilities/0/advisoryUrl');
  });

  it('rejects an unknown property on a vulnerability', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.vulnerabilities[0], 'exploitAvailable', true);

    expect(issuesFor(report)[0]).toContain('unknown property "exploitAvailable"');
  });
});

describe('risk validation', () => {
  it('rejects a priority score outside 0-100', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.risk[0], 'priorityScore', 140);

    expect(issuesFor(report)[0]).toContain('must be <= 100');
  });

  it('rejects a fractional priority score', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.risk[0], 'priorityScore', 78.5);

    expect(issuesFor(report)[0]).toContain('must be integer');
  });

  it('requires at least one machine-readable reason', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.risk[0], 'reasons', []);

    expect(issuesFor(report)[0]).toContain('at least 1 items');
  });

  it('rejects a reason that is not machine-readable', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.risk[0], 'reasons', ['Because it is scary']);

    expect(issuesFor(report)[0]).toContain('must match');
  });

  it('rejects a risk flag set that omits hasFix', () => {
    const report = draftReport('with-vulnerabilities');
    omitProp(report.risk[0].flags, 'hasFix');

    expect(issuesFor(report)[0]).toContain('missing required property "hasFix"');
  });

  it('accepts a risk entry with no fix available', () => {
    const report = draftReport('with-vulnerabilities');
    report.risk[0].flags.hasFix = false;
    setProp(report.risk[0], 'reasons', ['direct-dependency', 'no-fix-available']);

    expect(schemaIssuesFor(report)).toEqual([]);
  });
});

describe('suggestion validation', () => {
  it('requires the provider marker so LLM output stays attributable', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.suggestions[0], 'provider', 'engine');

    expect(issuesFor(report)[0]).toContain('must be "llm"');
  });

  it('rejects a suggestion that offers neither a version nor an alternative', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.suggestions[0], 'saferVersion', null);
    setProp(report.suggestions[0], 'alternativePackage', null);

    expect(issuesFor(report)[0]).toContain('any of the allowed schemas');
  });

  it('accepts an alternative package instead of a version', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.suggestions[0], 'saferVersion', null);
    setProp(report.suggestions[0], 'alternativePackage', 'ruamel.yaml');

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('rejects an empty rationale', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.suggestions[0], 'rationale', '');

    expect(issuesFor(report)[0]).toContain('/suggestions/0/rationale');
  });
});

describe('package isDev', () => {
  it('accepts false for a production dependency', () => {
    const report = draftReport('clean');

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('accepts true for a development dependency', () => {
    const report = draftReport('clean');
    setProp(report.packages[0], 'isDev', true);

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('accepts null for an ecosystem with no dev distinction', () => {
    const report = draftReport('clean');
    setProp(report.packages[0], 'isDev', null);

    expect(schemaIssuesFor(report)).toEqual([]);
  });

  it('rejects a string isDev', () => {
    const report = draftReport('clean');
    setProp(report.packages[0], 'isDev', 'false');

    expect(schemaIssuesFor(report)[0]).toContain('/packages/0/isDev');
  });

  it('requires isDev on every package', () => {
    const report = draftReport('clean');
    omitProp(report.packages[0], 'isDev');

    expect(schemaIssuesFor(report)[0]).toContain('missing required property "isDev"');
  });
});

describe('stats validation', () => {
  it('requires unresolvedCount', () => {
    const report = draftReport('with-vulnerabilities');
    omitProp(report.stats, 'unresolvedCount');

    expect(schemaIssuesFor(report)[0]).toContain('missing required property "unresolvedCount"');
  });

  it('rejects an unresolvedCount that disagrees with meta.unresolved', () => {
    const report = draftReport('with-vulnerabilities');
    report.stats.unresolvedCount = 2;

    expect(issuesFor(report)[0]).toContain('/stats must match the report contents');
  });

  it('accepts an unresolvedCount that matches meta.unresolved', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.meta, 'unresolved', [
      { raw: 'flask>=1.0', name: 'flask', specifier: '>=1.0', line: 1, reason: 'not-pinned' },
    ]);
    report.stats.unresolvedCount = 1;

    expect(issuesFor(report)).toEqual([]);
  });

  it('requires all four severity counters', () => {
    const report = draftReport('with-vulnerabilities');
    omitProp(report.stats.bySeverity, 'low');

    expect(issuesFor(report)[0]).toContain('missing required property "low"');
  });

  it('rejects an unknown severity counter', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.stats.bySeverity, 'info', 0);

    expect(issuesFor(report)[0]).toContain('unknown property "info"');
  });

  it('rejects a negative total', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.stats, 'totalPackages', -1);

    expect(issuesFor(report)[0]).toContain('must be >= 0');
  });
});

describe('top-level shape', () => {
  it('requires every section', () => {
    const report = draftReport('clean');
    omitProp(report, 'stats');

    expect(issuesFor(report)[0]).toContain('missing required property "stats"');
  });

  it('rejects unknown top-level sections', () => {
    const report = draftReport('clean');
    setProp(report, 'llmNarrative', 'once upon a time');

    expect(issuesFor(report)[0]).toContain('unknown property "llmNarrative"');
  });

  it('rejects a value that is not an object at all', () => {
    expect(issuesFor('not a report')[0]).toContain('must be object');
  });
});
