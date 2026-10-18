import { describe, expect, it } from 'vitest';

import { REPORT_SCHEMA, isDeepEqual, isReport, validateReport } from './index.js';
import { loadReportFixture } from './test-helpers.js';

function issuesFor(input: unknown): string[] {
  const result = validateReport(input);
  return result.ok ? [] : result.issues.map((issue) => `${issue.path} ${issue.message}`);
}

describe('hand-written example reports', () => {
  it('accepts the clean report', () => {
    expect(issuesFor(loadReportFixture('clean'))).toEqual([]);
  });

  it('accepts the report with vulnerabilities', () => {
    expect(issuesFor(loadReportFixture('with-vulnerabilities'))).toEqual([]);
  });

  it('narrows the type with isReport', () => {
    expect(isReport(loadReportFixture('clean'))).toBe(true);
    expect(isReport({})).toBe(false);
  });

  it('declares the schema version both fixtures use', () => {
    const clean = loadReportFixture('clean');
    const vulnerable = loadReportFixture('with-vulnerabilities');
    const declared = (REPORT_SCHEMA.properties?.['schemaVersion'] as { const: unknown }).const;

    expect(declared).toBe(2);
    expect(isDeepEqual((clean as { schemaVersion: unknown }).schemaVersion, declared)).toBe(true);
    expect(isDeepEqual((vulnerable as { schemaVersion: unknown }).schemaVersion, declared)).toBe(
      true,
    );
  });

  it('returns the parsed report unchanged, so the CLI can re-serialise it', () => {
    const input = loadReportFixture('with-vulnerabilities');
    const result = validateReport(input);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.report).toBe(input);
    }
  });

  it('covers a scan with no findings and a scan with four', () => {
    const clean = loadReportFixture('clean');
    const vulnerable = loadReportFixture('with-vulnerabilities');

    expect(isDeepEqual(clean, vulnerable)).toBe(false);
    expect(JSON.stringify(clean)).toContain('"totalVulnerabilities":0');
    expect(JSON.stringify(vulnerable)).toContain('"totalVulnerabilities":4');
  });
});
