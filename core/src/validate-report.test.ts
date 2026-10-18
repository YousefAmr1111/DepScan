import { describe, expect, it } from 'vitest';

import { isReport, validateReport } from './index.js';
import { draftReport, loadReportFixture, setProp } from './test-helpers.js';

function issuesFor(input: unknown): string[] {
  const result = validateReport(input);
  return result.ok ? [] : result.issues.map((issue) => `${issue.path} ${issue.message}`);
}

describe('validateReport invariants', () => {
  it('returns the report untouched when it is valid', () => {
    const input = loadReportFixture('clean');
    const result = validateReport(input);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.report).toBe(input);
    }
  });

  it('rejects duplicate vulnerability ids', () => {
    const report = draftReport('with-vulnerabilities');
    report.vulnerabilities.push(structuredClone(report.vulnerabilities[0]));

    expect(issuesFor(report)).toContain(
      '/vulnerabilities contains duplicate vulnerability id "CVE-2020-14343"',
    );
  });

  it('rejects duplicate package entries', () => {
    const report = draftReport('clean');
    report.packages.push(structuredClone(report.packages[0]));

    expect(issuesFor(report)).toContain(
      '/packages contains duplicate package "body-parser@1.20.2"',
    );
  });

  it('rejects a package whose isDirect disagrees with its depth', () => {
    const report = draftReport('clean');
    report.packages[0].isDirect = false;

    expect(issuesFor(report)).toContain(
      '/packages/0 isDirect must be true exactly when depth is 0',
    );
  });

  it('rejects a report that looks clean while requirements are unresolved', () => {
    const report = draftReport('clean');
    setProp(report.meta, 'unresolved', [
      { raw: 'flask>=1.0', name: 'flask', specifier: '>=1.0', line: 1, reason: 'not-pinned' },
    ]);
    report.stats.unresolvedCount = 1;

    expect(issuesFor(report)).toEqual([
      '/meta/unresolved must not sit next to an empty vulnerabilities array: a scan with unresolved requirements has not checked everything and cannot be reported as clean',
    ]);
  });

  it('accepts an incomplete scan that still found something', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.meta, 'unresolved', [
      { raw: 'flask>=1.0', name: 'flask', specifier: '>=1.0', line: 1, reason: 'not-pinned' },
    ]);
    report.stats.unresolvedCount = 1;

    expect(issuesFor(report)).toEqual([]);
  });

  it('rejects a parents entry that is not in the package list', () => {
    const report = draftReport('clean');
    setProp(report.packages[2], 'parents', ['ghost@1.0.0']);

    expect(issuesFor(report)).toContain(
      '/packages/2/parents/0 references unknown package "ghost@1.0.0"',
    );
  });

  it('rejects a parents entry that names the right package at the wrong version', () => {
    const report = draftReport('clean');
    setProp(report.packages[2], 'parents', ['express@4.18.1']);

    expect(issuesFor(report)).toContain(
      '/packages/2/parents/0 references unknown package "express@4.18.1"',
    );
  });

  it('accepts a parents entry that is in the package list', () => {
    const report = draftReport('clean');

    expect(issuesFor(report)).toEqual([]);
  });

  it('rejects a risk entry for a vulnerability that does not exist', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.risk[0], 'vulnerabilityId', 'CVE-1999-00001');

    expect(issuesFor(report)).toContain('/risk references unknown vulnerability "CVE-1999-00001"');
  });

  it('rejects a partially scored report, where one risk entry is missing', () => {
    const report = draftReport('with-vulnerabilities');
    report.risk.pop();

    expect(issuesFor(report)).toContain('/risk is missing an entry for "CVE-2024-22195"');
  });

  it('accepts an empty risk section while priority scoring is not implemented', () => {
    const report = draftReport('with-vulnerabilities');
    report.risk.length = 0;

    expect(issuesFor(report)).toEqual([]);
  });

  it('rejects two risk entries for the same vulnerability', () => {
    const report = draftReport('with-vulnerabilities');
    report.risk.push(structuredClone(report.risk[0]));

    expect(issuesFor(report)).toContain('/risk contains duplicate entry for "CVE-2020-14343"');
  });

  it('rejects a suggestion for a vulnerability that does not exist', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report.suggestions[0], 'vulnerabilityId', 'CVE-1999-00002');

    expect(issuesFor(report)).toContain(
      '/suggestions references unknown vulnerability "CVE-1999-00002"',
    );
  });

  it('rejects duplicate suggestions for one vulnerability', () => {
    const report = draftReport('with-vulnerabilities');
    report.suggestions.push(structuredClone(report.suggestions[0]));

    expect(issuesFor(report)).toContain(
      '/suggestions contains duplicate entry for "CVE-2020-14343"',
    );
  });

  it('accepts a report with no suggestions at all', () => {
    const report = draftReport('with-vulnerabilities');
    report.suggestions.length = 0;

    expect(issuesFor(report)).toEqual([]);
  });

  it('rejects stats that disagree with the report contents', () => {
    const report = draftReport('with-vulnerabilities');
    report.stats.totalVulnerabilities = 9;

    expect(issuesFor(report)[0]).toContain('/stats must match the report contents');
  });

  it('rejects severity totals that do not add up', () => {
    const report = draftReport('with-vulnerabilities');
    report.stats.bySeverity.medium = 0;

    expect(issuesFor(report)[0]).toContain('/stats must match the report contents');
  });

  it('rejects stats that disagree about direct package counts', () => {
    const report = draftReport('clean');
    report.stats.directPackages = 3;

    expect(issuesFor(report)[0]).toContain('/stats must match the report contents');
  });

  it('reports every invariant violation at once', () => {
    const report = draftReport('with-vulnerabilities');
    report.risk.length = 1;
    report.stats.totalVulnerabilities = 1;

    expect(issuesFor(report)).toHaveLength(4);
  });

  it('stops at schema issues before checking invariants', () => {
    const report = draftReport('with-vulnerabilities');
    setProp(report, 'schemaVersion', 99);

    expect(issuesFor(report)).toEqual(['/schemaVersion must be 2']);
  });

  it('narrows the type only for a fully valid report', () => {
    const report = draftReport('clean');
    report.stats.totalPackages = 4;

    expect(isReport(report)).toBe(false);
    expect(isReport(draftReport('clean'))).toBe(true);
  });
});
