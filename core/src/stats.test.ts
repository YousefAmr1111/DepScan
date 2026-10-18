import { describe, expect, it } from 'vitest';

import { computeStats, countBySeverity, emptySeverityCounts } from './index.js';
import { draftReport } from './test-helpers.js';

describe('computeStats', () => {
  it('derives every total from the packages and vulnerabilities in the report', () => {
    const report = draftReport('with-vulnerabilities');

    expect(
      computeStats(report.packages, report.vulnerabilities, report.meta.unresolved.length),
    ).toEqual(report.stats);
  });

  it('mirrors the number of unresolved requirements', () => {
    expect(computeStats([], [], 3).unresolvedCount).toBe(3);
  });

  it('defaults unresolvedCount to zero', () => {
    expect(computeStats([], []).unresolvedCount).toBe(0);
  });

  it('counts direct and transitive packages separately', () => {
    const report = draftReport('clean');

    expect(report.stats.directPackages).toBe(2);
    expect(report.stats.transitivePackages).toBe(3);
    expect(report.stats.totalPackages).toBe(5);
  });

  it('counts vulnerabilities per severity', () => {
    const report = draftReport('with-vulnerabilities');

    expect(countBySeverity(report.vulnerabilities)).toEqual({
      critical: 1,
      high: 1,
      medium: 2,
      low: 0,
    });
  });

  it('returns all-zero stats for a report with nothing to report', () => {
    const report = draftReport('clean');

    expect(computeStats([], [])).toEqual({
      totalPackages: 0,
      directPackages: 0,
      transitivePackages: 0,
      totalVulnerabilities: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      unresolvedCount: 0,
    });
    expect(report.stats.totalVulnerabilities).toBe(0);
  });

  it('hands out an independent counter object every time', () => {
    const first = emptySeverityCounts();
    first.critical = 5;

    expect(emptySeverityCounts().critical).toBe(0);
  });
});
