import type { PackageEntry, ReportStats, Severity, Vulnerability } from './types.js';
export declare function emptySeverityCounts(): Record<Severity, number>;
export declare function countBySeverity(items: readonly Pick<Vulnerability, 'severity'>[]): Record<Severity, number>;
/**
 * Derives every stats field from the report contents. `unresolvedCount` comes from the
 * caller because it mirrors `meta.unresolved`, which is not part of the stats input.
 */
export declare function computeStats(packages: readonly PackageEntry[], vulnerabilities: readonly Vulnerability[], unresolvedCount?: number): ReportStats;
//# sourceMappingURL=stats.d.ts.map