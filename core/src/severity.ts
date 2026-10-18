import { SEVERITIES, type Severity, type Vulnerability } from './types.js';

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

export function compareSeverity(left: Severity, right: Severity): number {
  return SEVERITY_RANK[left] - SEVERITY_RANK[right];
}

/** Returns a new array ordered by severity, most severe first. The input is untouched. */
export function sortVulnerabilitiesBySeverity<T extends Pick<Vulnerability, 'severity'>>(
  vulnerabilities: readonly T[],
): T[] {
  return [...vulnerabilities].sort((left, right) => compareSeverity(left.severity, right.severity));
}
