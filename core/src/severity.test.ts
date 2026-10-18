import { describe, expect, it } from 'vitest';

import { SEVERITIES, compareSeverity, isSeverity, sortVulnerabilitiesBySeverity } from './index.js';

const vulnerability = (
  id: string,
  severity: (typeof SEVERITIES)[number],
): { id: string; severity: (typeof SEVERITIES)[number] } => ({ id, severity });

describe('severity primitives', () => {
  it('exposes exactly the four report severities in descending order', () => {
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low']);
  });

  it('recognises known severities and rejects unknown values', () => {
    expect(isSeverity('critical')).toBe(true);
    expect(isSeverity('info')).toBe(false);
  });

  it('sorts critical vulnerabilities before low ones', () => {
    const sorted = sortVulnerabilitiesBySeverity([
      vulnerability('a', 'low'),
      vulnerability('b', 'critical'),
      vulnerability('c', 'medium'),
    ]);

    expect(sorted.map((entry) => entry.id)).toEqual(['b', 'c', 'a']);
  });

  it('leaves the input array untouched while sorting', () => {
    const input = [vulnerability('a', 'low'), vulnerability('b', 'critical')];
    sortVulnerabilitiesBySeverity(input);

    expect(input.map((entry) => entry.id)).toEqual(['a', 'b']);
  });

  it('is stable for vulnerabilities that share a severity', () => {
    const sorted = sortVulnerabilitiesBySeverity([
      vulnerability('a', 'high'),
      vulnerability('b', 'high'),
    ]);

    expect(sorted.map((entry) => entry.id)).toEqual(['a', 'b']);
  });

  it('compares severities as a total order', () => {
    expect(compareSeverity('critical', 'low')).toBeLessThan(0);
    expect(compareSeverity('medium', 'medium')).toBe(0);
    expect(compareSeverity('low', 'high')).toBeGreaterThan(0);
  });
});
