import { describe, expect, it } from 'vitest';

import {
  cvssFromVectors,
  decideSeverity,
  severityFromCvssScore,
  severityFromGithubRating,
} from './index.js';

describe('severityFromGithubRating', () => {
  it('maps every GitHub rating', () => {
    expect(severityFromGithubRating('CRITICAL')).toBe('critical');
    expect(severityFromGithubRating('HIGH')).toBe('high');
    expect(severityFromGithubRating('MODERATE')).toBe('medium');
    expect(severityFromGithubRating('LOW')).toBe('low');
  });

  it('ignores casing and surrounding space', () => {
    expect(severityFromGithubRating(' high ')).toBe('high');
  });

  it('returns null for a rating it does not know', () => {
    expect(severityFromGithubRating('SEVERE')).toBeNull();
    expect(severityFromGithubRating(undefined)).toBeNull();
  });
});

describe('severityFromCvssScore', () => {
  it('applies the fixed bands', () => {
    expect(severityFromCvssScore(9.8)).toBe('critical');
    expect(severityFromCvssScore(9)).toBe('critical');
    expect(severityFromCvssScore(8.9)).toBe('high');
    expect(severityFromCvssScore(7)).toBe('high');
    expect(severityFromCvssScore(6.9)).toBe('medium');
    expect(severityFromCvssScore(4)).toBe('medium');
    expect(severityFromCvssScore(3.9)).toBe('low');
    expect(severityFromCvssScore(0)).toBe('low');
  });
});

describe('decideSeverity', () => {
  it('prefers the GitHub rating over a CVSS score', () => {
    const decision = decideSeverity('LOW', ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']);

    expect(decision.severity).toBe('low');
    expect(decision.reason).toBe('github_rating');
  });

  it('falls back to the CVSS base score when there is no rating', () => {
    const decision = decideSeverity(undefined, ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']);

    expect(decision.severity).toBe('critical');
    expect(decision.reason).toBe('cvss_base_score');
    expect(decision.cvss?.score).toBe(9.8);
  });

  it('falls back to low with severity_unknown and never invents a score', () => {
    const decision = decideSeverity(undefined, []);

    expect(decision).toEqual({ severity: 'low', reason: 'severity_unknown', cvss: null });
  });

  it('falls back to low with severity_unknown for a CVSS 4 only record', () => {
    const decision = decideSeverity(undefined, [
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
    ]);

    expect(decision.severity).toBe('low');
    expect(decision.reason).toBe('severity_unknown');
    expect(decision.cvss).toBeNull();
  });

  it('uses the v3 vector when a record also carries a v4 vector', () => {
    const decision = decideSeverity(undefined, [
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N',
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    ]);

    expect(decision.severity).toBe('critical');
    expect(decision.cvss?.vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });
});

describe('cvssFromVectors', () => {
  it('returns the score and the vector it came from', () => {
    expect(cvssFromVectors(['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'])).toEqual({
      score: 7.5,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    });
  });

  it('returns null when no vector can be scored', () => {
    expect(cvssFromVectors(['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H'])).toBeNull();
  });

  it('returns null for no vectors', () => {
    expect(cvssFromVectors([])).toBeNull();
  });
});
