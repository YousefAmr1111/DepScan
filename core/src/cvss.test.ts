import { describe, expect, it } from 'vitest';

import { cvss3BaseScore, cvssBaseScore, parseCvssVector } from './index.js';

describe('parseCvssVector', () => {
  it('reads the version and metrics of a v3.1 vector', () => {
    const parsed = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

    expect(parsed?.version).toBe('3.1');
    expect(parsed?.metrics['AV']).toBe('N');
    expect(parsed?.metrics['S']).toBe('U');
  });

  it('recognises a v3.0 vector', () => {
    expect(parseCvssVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')?.version).toBe('3.0');
  });

  it('recognises a v4.0 vector', () => {
    expect(parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H')?.version).toBe(
      '4.0',
    );
  });

  it('rejects a string that is not a CVSS vector', () => {
    expect(parseCvssVector('MODERATE')).toBeNull();
  });
});

describe('cvssBaseScore', () => {
  it('scores the specification example 9.8', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('scores a scope-changed example 6.1', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(6.1);
  });

  it('scores an availability-only impact 7.5', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBe(7.5);
  });

  it('scores a local network vector 8.4', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(8.4);
  });

  it('treats changed privileges as higher risk in an unchanged scope', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H')).toBe(8.8);
  });

  it('caps the score at 10', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
  });

  it('scores a CVSS 3.0 vector with the same constants', () => {
    expect(cvssBaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('returns null for a CVSS 4.0 vector rather than guessing', () => {
    expect(
      cvssBaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'),
    ).toBeNull();
  });

  it('returns null for an unknown metric value', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
  });

  it('returns null when a required metric is missing', () => {
    expect(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toBeNull();
  });

  it('returns null for a string that is not a vector', () => {
    expect(cvssBaseScore('MODERATE')).toBeNull();
  });
});

describe('cvss3BaseScore', () => {
  it('refuses to score a v4 vector directly', () => {
    const parsed = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H');

    expect(parsed === null ? null : cvss3BaseScore(parsed)).toBeNull();
  });
});
