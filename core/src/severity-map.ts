import { cvssBaseScore } from './cvss.js';
import type { CvssScore, Severity } from './types.js';

/** Why a severity was chosen. Mirrors the order fixed in docs/p05-decisions.md. */
export type SeverityReason = 'github_rating' | 'cvss_base_score' | 'severity_unknown';

export interface SeverityDecision {
  readonly severity: Severity;
  readonly reason: SeverityReason;
  /** null when no CVSS vector could be turned into a base score. */
  readonly cvss: CvssScore | null;
}

const GITHUB_RATINGS: Readonly<Record<string, Severity>> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  LOW: 'low',
};

export function severityFromGithubRating(rating: string | undefined): Severity | null {
  if (rating === undefined) {
    return null;
  }
  return GITHUB_RATINGS[rating.trim().toUpperCase()] ?? null;
}

/** Picks the first vector whose base score can actually be derived, preferring v3. */
export function cvssFromVectors(vectors: readonly string[]): CvssScore | null {
  const ordered = [...vectors].sort((left, right) => {
    const leftV3 = left.startsWith('CVSS:3') ? 0 : 1;
    const rightV3 = right.startsWith('CVSS:3') ? 0 : 1;
    return leftV3 - rightV3;
  });

  for (const vector of ordered) {
    const score = cvssBaseScore(vector);
    if (score !== null) {
      return { score, vector };
    }
  }

  return null;
}

export function severityFromCvssScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Severity for one advisory record, in the order fixed by docs/p05-decisions.md:
 * GitHub rating, then CVSS base score, then `low` with `severity_unknown`. A score is
 * never invented: without a rating and without a derivable score the result is low and the
 * reason says so.
 */
export function decideSeverity(
  githubRating: string | undefined,
  vectors: readonly string[],
): SeverityDecision {
  const cvss = cvssFromVectors(vectors);

  const rating = severityFromGithubRating(githubRating);
  if (rating !== null) {
    return { severity: rating, reason: 'github_rating', cvss };
  }

  if (cvss !== null) {
    return {
      severity: severityFromCvssScore(cvss.score),
      reason: 'cvss_base_score',
      cvss,
    };
  }

  return { severity: 'low', reason: 'severity_unknown', cvss: null };
}
