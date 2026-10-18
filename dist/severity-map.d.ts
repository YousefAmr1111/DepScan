import type { CvssScore, Severity } from './types.js';
/** Why a severity was chosen. Mirrors the order fixed in docs/p05-decisions.md. */
export type SeverityReason = 'github_rating' | 'cvss_base_score' | 'severity_unknown';
export interface SeverityDecision {
    readonly severity: Severity;
    readonly reason: SeverityReason;
    /** null when no CVSS vector could be turned into a base score. */
    readonly cvss: CvssScore | null;
}
export declare function severityFromGithubRating(rating: string | undefined): Severity | null;
/** Picks the first vector whose base score can actually be derived, preferring v3. */
export declare function cvssFromVectors(vectors: readonly string[]): CvssScore | null;
export declare function severityFromCvssScore(score: number): Severity;
/**
 * Severity for one advisory record, in the order fixed by docs/p05-decisions.md:
 * GitHub rating, then CVSS base score, then `low` with `severity_unknown`. A score is
 * never invented: without a rating and without a derivable score the result is low and the
 * reason says so.
 */
export declare function decideSeverity(githubRating: string | undefined, vectors: readonly string[]): SeverityDecision;
//# sourceMappingURL=severity-map.d.ts.map