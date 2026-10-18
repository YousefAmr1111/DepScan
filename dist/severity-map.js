import { cvssBaseScore } from './cvss.js';
const GITHUB_RATINGS = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MODERATE: 'medium',
    LOW: 'low',
};
export function severityFromGithubRating(rating) {
    if (rating === undefined) {
        return null;
    }
    return GITHUB_RATINGS[rating.trim().toUpperCase()] ?? null;
}
/** Picks the first vector whose base score can actually be derived, preferring v3. */
export function cvssFromVectors(vectors) {
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
export function severityFromCvssScore(score) {
    if (score >= 9)
        return 'critical';
    if (score >= 7)
        return 'high';
    if (score >= 4)
        return 'medium';
    return 'low';
}
/**
 * Severity for one advisory record, in the order fixed by docs/p05-decisions.md:
 * GitHub rating, then CVSS base score, then `low` with `severity_unknown`. A score is
 * never invented: without a rating and without a derivable score the result is low and the
 * reason says so.
 */
export function decideSeverity(githubRating, vectors) {
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
//# sourceMappingURL=severity-map.js.map