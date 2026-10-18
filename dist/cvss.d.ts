/**
 * CVSS base score calculation, enough for severity mapping.
 *
 * v3.0 and v3.1 are implemented exactly, following the specification's constants and
 * `Roundup`. CVSS v4.0 returns `null`: its base score is defined by a macrovector lookup
 * table that cannot be derived from the vector string, and inventing a number would be
 * worse than reporting that the score is unavailable. See docs/p05-decisions.md.
 */
export type CvssVersion = '3.0' | '3.1' | '4.0';
export interface CvssVector {
    readonly version: CvssVersion;
    readonly metrics: Readonly<Record<string, string>>;
}
/** Parses a CVSS vector string. Returns null when the string is not a CVSS vector. */
export declare function parseCvssVector(vector: string): CvssVector | null;
/** The CVSS v3.0/v3.1 base score, or null when a required metric is missing. */
export declare function cvss3BaseScore(vector: CvssVector): number | null;
/**
 * Base score for any CVSS vector, or null when it cannot be derived. Callers must treat
 * null as "unknown", never as zero.
 */
export declare function cvssBaseScore(vector: string): number | null;
//# sourceMappingURL=cvss.d.ts.map