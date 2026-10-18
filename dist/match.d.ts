import { type OsvHttp } from './osv-http.js';
import { type OsvCache } from './osv-cache.js';
import type { OsvVulnerability } from './osv-types.js';
import type { Ecosystem, PackageEntry, Vulnerability } from './types.js';
export declare const OSV_SOURCE = "osv.dev";
/** Joins the several affected ranges of one advisory into one readable string. */
export declare const SEPARATOR = " || ";
export interface UnidentifiedAdvisory {
    readonly package: string;
    readonly version: string;
    readonly recordId: string | null;
    readonly summary: string;
}
export interface MatchOptions {
    readonly ecosystem: Ecosystem;
    readonly http?: OsvHttp;
    readonly cache?: OsvCache;
    /** Read only the cache. A miss throws `OsvCacheMissError`. */
    readonly offline?: boolean;
    /** Called for every advisory record with neither a CVE nor a GHSA id. */
    readonly onUnidentifiedAdvisory?: (info: UnidentifiedAdvisory) => void;
}
/** The ecosystem name osv.dev uses, which is not the one the report uses. */
export declare function osvEcosystemName(ecosystem: Ecosystem): string;
/** The name to query with. PyPI treats `-`, `_` and `.` as equal and publishes normalised names. */
export declare function osvLookupName(ecosystem: Ecosystem, name: string): string;
/** Every CVE id a record names, its own id included. */
export declare function recordCveIds(record: OsvVulnerability): readonly string[];
/** Every GHSA id a record names, its own id included. */
export declare function recordGhsaIds(record: OsvVulnerability): readonly string[];
/**
 * Matches installed packages against osv.dev and returns findings in the report shape:
 * one row per (canonical id, package@version), sorted deterministically.
 */
export declare function matchVulnerabilities(packages: readonly PackageEntry[], options: MatchOptions): Promise<readonly Vulnerability[]>;
//# sourceMappingURL=match.d.ts.map