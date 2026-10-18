export declare const CORE_PACKAGE_NAME = "@depscan/core";
export declare const TOOL_NAME = "depscan";
export declare const REPORT_SCHEMA_VERSION = 2;
export declare const SEVERITIES: readonly ["critical", "high", "medium", "low"];
export type Severity = (typeof SEVERITIES)[number];
export declare const ECOSYSTEMS: readonly ["npm", "pypi"];
export type Ecosystem = (typeof ECOSYSTEMS)[number];
export declare const UNRESOLVED_REASONS: readonly ["not-pinned", "wildcard-pin", "multiple-pins", "url-reference", "editable", "include-directive", "option-line"];
export type UnresolvedReason = (typeof UNRESOLVED_REASONS)[number];
/**
 * A requirement that could not be resolved to an exact installed version, so it could
 * not be checked. A report with any of these has not fully scanned the project and must
 * never be presented as clean.
 */
export interface UnresolvedRequirement {
    readonly raw: string;
    /** Empty when the line declares no package, e.g. `--index-url https://example.com`. */
    readonly name: string;
    readonly specifier: string;
    /** 1-based line number in the manifest. */
    readonly line: number;
    readonly reason: UnresolvedReason;
}
export interface ToolInfo {
    readonly name: typeof TOOL_NAME;
    readonly version: string;
}
export interface ReportMeta {
    readonly tool: ToolInfo;
    readonly generatedAt: string;
    readonly projectName: string;
    readonly ecosystem: Ecosystem;
    readonly manifestPath: string;
    /** Requirements that were never checked. Non-empty means the scan is not complete. */
    readonly unresolved: readonly UnresolvedRequirement[];
    /** Recoverable problems reported by the parsers. */
    readonly warnings: readonly string[];
}
export interface PackageEntry {
    readonly name: string;
    readonly version: string;
    readonly isDirect: boolean;
    readonly depth: number;
    /** Each entry is `name@version` of an installed package that requires this one. */
    readonly parents: readonly string[];
    /** null when the ecosystem has no dev/prod distinction, such as PyPI. */
    readonly isDev: boolean | null;
}
export interface Vulnerability {
    readonly id: string;
    readonly aliases: readonly string[];
    readonly package: string;
    readonly installedVersion: string;
    readonly severity: Severity;
    readonly cvss: CvssScore | null;
    readonly summary: string;
    readonly affectedRange: string;
    readonly fixedVersion: string | null;
    readonly advisoryUrl: string | null;
    readonly source: string;
}
export interface CvssScore {
    readonly score: number;
    readonly vector: string;
}
export interface RiskAssessment {
    readonly vulnerabilityId: string;
    readonly priorityScore: number;
    readonly flags: RiskFlags;
    /** Machine-readable reason codes, e.g. `direct-dependency`, `fix-available`. */
    readonly reasons: readonly string[];
}
export interface RiskFlags {
    readonly isReachable: boolean;
    readonly isDirect: boolean;
    readonly hasFix: boolean;
}
export interface Suggestion {
    readonly vulnerabilityId: string;
    readonly saferVersion: string | null;
    readonly alternativePackage: string | null;
    readonly rationale: string;
    /** Provenance marker. The LLM layer may only write suggestions with this value. */
    readonly provider: 'llm';
}
export interface ReportStats {
    readonly totalPackages: number;
    readonly directPackages: number;
    readonly transitivePackages: number;
    readonly totalVulnerabilities: number;
    readonly bySeverity: Readonly<Record<Severity, number>>;
    /** How many requirements could not be checked. Mirrors `meta.unresolved.length`. */
    readonly unresolvedCount: number;
}
export interface Report {
    readonly schemaVersion: typeof REPORT_SCHEMA_VERSION;
    readonly meta: ReportMeta;
    readonly packages: readonly PackageEntry[];
    readonly vulnerabilities: readonly Vulnerability[];
    readonly risk: readonly RiskAssessment[];
    readonly suggestions: readonly Suggestion[];
    readonly stats: ReportStats;
}
//# sourceMappingURL=types.d.ts.map