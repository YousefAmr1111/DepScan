import type { PackageEntry } from './types.js';
/** Canonical key for a package instance: `name@version`, e.g. `ms@2.1.2`. */
export declare function packageId(name: string, version: string): string;
/**
 * Splits `name@version`, tolerating a scoped name such as `@scope/pkg@1.2.3` by taking
 * the last `@`. Returns null when there is no version part.
 */
export declare function splitPackageId(id: string): {
    readonly name: string;
    readonly version: string;
} | null;
/**
 * Compares dotted version strings numerically where possible (`4.9.0` < `4.17.0`).
 * Deterministic, not a full semver implementation: pre-release ordering is not modelled.
 */
export declare function compareVersions(left: string, right: string): number;
/** Total order over package instances: by name, then by version. Required for §1.5. */
export declare function comparePackageEntries(left: PackageEntry, right: PackageEntry): number;
export declare function sortPackageEntries(packages: readonly PackageEntry[]): PackageEntry[];
//# sourceMappingURL=package-key.d.ts.map