import type { PackageEntry } from './types.js';
export declare const SUPPORTED_LOCKFILE_VERSIONS: readonly [2, 3];
export interface NpmProject {
    readonly ecosystem: 'npm';
    readonly projectName: string;
    readonly manifestPath: string;
    readonly packages: readonly PackageEntry[];
    /** Installed packages that nothing in the dependency graph requires. */
    readonly orphans: readonly string[];
    /** Recoverable problems, e.g. a manifest dependency missing from the lockfile. */
    readonly warnings: readonly string[];
}
/**
 * Reads an npm project: every installed package keyed by `name@version`, with `isDirect`,
 * `depth` (shortest distance from the manifest) and `parents` taken from the dependency
 * graph rather than from lockfile paths, because npm hoists and dedupes.
 */
export declare function parseNpm(projectDir: string): NpmProject;
//# sourceMappingURL=npm-parse.d.ts.map