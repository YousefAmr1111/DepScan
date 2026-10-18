import { UNRESOLVED_REASONS, type PackageEntry, type UnresolvedRequirement } from './types.js';
export { UNRESOLVED_REASONS };
export type { UnresolvedReason, UnresolvedRequirement } from './types.js';
export interface PythonProject {
    readonly ecosystem: 'pypi';
    readonly projectName: string;
    readonly manifestPath: string;
    /** Only exactly pinned requirements. Anything else is in `unresolved`. */
    readonly packages: readonly PackageEntry[];
    readonly unresolved: readonly UnresolvedRequirement[];
    readonly warnings: readonly string[];
}
/**
 * PyPI treats names case-insensitively and treats `-`, `_` and `.` as equivalent
 * (`PyYAML`, `pyyaml` and `py-yaml` are one project). Advisories are published under the
 * normalised name, so matching must use this form. The report keeps the name as written in
 * the manifest for traceability.
 */
export declare function normalizePythonName(name: string): string;
/**
 * Reads a Python project. Only `name==version` pins become packages; every other line is
 * reported as unresolved with a reason, because guessing a version would invent a finding.
 */
export declare function parsePython(projectDir: string): PythonProject;
//# sourceMappingURL=python-parse.d.ts.map