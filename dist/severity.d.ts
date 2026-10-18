import { type Severity, type Vulnerability } from './types.js';
export declare function isSeverity(value: string): value is Severity;
export declare function compareSeverity(left: Severity, right: Severity): number;
/** Returns a new array ordered by severity, most severe first. The input is untouched. */
export declare function sortVulnerabilitiesBySeverity<T extends Pick<Vulnerability, 'severity'>>(vulnerabilities: readonly T[]): T[];
//# sourceMappingURL=severity.d.ts.map