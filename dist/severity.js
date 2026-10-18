import { SEVERITIES } from './types.js';
const SEVERITY_RANK = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
};
export function isSeverity(value) {
    return SEVERITIES.includes(value);
}
export function compareSeverity(left, right) {
    return SEVERITY_RANK[left] - SEVERITY_RANK[right];
}
/** Returns a new array ordered by severity, most severe first. The input is untouched. */
export function sortVulnerabilitiesBySeverity(vulnerabilities) {
    return [...vulnerabilities].sort((left, right) => compareSeverity(left.severity, right.severity));
}
//# sourceMappingURL=severity.js.map