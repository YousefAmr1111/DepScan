import { isDeepEqual, validateJsonSchema } from './json-schema.js';
import { packageId } from './package-key.js';
import { REPORT_SCHEMA } from './report-schema.js';
import { computeStats } from './stats.js';
function uniqueDuplicates(values) {
    const seen = new Set();
    const repeated = [];
    for (const value of values) {
        if (seen.has(value) && !repeated.includes(value)) {
            repeated.push(value);
        }
        seen.add(value);
    }
    return repeated;
}
/**
 * Invariants that JSON Schema cannot express: cross-references between sections and
 * internal consistency of the derived stats.
 */
function validateSemantics(report) {
    const issues = [];
    const packageIds = report.packages.map((entry) => packageId(entry.name, entry.version));
    const knownPackageIds = new Set(packageIds);
    for (const duplicate of uniqueDuplicates(packageIds)) {
        issues.push({ path: '/packages', message: `contains duplicate package "${duplicate}"` });
    }
    report.packages.forEach((entry, index) => {
        if (entry.isDirect !== (entry.depth === 0)) {
            issues.push({
                path: `/packages/${index}`,
                message: 'isDirect must be true exactly when depth is 0',
            });
        }
        for (const [position, parentId] of entry.parents.entries()) {
            if (!knownPackageIds.has(parentId)) {
                issues.push({
                    path: `/packages/${index}/parents/${position}`,
                    message: `references unknown package "${parentId}"`,
                });
            }
        }
    });
    const vulnerabilityIds = report.vulnerabilities.map((entry) => entry.id);
    const knownVulnerabilityIds = new Set(vulnerabilityIds);
    for (const duplicate of uniqueDuplicates(vulnerabilityIds)) {
        issues.push({
            path: '/vulnerabilities',
            message: `contains duplicate vulnerability id "${duplicate}"`,
        });
    }
    const riskIds = report.risk.map((entry) => entry.vulnerabilityId);
    for (const duplicate of uniqueDuplicates(riskIds)) {
        issues.push({ path: '/risk', message: `contains duplicate entry for "${duplicate}"` });
    }
    for (const id of riskIds) {
        if (!knownVulnerabilityIds.has(id)) {
            issues.push({ path: '/risk', message: `references unknown vulnerability "${id}"` });
        }
    }
    // Coverage is only required once a report claims to be scored. `risk: []` means
    // priority scoring is not implemented yet, which docs/p05-decisions.md allows; a partial
    // risk section would silently drop findings, so that is rejected.
    if (riskIds.length > 0) {
        for (const id of knownVulnerabilityIds) {
            if (!riskIds.includes(id)) {
                issues.push({ path: '/risk', message: `is missing an entry for "${id}"` });
            }
        }
    }
    const suggestedIds = report.suggestions.map((entry) => entry.vulnerabilityId);
    for (const duplicate of uniqueDuplicates(suggestedIds)) {
        issues.push({ path: '/suggestions', message: `contains duplicate entry for "${duplicate}"` });
    }
    for (const id of suggestedIds) {
        if (!knownVulnerabilityIds.has(id)) {
            issues.push({ path: '/suggestions', message: `references unknown vulnerability "${id}"` });
        }
    }
    const expectedStats = computeStats(report.packages, report.vulnerabilities, report.meta.unresolved.length);
    if (!isDeepEqual(expectedStats, report.stats)) {
        issues.push({
            path: '/stats',
            message: `must match the report contents, expected ${JSON.stringify(expectedStats)}`,
        });
    }
    if (report.meta.unresolved.length > 0 && report.vulnerabilities.length === 0) {
        issues.push({
            path: '/meta/unresolved',
            message: 'must not sit next to an empty vulnerabilities array: a scan with unresolved ' +
                'requirements has not checked everything and cannot be reported as clean',
        });
    }
    return issues;
}
/** Validates an unknown value against the report schema and the report invariants. */
export function validateReport(input) {
    const schemaIssues = validateJsonSchema(input, REPORT_SCHEMA);
    if (schemaIssues.length > 0) {
        return { ok: false, issues: schemaIssues };
    }
    const semanticIssues = validateSemantics(input);
    if (semanticIssues.length > 0) {
        return { ok: false, issues: semanticIssues };
    }
    return { ok: true, report: input };
}
export function isReport(input) {
    return validateReport(input).ok;
}
//# sourceMappingURL=validate-report.js.map