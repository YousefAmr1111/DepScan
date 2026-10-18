import { type ValidationIssue } from './json-schema.js';
import type { Report } from './types.js';
export type ReportValidationResult = {
    readonly ok: true;
    readonly report: Report;
} | {
    readonly ok: false;
    readonly issues: readonly ValidationIssue[];
};
/** Validates an unknown value against the report schema and the report invariants. */
export declare function validateReport(input: unknown): ReportValidationResult;
export declare function isReport(input: unknown): input is Report;
//# sourceMappingURL=validate-report.d.ts.map