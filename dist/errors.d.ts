export declare const PARSE_ERROR_CODES: readonly ["missing-manifest", "missing-lockfile", "missing-requirements", "malformed-manifest", "malformed-lockfile", "malformed-requirements", "unsupported-lockfile-version"];
export type ParseErrorCode = (typeof PARSE_ERROR_CODES)[number];
/** Every expected failure while reading a project manifest. Never a bug, always typed. */
export declare class ProjectParseError extends Error {
    readonly code: ParseErrorCode;
    readonly path: string;
    constructor(code: ParseErrorCode, path: string, detail: string);
}
export declare function isProjectParseError(value: unknown): value is ProjectParseError;
//# sourceMappingURL=errors.d.ts.map