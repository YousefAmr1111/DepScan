export const PARSE_ERROR_CODES = [
    'missing-manifest',
    'missing-lockfile',
    'missing-requirements',
    'malformed-manifest',
    'malformed-lockfile',
    'malformed-requirements',
    'unsupported-lockfile-version',
];
/** Every expected failure while reading a project manifest. Never a bug, always typed. */
export class ProjectParseError extends Error {
    code;
    path;
    constructor(code, path, detail) {
        super(`${code}: ${path} (${detail})`);
        this.name = 'ProjectParseError';
        this.code = code;
        this.path = path;
    }
}
export function isProjectParseError(value) {
    return value instanceof ProjectParseError;
}
//# sourceMappingURL=errors.js.map