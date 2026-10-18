export const PARSE_ERROR_CODES = [
  'missing-manifest',
  'missing-lockfile',
  'missing-requirements',
  'malformed-manifest',
  'malformed-lockfile',
  'malformed-requirements',
  'unsupported-lockfile-version',
] as const;

export type ParseErrorCode = (typeof PARSE_ERROR_CODES)[number];

/** Every expected failure while reading a project manifest. Never a bug, always typed. */
export class ProjectParseError extends Error {
  readonly code: ParseErrorCode;
  readonly path: string;

  constructor(code: ParseErrorCode, path: string, detail: string) {
    super(`${code}: ${path} (${detail})`);
    this.name = 'ProjectParseError';
    this.code = code;
    this.path = path;
  }
}

export function isProjectParseError(value: unknown): value is ProjectParseError {
  return value instanceof ProjectParseError;
}
