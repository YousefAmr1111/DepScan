import { existsSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';

import { ProjectParseError } from './errors.js';
import { packageId, sortPackageEntries } from './package-key.js';
import {
  UNRESOLVED_REASONS,
  type PackageEntry,
  type UnresolvedReason,
  type UnresolvedRequirement,
} from './types.js';

const REQUIREMENTS_FILE = 'requirements.txt';

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

const REQUIREMENT_PATTERN = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([^\]]*)\])?[ \t]*(.*)$/u;
const PIN_PATTERN = /^(===|==|>=|<=|~=|!=|>|<)[ \t]*(.+)$/u;

/**
 * PyPI treats names case-insensitively and treats `-`, `_` and `.` as equivalent
 * (`PyYAML`, `pyyaml` and `py-yaml` are one project). Advisories are published under the
 * normalised name, so matching must use this form. The report keeps the name as written in
 * the manifest for traceability.
 */
export function normalizePythonName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/gu, '-');
}

function stripComment(line: string): string {
  const hash = line.indexOf('#');
  return hash === -1 ? line : line.slice(0, hash);
}

function optionReason(line: string): UnresolvedReason {
  if (line.startsWith('-e ') || line.startsWith('--editable')) return 'editable';
  if (line.startsWith('-r ') || line.startsWith('--requirement')) return 'include-directive';
  return 'option-line';
}

function classifyRequirement(
  name: string,
  specifier: string,
  raw: string,
  line: number,
): { readonly version: string } | UnresolvedRequirement {
  const unresolved = (reason: UnresolvedReason): UnresolvedRequirement => ({
    raw,
    name,
    specifier,
    line,
    reason,
  });

  if (specifier.startsWith('@')) {
    return unresolved('url-reference');
  }

  const pin = PIN_PATTERN.exec(specifier);
  if (pin === null) {
    return unresolved('not-pinned');
  }

  const [, operator = '', version = ''] = pin;
  if (operator !== '==' && operator !== '===') {
    return unresolved('not-pinned');
  }
  if (version.includes(',')) {
    return unresolved('multiple-pins');
  }
  if (version.includes('*')) {
    return unresolved('wildcard-pin');
  }
  if (version.length === 0) {
    return unresolved('not-pinned');
  }

  return { version: version.trim() };
}

/**
 * Reads a Python project. Only `name==version` pins become packages; every other line is
 * reported as unresolved with a reason, because guessing a version would invent a finding.
 */
export function parsePython(projectDir: string): PythonProject {
  const manifestPath = join(projectDir, REQUIREMENTS_FILE);
  if (!existsSync(manifestPath)) {
    throw new ProjectParseError('missing-requirements', manifestPath, 'file does not exist');
  }

  const contents = readFileSync(manifestPath, 'utf8');
  const warnings: string[] = [];
  const packages: PackageEntry[] = [];
  const unresolved: UnresolvedRequirement[] = [];
  const seen = new Set<string>();

  contents.split(/\r?\n/u).forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const line = stripComment(rawLine).trim();
    if (line.length === 0) {
      return;
    }

    if (line.startsWith('-')) {
      unresolved.push({
        raw: line,
        name: '',
        specifier: line.replace(/^--?[a-z-]+[ \t]*/u, ''),
        line: lineNumber,
        reason: optionReason(line),
      });
      return;
    }

    const [requirement = '', marker] = line.split(';', 2);
    const match = REQUIREMENT_PATTERN.exec(requirement.trim());
    if (match === null) {
      throw new ProjectParseError(
        'malformed-requirements',
        manifestPath,
        `line ${lineNumber} is not a requirement: "${line}"`,
      );
    }

    const [, name = '', , specifier = ''] = match;
    if (marker !== undefined && marker.trim().length > 0) {
      warnings.push(
        `line ${lineNumber} has an environment marker that is ignored: ${marker.trim()}`,
      );
    }

    const classified = classifyRequirement(name, specifier, requirement.trim(), lineNumber);
    if ('version' in classified) {
      const id = packageId(name, classified.version);
      if (seen.has(id)) {
        warnings.push(`"${id}" is pinned more than once`);
        return;
      }
      seen.add(id);
      packages.push({
        name,
        version: classified.version,
        isDirect: true,
        depth: 0,
        parents: [],
        isDev: null,
      });
      return;
    }

    unresolved.push(classified);
  });

  return {
    ecosystem: 'pypi',
    projectName: basename(projectDir),
    manifestPath: REQUIREMENTS_FILE,
    packages: sortPackageEntries(packages),
    unresolved,
    warnings,
  };
}
