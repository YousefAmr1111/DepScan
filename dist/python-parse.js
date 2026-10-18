import { existsSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { ProjectParseError } from './errors.js';
import { packageId, sortPackageEntries } from './package-key.js';
import { UNRESOLVED_REASONS, } from './types.js';
const REQUIREMENTS_FILE = 'requirements.txt';
export { UNRESOLVED_REASONS };
const REQUIREMENT_PATTERN = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([^\]]*)\])?[ \t]*(.*)$/u;
const PIN_PATTERN = /^(===|==|>=|<=|~=|!=|>|<)[ \t]*(.+)$/u;
/**
 * PyPI treats names case-insensitively and treats `-`, `_` and `.` as equivalent
 * (`PyYAML`, `pyyaml` and `py-yaml` are one project). Advisories are published under the
 * normalised name, so matching must use this form. The report keeps the name as written in
 * the manifest for traceability.
 */
export function normalizePythonName(name) {
    return name.toLowerCase().replace(/[-_.]+/gu, '-');
}
function stripComment(line) {
    const hash = line.indexOf('#');
    return hash === -1 ? line : line.slice(0, hash);
}
function optionReason(line) {
    if (line.startsWith('-e ') || line.startsWith('--editable'))
        return 'editable';
    if (line.startsWith('-r ') || line.startsWith('--requirement'))
        return 'include-directive';
    return 'option-line';
}
function classifyRequirement(name, specifier, raw, line) {
    const unresolved = (reason) => ({
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
export function parsePython(projectDir) {
    const manifestPath = join(projectDir, REQUIREMENTS_FILE);
    if (!existsSync(manifestPath)) {
        throw new ProjectParseError('missing-requirements', manifestPath, 'file does not exist');
    }
    const contents = readFileSync(manifestPath, 'utf8');
    const warnings = [];
    const packages = [];
    const unresolved = [];
    const seen = new Set();
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
            throw new ProjectParseError('malformed-requirements', manifestPath, `line ${lineNumber} is not a requirement: "${line}"`);
        }
        const [, name = '', , specifier = ''] = match;
        if (marker !== undefined && marker.trim().length > 0) {
            warnings.push(`line ${lineNumber} has an environment marker that is ignored: ${marker.trim()}`);
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
//# sourceMappingURL=python-parse.js.map