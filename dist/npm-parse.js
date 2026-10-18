import { existsSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { ProjectParseError } from './errors.js';
import { packageId, sortPackageEntries } from './package-key.js';
const MANIFEST_FILE = 'package.json';
const LOCKFILE = 'package-lock.json';
const NODE_MODULES = 'node_modules/';
export const SUPPORTED_LOCKFILE_VERSIONS = [2, 3];
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function readJson(path, malformedCode) {
    const text = readFileSync(path, 'utf8');
    try {
        return JSON.parse(text);
    }
    catch (error) {
        const detail = error instanceof Error ? error.message : 'invalid JSON';
        throw new ProjectParseError(malformedCode, path, detail);
    }
}
/** Reads a dependency map such as `dependencies`, rejecting anything that is not one. */
function dependencyMap(source, key, path, malformedCode) {
    const value = source[key];
    if (value === undefined) {
        return {};
    }
    if (!isRecord(value)) {
        throw new ProjectParseError(malformedCode, path, `"${key}" must be an object`);
    }
    const result = {};
    for (const [name, range] of Object.entries(value)) {
        if (typeof range !== 'string') {
            throw new ProjectParseError(malformedCode, path, `"${key}.${name}" must be a string`);
        }
        result[name] = range;
    }
    return result;
}
/**
 * Resolves a dependency the way Node does: look in the requiring package's own
 * `node_modules`, then walk up towards the project root. Lockfile paths are never treated
 * as depth, because npm hoists and dedupes.
 */
function resolveFrom(installed, fromPath, name) {
    let prefix = fromPath;
    for (;;) {
        const candidate = prefix === '' ? `${NODE_MODULES}${name}` : `${prefix}/${NODE_MODULES}${name}`;
        const found = installed.get(candidate);
        if (found !== undefined) {
            return candidate;
        }
        if (prefix === '') {
            return undefined;
        }
        const parent = prefix.lastIndexOf(`/${NODE_MODULES}`);
        prefix = parent === -1 ? '' : prefix.slice(0, parent);
    }
}
function nameFromPath(path) {
    return path.slice(path.lastIndexOf(NODE_MODULES) + NODE_MODULES.length);
}
/**
 * Reads an npm project: every installed package keyed by `name@version`, with `isDirect`,
 * `depth` (shortest distance from the manifest) and `parents` taken from the dependency
 * graph rather than from lockfile paths, because npm hoists and dedupes.
 */
export function parseNpm(projectDir) {
    const manifestPath = join(projectDir, MANIFEST_FILE);
    if (!existsSync(manifestPath)) {
        throw new ProjectParseError('missing-manifest', manifestPath, 'file does not exist');
    }
    const rawManifest = readJson(manifestPath, 'malformed-manifest');
    if (!isRecord(rawManifest)) {
        throw new ProjectParseError('malformed-manifest', manifestPath, 'expected a JSON object');
    }
    const lockPath = join(projectDir, LOCKFILE);
    if (!existsSync(lockPath)) {
        throw new ProjectParseError('missing-lockfile', lockPath, 'file does not exist');
    }
    const rawLock = readJson(lockPath, 'malformed-lockfile');
    if (!isRecord(rawLock)) {
        throw new ProjectParseError('malformed-lockfile', lockPath, 'expected a JSON object');
    }
    const lockfileVersion = rawLock['lockfileVersion'];
    if (typeof lockfileVersion !== 'number' ||
        !SUPPORTED_LOCKFILE_VERSIONS.includes(lockfileVersion)) {
        throw new ProjectParseError('unsupported-lockfile-version', lockPath, `lockfileVersion ${JSON.stringify(lockfileVersion ?? null)} is not one of ${SUPPORTED_LOCKFILE_VERSIONS.join(', ')}`);
    }
    const rawPackages = rawLock['packages'];
    if (!isRecord(rawPackages)) {
        throw new ProjectParseError('malformed-lockfile', lockPath, '"packages" must be an object');
    }
    const installed = new Map();
    for (const [path, value] of Object.entries(rawPackages)) {
        if (path === '' || !isRecord(value) || value['link'] === true) {
            continue;
        }
        const entryVersion = value['version'];
        if (typeof entryVersion !== 'string' || entryVersion.length === 0) {
            continue;
        }
        installed.set(path, {
            path,
            name: nameFromPath(path),
            version: entryVersion,
            // npm writes dev: true only for dev-only entries, so its absence means production.
            isDev: value['dev'] === true,
        });
    }
    const installedByName = new Map();
    for (const entry of installed.values()) {
        const existing = installedByName.get(entry.name) ?? [];
        existing.push(entry);
        installedByName.set(entry.name, existing);
    }
    const warnings = [];
    const resolveDependency = (fromPath, name) => {
        const resolved = resolveFrom(installed, fromPath, name);
        if (resolved !== undefined) {
            return resolved;
        }
        const candidates = installedByName.get(name) ?? [];
        const only = candidates.length === 1 ? candidates[0] : undefined;
        if (only !== undefined) {
            warnings.push(`"${name}" required by "${fromPath || '<project>'}" is installed elsewhere`);
            return only.path;
        }
        return undefined;
    };
    const manifestDependencies = {
        ...dependencyMap(rawManifest, 'dependencies', manifestPath, 'malformed-manifest'),
        ...dependencyMap(rawManifest, 'devDependencies', manifestPath, 'malformed-manifest'),
        ...dependencyMap(rawManifest, 'optionalDependencies', manifestPath, 'malformed-manifest'),
    };
    const rootPaths = [];
    for (const name of Object.keys(manifestDependencies).sort()) {
        const resolved = resolveDependency('', name);
        if (resolved === undefined) {
            warnings.push(`manifest dependency "${name}" is not in the lockfile`);
            continue;
        }
        rootPaths.push(resolved);
    }
    const depthByPath = new Map();
    const parentsByPath = new Map();
    const queue = [];
    for (const path of rootPaths) {
        if (!depthByPath.has(path)) {
            depthByPath.set(path, 0);
            queue.push(path);
        }
    }
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
        const path = queue[cursor];
        if (path === undefined) {
            continue;
        }
        const entry = installed.get(path);
        const parentDepth = depthByPath.get(path);
        if (entry === undefined || parentDepth === undefined) {
            continue;
        }
        const parentId = packageId(entry.name, entry.version);
        const rawEntry = rawPackages[path];
        const declared = isRecord(rawEntry)
            ? {
                ...dependencyMap(rawEntry, 'dependencies', lockPath, 'malformed-lockfile'),
                ...dependencyMap(rawEntry, 'optionalDependencies', lockPath, 'malformed-lockfile'),
            }
            : {};
        for (const name of Object.keys(declared).sort()) {
            const resolved = resolveDependency(path, name);
            if (resolved === undefined) {
                warnings.push(`"${name}" required by "${entry.name}" is not installed`);
                continue;
            }
            const child = installed.get(resolved);
            if (child === undefined) {
                continue;
            }
            const parents = parentsByPath.get(resolved) ?? new Set();
            parents.add(parentId);
            parentsByPath.set(resolved, parents);
            if (!depthByPath.has(resolved)) {
                depthByPath.set(resolved, parentDepth + 1);
                queue.push(resolved);
            }
        }
    }
    const depthById = new Map();
    const parentsById = new Map();
    const identityById = new Map();
    for (const [path, depth] of depthByPath) {
        const entry = installed.get(path);
        if (entry === undefined) {
            continue;
        }
        const id = packageId(entry.name, entry.version);
        identityById.set(id, entry);
        const existingDepth = depthById.get(id);
        if (existingDepth === undefined || depth < existingDepth) {
            depthById.set(id, depth);
        }
        const parents = parentsById.get(id) ?? new Set();
        for (const parent of parentsByPath.get(path) ?? []) {
            parents.add(parent);
        }
        parentsById.set(id, parents);
    }
    const directIds = new Set();
    for (const path of rootPaths) {
        const entry = installed.get(path);
        if (entry !== undefined) {
            directIds.add(packageId(entry.name, entry.version));
        }
    }
    const packages = [];
    for (const [id, entry] of identityById) {
        const depth = depthById.get(id);
        if (depth === undefined) {
            continue;
        }
        packages.push({
            name: entry.name,
            version: entry.version,
            isDirect: directIds.has(id),
            depth,
            parents: [...(parentsById.get(id) ?? new Set())].sort(),
            isDev: entry.isDev,
        });
    }
    const orphans = [...installed.values()]
        .filter((entry) => !depthByPath.has(entry.path))
        .map((entry) => packageId(entry.name, entry.version))
        .sort();
    const manifestName = rawManifest['name'];
    const fallbackName = basename(projectDir);
    return {
        ecosystem: 'npm',
        projectName: typeof manifestName === 'string' && manifestName.length > 0 ? manifestName : fallbackName,
        manifestPath: MANIFEST_FILE,
        packages: sortPackageEntries(packages),
        orphans,
        warnings,
    };
}
//# sourceMappingURL=npm-parse.js.map