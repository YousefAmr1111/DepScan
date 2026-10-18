import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
export const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const OSV_CACHE_MISS_CODES = ['cache-miss'];
/** Thrown in offline mode when a query is not in the cache. Names every missing key. */
export class OsvCacheMissError extends Error {
    code;
    missingKeys;
    constructor(missingKeys) {
        super(`offline: no cached osv.dev response for ${missingKeys.join(', ')}. ` +
            'Run once online to populate the cache.');
        this.name = 'OsvCacheMissError';
        this.code = 'cache-miss';
        this.missingKeys = missingKeys;
    }
}
export function isOsvCacheMissError(value) {
    return value instanceof OsvCacheMissError;
}
/** Stable, filesystem-safe cache key for one query. */
export function cacheKeyFor(query) {
    return `${query.ecosystem}__${query.name}@${query.version}`;
}
export function defaultCacheDir() {
    const override = process.env['DEPSCAN_CACHE_DIR'];
    return override !== undefined && override.length > 0
        ? override
        : join(homedir(), '.depscan', 'cache', 'osv');
}
function fileNameFor(key) {
    return `${key.replace(/[^A-Za-z0-9._@+-]/gu, '_')}.json`;
}
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/**
 * On-disk cache keyed by (ecosystem, name, version), storing the raw OSV response with the
 * time it was recorded. Entries older than the TTL are treated as misses so a fix
 * published after the recording is picked up.
 */
export function createFileCache(options = {}) {
    const dir = options.dir ?? defaultCacheDir();
    const ttlMs = options.ttlMs ?? DEFAULT_CACHE_TTL_MS;
    const now = options.now ?? (() => Date.now());
    return {
        dir,
        ttlMs,
        get(query) {
            const path = join(dir, fileNameFor(cacheKeyFor(query)));
            if (!existsSync(path)) {
                return { status: 'miss', reason: 'absent' };
            }
            let parsed;
            try {
                parsed = JSON.parse(readFileSync(path, 'utf8'));
            }
            catch {
                return { status: 'miss', reason: 'unreadable' };
            }
            if (!isRecord(parsed) ||
                typeof parsed['recordedAt'] !== 'number' ||
                !Array.isArray(parsed['vulns'])) {
                return { status: 'miss', reason: 'unreadable' };
            }
            const recordedAt = parsed['recordedAt'];
            const ageMs = now() - recordedAt;
            if (ageMs > ttlMs) {
                return { status: 'miss', reason: 'expired' };
            }
            return { status: 'hit', vulns: (parsed['vulns'] ?? []), ageMs };
        },
        set(query, vulns) {
            mkdirSync(dir, { recursive: true });
            const entry = {
                key: cacheKeyFor(query),
                ecosystem: query.ecosystem,
                name: query.name,
                version: query.version,
                recordedAt: now(),
                vulns,
            };
            writeFileSync(join(dir, fileNameFor(entry.key)), `${JSON.stringify(entry)}\n`, 'utf8');
        },
    };
}
/** A cache that is never written to and never expires. Handy for tests and replay tools. */
export function createMemoryCache(initial = {}) {
    const store = new Map(Object.entries(initial));
    return {
        dir: '<memory>',
        ttlMs: Number.POSITIVE_INFINITY,
        get(query) {
            const vulns = store.get(cacheKeyFor(query));
            return vulns === undefined
                ? { status: 'miss', reason: 'absent' }
                : { status: 'hit', vulns, ageMs: 0 };
        },
        set(query, vulns) {
            store.set(cacheKeyFor(query), vulns);
        },
    };
}
//# sourceMappingURL=osv-cache.js.map