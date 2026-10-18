import type { OsvQuery, OsvVulnerability } from './osv-types.js';
export declare const DEFAULT_CACHE_TTL_MS: number;
export declare const OSV_CACHE_MISS_CODES: readonly ["cache-miss"];
export type OsvCacheMissCode = (typeof OSV_CACHE_MISS_CODES)[number];
/** Thrown in offline mode when a query is not in the cache. Names every missing key. */
export declare class OsvCacheMissError extends Error {
    readonly code: OsvCacheMissCode;
    readonly missingKeys: readonly string[];
    constructor(missingKeys: readonly string[]);
}
export declare function isOsvCacheMissError(value: unknown): value is OsvCacheMissError;
export type OsvCacheLookup = {
    readonly status: 'hit';
    readonly vulns: readonly OsvVulnerability[];
    readonly ageMs: number;
} | {
    readonly status: 'miss';
    readonly reason: 'absent' | 'expired' | 'unreadable';
};
export interface OsvCache {
    readonly dir: string;
    readonly ttlMs: number;
    get(query: OsvQuery): OsvCacheLookup;
    set(query: OsvQuery, vulns: readonly OsvVulnerability[]): void;
}
export interface OsvCacheOptions {
    readonly dir?: string;
    readonly ttlMs?: number;
    readonly now?: () => number;
}
/** Stable, filesystem-safe cache key for one query. */
export declare function cacheKeyFor(query: OsvQuery): string;
export declare function defaultCacheDir(): string;
/**
 * On-disk cache keyed by (ecosystem, name, version), storing the raw OSV response with the
 * time it was recorded. Entries older than the TTL are treated as misses so a fix
 * published after the recording is picked up.
 */
export declare function createFileCache(options?: OsvCacheOptions): OsvCache;
/** A cache that is never written to and never expires. Handy for tests and replay tools. */
export declare function createMemoryCache(initial?: Readonly<Record<string, readonly OsvVulnerability[]>>): OsvCache;
//# sourceMappingURL=osv-cache.d.ts.map