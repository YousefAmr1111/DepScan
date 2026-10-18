import type { OsvQuery, OsvVulnerability } from './osv-types.js';
export declare const OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch";
/** OSV accepts at most 1000 queries in one batch. */
export declare const OSV_MAX_BATCH_SIZE = 1000;
export declare const DEFAULT_TIMEOUT_MS = 15000;
export declare const DEFAULT_RETRIES = 2;
export declare const DEFAULT_BASE_DELAY_MS = 500;
export declare const OSV_ERROR_CODES: readonly ["network-unavailable", "timeout", "http-error", "malformed-response"];
export type OsvErrorCode = (typeof OSV_ERROR_CODES)[number];
/** A failure to reach or understand osv.dev. Never a finding problem. */
export declare class OsvError extends Error {
    readonly code: OsvErrorCode;
    readonly status: number | null;
    readonly attempts: number;
    constructor(code: OsvErrorCode, message: string, attempts: number, status?: number | null);
}
export declare function isOsvError(value: unknown): value is OsvError;
/** The injectable HTTP layer. Tests pass their own; nothing in core calls fetch directly. */
export interface OsvHttp {
    /** Returns one vulnerability list per query, in the same order. */
    queryBatch(queries: readonly OsvQuery[]): Promise<readonly OsvVulnerability[][]>;
}
export interface OsvHttpOptions {
    readonly endpoint?: string;
    readonly timeoutMs?: number;
    readonly retries?: number;
    readonly baseDelayMs?: number;
    /** Injected for tests; must behave like `fetch`. */
    readonly fetchImpl?: typeof fetch;
    /** Injected for tests so backoff does not really sleep. */
    readonly sleep?: (ms: number) => Promise<void>;
}
/**
 * The real client: one HTTP round trip per batch, with a timeout, exponential backoff and
 * a typed error when osv.dev cannot be reached.
 */
export declare function createOsvHttp(options?: OsvHttpOptions): OsvHttp;
//# sourceMappingURL=osv-http.d.ts.map