export const OSV_BATCH_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
/** OSV accepts at most 1000 queries in one batch. */
export const OSV_MAX_BATCH_SIZE = 1000;
export const DEFAULT_TIMEOUT_MS = 15_000;
export const DEFAULT_RETRIES = 2;
export const DEFAULT_BASE_DELAY_MS = 500;
export const OSV_ERROR_CODES = [
    'network-unavailable',
    'timeout',
    'http-error',
    'malformed-response',
];
/** A failure to reach or understand osv.dev. Never a finding problem. */
export class OsvError extends Error {
    code;
    status;
    attempts;
    constructor(code, message, attempts, status = null) {
        super(message);
        this.name = 'OsvError';
        this.code = code;
        this.status = status;
        this.attempts = attempts;
    }
}
export function isOsvError(value) {
    return value instanceof OsvError;
}
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/** Retry on 429 and 5xx. Everything else fails immediately. */
function isRetryableStatus(status) {
    return status === 429 || status >= 500;
}
function retryAfterMs(response) {
    const header = response.headers.get('retry-after');
    if (header === null) {
        return null;
    }
    const seconds = Number.parseInt(header, 10);
    return Number.isNaN(seconds) ? null : seconds * 1000;
}
function chunk(items, size) {
    const chunks = [];
    for (let index = 0; index < items.length; index += size) {
        chunks.push(items.slice(index, index + size));
    }
    return chunks;
}
function parseBatchResponse(payload, expected) {
    if (!isRecord(payload) || !Array.isArray(payload['results'])) {
        throw new OsvError('malformed-response', 'osv.dev returned no results array', 1);
    }
    const results = payload['results'];
    if (results.length !== expected) {
        throw new OsvError('malformed-response', `osv.dev answered ${results.length} results for ${expected} queries`, 1);
    }
    return results.map((item) => {
        if (!isRecord(item) || !Array.isArray(item['vulns'])) {
            throw new OsvError('malformed-response', 'osv.dev returned a result without vulns', 1);
        }
        return (item['vulns'] ?? []);
    });
}
/**
 * The real client: one HTTP round trip per batch, with a timeout, exponential backoff and
 * a typed error when osv.dev cannot be reached.
 */
export function createOsvHttp(options = {}) {
    const endpoint = options.endpoint ?? OSV_BATCH_ENDPOINT;
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const retries = options.retries ?? DEFAULT_RETRIES;
    const baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
    const doFetch = options.fetchImpl ?? fetch;
    const sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    const post = async (queries, attempt) => {
        let response;
        try {
            response = await doFetch(endpoint, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ queries }),
                signal: AbortSignal.timeout(timeoutMs),
            });
        }
        catch (error) {
            const detail = error instanceof Error ? error.message : 'request failed';
            const timedOut = error instanceof Error && error.name === 'TimeoutError';
            throw new OsvError(timedOut ? 'timeout' : 'network-unavailable', `${endpoint} is unreachable: ${detail}`, attempt);
        }
        if (!response.ok) {
            const failure = new OsvError('http-error', `${endpoint} answered ${response.status} ${response.statusText}`, attempt, response.status);
            if (!isRetryableStatus(response.status) || attempt > retries) {
                throw failure;
            }
            await sleep(retryAfterMs(response) ?? baseDelayMs * 2 ** (attempt - 1));
            return post(queries, attempt + 1);
        }
        let body;
        try {
            body = await response.json();
        }
        catch (error) {
            const detail = error instanceof Error ? error.message : 'invalid JSON';
            throw new OsvError('malformed-response', `${endpoint} returned invalid JSON: ${detail}`, attempt);
        }
        return parseBatchResponse(body, queries.length);
    };
    return {
        async queryBatch(queries) {
            if (queries.length === 0) {
                return [];
            }
            const answers = [];
            for (const batch of chunk(queries, OSV_MAX_BATCH_SIZE)) {
                answers.push(...(await post(batch, 1)));
            }
            return answers;
        },
    };
}
//# sourceMappingURL=osv-http.js.map