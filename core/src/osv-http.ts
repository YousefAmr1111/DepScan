import type { OsvQuery, OsvVulnerability } from './osv-types.js';

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
] as const;

export type OsvErrorCode = (typeof OSV_ERROR_CODES)[number];

/** A failure to reach or understand osv.dev. Never a finding problem. */
export class OsvError extends Error {
  readonly code: OsvErrorCode;
  readonly status: number | null;
  readonly attempts: number;

  constructor(code: OsvErrorCode, message: string, attempts: number, status: number | null = null) {
    super(message);
    this.name = 'OsvError';
    this.code = code;
    this.status = status;
    this.attempts = attempts;
  }
}

export function isOsvError(value: unknown): value is OsvError {
  return value instanceof OsvError;
}

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Retry on 429 and 5xx. Everything else fails immediately. */
function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function retryAfterMs(response: Response): number | null {
  const header = response.headers.get('retry-after');
  if (header === null) {
    return null;
  }
  const seconds = Number.parseInt(header, 10);
  return Number.isNaN(seconds) ? null : seconds * 1000;
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

function parseBatchResponse(payload: unknown, expected: number): OsvVulnerability[][] {
  if (!isRecord(payload) || !Array.isArray(payload['results'])) {
    throw new OsvError('malformed-response', 'osv.dev returned no results array', 1);
  }

  const results = payload['results'];
  if (results.length !== expected) {
    throw new OsvError(
      'malformed-response',
      `osv.dev answered ${results.length} results for ${expected} queries`,
      1,
    );
  }

  return results.map((item) => {
    if (!isRecord(item) || !Array.isArray(item['vulns'])) {
      throw new OsvError('malformed-response', 'osv.dev returned a result without vulns', 1);
    }
    return (item['vulns'] ?? []) as OsvVulnerability[];
  });
}

/**
 * The real client: one HTTP round trip per batch, with a timeout, exponential backoff and
 * a typed error when osv.dev cannot be reached.
 */
export function createOsvHttp(options: OsvHttpOptions = {}): OsvHttp {
  const endpoint = options.endpoint ?? OSV_BATCH_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const retries = options.retries ?? DEFAULT_RETRIES;
  const baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const doFetch = options.fetchImpl ?? fetch;
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));

  const post = async (
    queries: readonly OsvQuery[],
    attempt: number,
  ): Promise<OsvVulnerability[][]> => {
    let response: Response;
    try {
      response = await doFetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'request failed';
      const timedOut = error instanceof Error && error.name === 'TimeoutError';
      throw new OsvError(
        timedOut ? 'timeout' : 'network-unavailable',
        `${endpoint} is unreachable: ${detail}`,
        attempt,
      );
    }

    if (!response.ok) {
      const failure = new OsvError(
        'http-error',
        `${endpoint} answered ${response.status} ${response.statusText}`,
        attempt,
        response.status,
      );
      if (!isRetryableStatus(response.status) || attempt > retries) {
        throw failure;
      }
      await sleep(retryAfterMs(response) ?? baseDelayMs * 2 ** (attempt - 1));
      return post(queries, attempt + 1);
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'invalid JSON';
      throw new OsvError(
        'malformed-response',
        `${endpoint} returned invalid JSON: ${detail}`,
        attempt,
      );
    }

    return parseBatchResponse(body, queries.length);
  };

  return {
    async queryBatch(queries: readonly OsvQuery[]): Promise<readonly OsvVulnerability[][]> {
      if (queries.length === 0) {
        return [];
      }
      const answers: OsvVulnerability[][] = [];
      for (const batch of chunk(queries, OSV_MAX_BATCH_SIZE)) {
        answers.push(...(await post(batch, 1)));
      }
      return answers;
    },
  };
}
