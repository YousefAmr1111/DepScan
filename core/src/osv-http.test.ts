import { describe, expect, it, vi, type Mock } from 'vitest';

import {
  DEFAULT_BASE_DELAY_MS,
  OSV_BATCH_ENDPOINT,
  OSV_ERROR_CODES,
  OSV_MAX_BATCH_SIZE,
  createOsvHttp,
  isOsvError,
  type OsvError,
  type OsvHttpOptions,
  type OsvQuery,
} from './index.js';

const QUERY: OsvQuery = { ecosystem: 'npm', name: 'lodash', version: '4.17.20' };

type FetchSpy = Mock<typeof fetch>;

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function batchResponse(vulnCounts: readonly number[]): unknown {
  return { results: vulnCounts.map((count) => ({ vulns: Array.from({ length: count }) })) };
}

function requestBody(init: RequestInit | undefined): unknown {
  return JSON.parse(init?.body as string) as unknown;
}

/** A client whose backoff never actually sleeps. */
function client(fetchImpl: FetchSpy, options: Omit<OsvHttpOptions, 'fetchImpl'> = {}) {
  return createOsvHttp({ fetchImpl, sleep: () => Promise.resolve(), ...options });
}

function sleepRecorder() {
  const sleeps: number[] = [];
  return { sleeps, sleep: (ms: number) => (sleeps.push(ms), Promise.resolve()) };
}

async function captureError(promise: Promise<unknown>): Promise<OsvError> {
  const thrown = await promise.catch((error: unknown) => error);
  if (!isOsvError(thrown)) {
    throw new Error(`expected an OsvError, received ${String(thrown)}`);
  }
  return thrown;
}

describe('createOsvHttp', () => {
  it('posts the batch endpoint with the queries', async () => {
    const fetchImpl: FetchSpy = vi.fn(() => Promise.resolve(jsonResponse(batchResponse([1, 0]))));

    const answers = await client(fetchImpl).queryBatch([QUERY, { ...QUERY, name: 'ms' }]);
    const [url, init] = fetchImpl.mock.calls[0] ?? [];

    expect(url).toBe(OSV_BATCH_ENDPOINT);
    expect(init?.method).toBe('POST');
    expect(requestBody(init)).toEqual({ queries: [QUERY, { ...QUERY, name: 'ms' }] });
    expect(answers[0]).toHaveLength(1);
    expect(answers[1]).toHaveLength(0);
  });

  it('makes no request for an empty query list', async () => {
    const fetchImpl: FetchSpy = vi.fn(() => Promise.resolve(jsonResponse(batchResponse([]))));

    expect(await client(fetchImpl).queryBatch([])).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('splits a large batch at the osv.dev limit', async () => {
    const queries = Array.from({ length: OSV_MAX_BATCH_SIZE + 1 }, (_unused, index) => ({
      ecosystem: 'npm',
      name: `pkg-${index}`,
      version: '1.0.0',
    }));
    const fetchImpl: FetchSpy = vi.fn((_input, init) => {
      const payload = requestBody(init) as { queries: readonly OsvQuery[] };
      return Promise.resolve(jsonResponse(batchResponse(payload.queries.map(() => 0))));
    });

    const answers = await client(fetchImpl).queryBatch(queries);

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(answers).toHaveLength(OSV_MAX_BATCH_SIZE + 1);
  });

  it('retries a 500 with exponential backoff', async () => {
    const { sleeps, sleep } = sleepRecorder();
    const fetchImpl: FetchSpy = vi
      .fn<FetchSpy>()
      .mockResolvedValueOnce(new Response('nope', { status: 500 }))
      .mockResolvedValueOnce(jsonResponse(batchResponse([0])));

    expect(await createOsvHttp({ fetchImpl, sleep }).queryBatch([QUERY])).toEqual([[]]);
    expect(sleeps).toEqual([DEFAULT_BASE_DELAY_MS]);
  });

  it('retries a 429 using Retry-After when the server sends one', async () => {
    const { sleeps, sleep } = sleepRecorder();
    const fetchImpl: FetchSpy = vi
      .fn<FetchSpy>()
      .mockResolvedValueOnce(
        new Response('slow down', { status: 429, headers: { 'retry-after': '2' } }),
      )
      .mockResolvedValueOnce(jsonResponse(batchResponse([0])));

    await createOsvHttp({ fetchImpl, sleep }).queryBatch([QUERY]);

    expect(sleeps).toEqual([2000]);
  });

  it('gives up after the retry budget and reports the status', async () => {
    const fetchImpl: FetchSpy = vi.fn(() => Promise.resolve(new Response('nope', { status: 503 })));

    const error = await captureError(client(fetchImpl, { retries: 1 }).queryBatch([QUERY]));

    expect(error.code).toBe('http-error');
    expect(error.status).toBe(503);
    expect(error.attempts).toBe(2);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('does not retry a 404', async () => {
    const fetchImpl: FetchSpy = vi.fn(() =>
      Promise.resolve(new Response('missing', { status: 404 })),
    );

    await client(fetchImpl)
      .queryBatch([QUERY])
      .catch(() => undefined);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reports an unreachable network with a typed error', async () => {
    const fetchImpl: FetchSpy = vi.fn(() => Promise.reject(new TypeError('fetch failed')));

    const error = await captureError(client(fetchImpl).queryBatch([QUERY]));

    expect(error.code).toBe('network-unavailable');
    expect(error.message).toContain(OSV_BATCH_ENDPOINT);
  });

  it('reports a timeout as its own error code', async () => {
    const fetchImpl: FetchSpy = vi.fn(() => {
      const timeout = new Error('The operation timed out');
      timeout.name = 'TimeoutError';
      return Promise.reject(timeout);
    });

    expect((await captureError(client(fetchImpl).queryBatch([QUERY]))).code).toBe('timeout');
  });

  it('rejects a response that is not JSON', async () => {
    const fetchImpl: FetchSpy = vi.fn(() =>
      Promise.resolve(new Response('<html>down</html>', { status: 200 })),
    );

    expect((await captureError(client(fetchImpl).queryBatch([QUERY]))).code).toBe(
      'malformed-response',
    );
  });

  it('rejects a batch whose result count does not match the query count', async () => {
    const fetchImpl: FetchSpy = vi.fn(() => Promise.resolve(jsonResponse(batchResponse([0]))));

    const error = await captureError(
      client(fetchImpl).queryBatch([QUERY, { ...QUERY, name: 'ms' }]),
    );

    expect(error.message).toContain('answered 1 results for 2 queries');
  });

  it('rejects a result without a vulns array', async () => {
    const fetchImpl: FetchSpy = vi.fn(() =>
      Promise.resolve(jsonResponse({ results: [{ vulns: [] }, { nothing: true }] })),
    );

    const error = await captureError(
      client(fetchImpl).queryBatch([QUERY, { ...QUERY, name: 'ms' }]),
    );

    expect(error.code).toBe('malformed-response');
  });

  it('publishes its error codes', () => {
    expect(OSV_ERROR_CODES).toContain('network-unavailable');
    expect(OSV_ERROR_CODES).toContain('malformed-response');
  });
});
