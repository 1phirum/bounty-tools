/**
 * BugTools backend test suite.
 *
 * Run: node --test test/bugtools.test.ts
 * (Node 24 executes TypeScript directly with --experimental-strip-types
 *  or natively; the package script uses the test runner.)
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { BugToolsError, normalizeError, isBugToolsError } from '../src/core/errors.js';
import { parseConfig, DEFAULT_CONFIG } from '../src/core/config.js';
import { nextTrafficId, parseTrafficId } from '../src/core/ids.js';
import { ScopeManager } from '../src/core/scope.js';
import { TrafficStore } from '../src/traffic/traffic-store.js';
import { computeFingerprint, clusterRequests } from '../src/traffic/dedup.js';
import type { HttpRequest } from '../src/traffic/http-message.js';
import { RateLimiter } from '../src/engines/rate-limiter.js';

function makeRequest(overrides: Partial<HttpRequest> = {}): HttpRequest {
  return {
    method: 'GET',
    url: 'https://api.example.com/v1/users?id=42',
    headers: { host: 'api.example.com' },
    body: Buffer.alloc(0),
    ...overrides,
  };
}

// ── Errors ──────────────────────────────────────────────────────────
describe('errors', () => {
  test('typed error serializes with stable keys', () => {
    const err = new BugToolsError('E_SCOPE_VIOLATION', 'blocked', { host: 'x' });
    const json = err.toJSON();
    assert.equal(json.code, 'E_SCOPE_VIOLATION');
    assert.equal(json.message, 'blocked');
    assert.deepEqual(json.context, { host: 'x' });
  });

  test('normalizeError wraps unknown throws', () => {
    const wrapped = normalizeError(new Error('boom'), 'test-site');
    assert.ok(isBugToolsError(wrapped));
    assert.equal(wrapped.code, 'E_INTERNAL');
    assert.match(wrapped.message, /test-site: boom/);
  });
});

// ── Config ──────────────────────────────────────────────────────────
describe('config', () => {
  test('defaults parse cleanly', () => {
    const cfg = parseConfig(undefined);
    assert.deepEqual(cfg, DEFAULT_CONFIG);
  });

  test('unknown keys are rejected', () => {
    assert.throws(() => parseConfig({ bogus: 1 }), (err: unknown) => {
      return err instanceof BugToolsError && err.code === 'E_CONFIG_INVALID';
    });
  });

  test('negative port rejected', () => {
    assert.throws(() => parseConfig({ proxy: { bindPort: -1 } }), BugToolsError);
  });
});

// ── IDs ─────────────────────────────────────────────────────────────
describe('ids', () => {
  test('ids are unique and parseable', () => {
    const a = nextTrafficId();
    const b = nextTrafficId();
    assert.notEqual(a, b);
    const parsed = parseTrafficId(a);
    assert.ok(parsed !== null);
    assert.equal(parsed.prefix.length, 8);
  });
});

// ── Scope ───────────────────────────────────────────────────────────
describe('scope manager', () => {
  const scope = new ScopeManager();
  scope.addRule({ protocol: '*', host: '*.example.com', port: '*', pathPrefix: '/' });
  scope.addRule({ protocol: 'https', host: 'api.target.io', port: 443, pathPrefix: '/v1' });

  test('wildcard subdomains allowed', () => {
    assert.equal(scope.isAllowed(new URL('https://deep.api.example.com/x')).allowed, true);
    assert.equal(scope.isAllowed(new URL('https://example.com/x')).allowed, true);
  });

  test('out-of-scope hosts denied with reason', () => {
    const decision = scope.isAllowed(new URL('https://evil.com/x'));
    assert.equal(decision.allowed, false);
    assert.match(decision.reason, /no rule matched/);
  });

  test('path prefix enforced', () => {
    assert.equal(scope.isAllowed(new URL('https://api.target.io/v2/x')).allowed, false);
    assert.equal(scope.isAllowed(new URL('https://api.target.io/v1/x')).allowed, true);
  });

  test('assertAllowed throws typed error', () => {
    assert.throws(
      () => scope.assertAllowed(new URL('https://unauthorized.net/x')),
      (err: unknown) => err instanceof BugToolsError && err.code === 'E_SCOPE_VIOLATION',
    );
  });
});

// ── Traffic store ───────────────────────────────────────────────────
describe('traffic store', () => {
  test('dedups by fingerprint and evicts oldest beyond capacity', () => {
    const store = new TrafficStore(2);
    const { hash } = computeFingerprint(makeRequest());
    const entry = {
      id: nextTrafficId(),
      request: makeRequest(),
      response: null,
      capturedAt: Date.now(),
      fingerprint: hash,
      source: 'proxy' as const,
    };
    assert.equal(store.append(entry), true);
    assert.equal(store.append(entry), false); // duplicate fingerprint
    assert.equal(store.size, 1);
  });

  test('pagination newest-first', () => {
    const store = new TrafficStore(10);
    for (let i = 0; i < 5; i += 1) {
      const { hash } = computeFingerprint(makeRequest({ url: `https://x.test/${i}` }));
      store.append({
        id: nextTrafficId(),
        request: makeRequest({ url: `https://x.test/${i}` }),
        response: null,
        capturedAt: Date.now(),
        fingerprint: hash,
        source: 'proxy',
      });
    }
    const page = store.page(0, 3);
    assert.equal(page.entries.length, 3);
    assert.equal(page.hasMore, true);
    assert.equal(page.total, 5);
    // Newest first: path /4 should be first.
    assert.match(page.entries[0].request.url, /\/4$/);
  });
});

// ── Dedup ───────────────────────────────────────────────────────────
describe('dedup fingerprinting', () => {
  test('volatile query params ignored', () => {
    const a = computeFingerprint(makeRequest({ url: 'https://api.example.com/v1/users?id=42&_=111' }));
    const b = computeFingerprint(makeRequest({ url: 'https://api.example.com/v1/users?id=42&_=999' }));
    assert.equal(a.hash, b.hash);
  });

  test('different paths produce different hashes', () => {
    const a = computeFingerprint(makeRequest({ url: 'https://api.example.com/v1/users' }));
    const b = computeFingerprint(makeRequest({ url: 'https://api.example.com/v1/orders' }));
    assert.notEqual(a.hash, b.hash);
  });

  test('clustering groups same endpoint', () => {
    const clusters = clusterRequests([
      makeRequest({ url: 'https://x.test/a?p=1' }),
      makeRequest({ url: 'https://x.test/a?p=2' }),
      makeRequest({ url: 'https://x.test/b' }),
    ]);
    assert.equal(clusters.length, 2);
  });
});

// ── Rate limiter ────────────────────────────────────────────────────
describe('rate limiter', () => {
  test('burst respected then refill recovers', async () => {
    const limiter = new RateLimiter({ burst: 3, refillPerSecond: 100 });
    assert.equal(limiter.tryConsume(), true);
    assert.equal(limiter.tryConsume(), true);
    assert.equal(limiter.tryConsume(), true);
    assert.equal(limiter.tryConsume(), false);
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(limiter.tryConsume(), true);
  });

  test('msUntilNextToken reports realistic wait', () => {
    const limiter = new RateLimiter({ burst: 1, refillPerSecond: 10 });
    limiter.tryConsume();
    const wait = limiter.msUntilNextToken();
    assert.ok(wait > 0 && wait <= 1000);
  });
});
