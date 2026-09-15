/**
 * Proxy engine — intercepting HTTP/1.1 forward proxy core.
 *
 * Responsibilities:
 *  1. Accept client connections and parse requests.
 *  2. Enforce scope BEFORE any outbound bytes are sent.
 *  3. Forward in-scope requests to the target, capture responses.
 *  4. Feed every completed exchange into the TrafficStore.
 *  5. Honor a shared rate limiter so scanning stays polite.
 *
 * The engine is transport-agnostic: it consumes raw sockets from the
 * Tauri-side listener (or a plain `node:net` server in tests), so the
 * same logic runs against a live proxy or replayed fixtures.
 */

import { BugToolsError, normalizeError } from '../core/errors.js';
import type { BugToolsConfig } from '../core/config.js';
import { ScopeManager } from '../core/scope.js';
import { nextTrafficId } from '../core/ids.js';
import { computeFingerprint } from '../traffic/dedup.js';
import type { TrafficEntry, HttpRequest, HttpResponse } from '../traffic/http-message.js';
import { TrafficEntryBuilder } from '../traffic/http-message.js';
import type { TrafficStore } from '../traffic/traffic-store.js';
import type { RateLimiter } from './rate-limiter.js';

export interface ProxyInterceptDecision {
  readonly intercepted: boolean;
  /** When intercepted, the request is held for analyst modification. */
  readonly holdReason?: 'scope_review' | 'match_filter';
}

export interface ProxyEngineDeps {
  readonly config: BugToolsConfig;
  readonly scope: ScopeManager;
  readonly store: TrafficStore;
  readonly limiter: RateLimiter;
  /** When true, requests pause for analyst approval instead of forwarding. */
  readonly interceptMode?: boolean;
  /** Extra predicate for hold (e.g. "hold all POSTs"). */
  readonly holdFilter?: (request: HttpRequest) => boolean;
}

export class ProxyEngine {
  private readonly inflight = new Set<string>();

  constructor(private readonly deps: ProxyEngineDeps) {}

  /**
   * Classify an inbound request before forwarding.
   * Pure — no I/O — so the UI can preview the decision.
   */
  classify(request: HttpRequest): ProxyInterceptDecision {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      throw new BugToolsError('E_INTERNAL', `malformed request URL: ${request.url}`, {
        url: request.url,
      });
    }

    this.deps.scope.assertAllowed(url); // throws E_SCOPE_VIOLATION when denied

    if (this.deps.interceptMode) {
      return { intercepted: true, holdReason: 'scope_review' };
    }
    if (this.deps.holdFilter?.(request)) {
      return { intercepted: true, holdReason: 'match_filter' };
    }
    return { intercepted: false };
  }

  /**
   * Forward a request and record the exchange.
   *
   * Rate limiting is applied *before* the socket write; a scope
   * violation never consumes a token (safety checks are free).
   */
  async forward(request: HttpRequest, source: TrafficEntry['source'] = 'proxy'): Promise<TrafficEntry> {
    const decision = this.classify(request); // throws when out of scope

    if (decision.intercepted && !this.deps.interceptMode) {
      // holdFilter matched but engine isn't paused — treat as pass-through
    }

    if (!this.deps.limiter.tryConsume()) {
      const wait = this.deps.limiter.msUntilNextToken();
      await delay(wait);
    }

    const startedAt = Date.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(
        () => controller.abort(),
        this.deps.config.fuzzer.requestTimeoutMs,
      );

      const response = await fetch(request.url, {
        method: request.method,
        headers: request.headers,
        body: request.body.length > 0 && request.method !== 'GET' && request.method !== 'HEAD'
          ? new Uint8Array(request.body)
          : undefined,
        signal: controller.signal,
        redirect: 'manual',
      });

      clearTimeout(timer);

      const body = Buffer.from(await response.arrayBuffer());
      const httpResponse: HttpResponse = Object.freeze({
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries([...response.headers.entries()].map(([k, v]) => [k.toLowerCase(), v])),
        body,
        durationMs: Date.now() - startedAt,
      });

      const { hash } = computeFingerprint(request);
      const entry = new TrafficEntryBuilder(request, hash, source)
        .withResponse(httpResponse)
        .build(nextTrafficId());

      this.deps.store.append(entry);
      return entry;
    } catch (err) {
      throw normalizeError(err, `proxy forward failed for ${request.url}`);
    } finally {
      this.inflight.delete(request.url);
    }
  }

  /** Record a request that the analyst edited during interception. */
  recordHeld(request: HttpRequest, response: HttpResponse | null): TrafficEntry {
    const { hash } = computeFingerprint(request);
    const entry = new TrafficEntryBuilder(request, hash, 'proxy').withResponse(
      response ?? Object.freeze({
        status: 0,
        statusText: 'HELD',
        headers: {},
        body: Buffer.alloc(0),
        durationMs: 0,
      }),
    );
    const built = entry.build(nextTrafficId());
    this.deps.store.append(built);
    return built;
  }

  get inflightCount(): number {
    return this.inflight.size;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
