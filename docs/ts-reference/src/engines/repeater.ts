/**
 * Repeater engine — deterministic single-request replay with analyst
 * edits. Given a captured entry, produce a modified request, validate
 * it against scope, send once, and record the result as a new entry
 * (never mutating the original).
 */

import { BugToolsError } from '../core/errors.js';
import { ScopeManager } from '../core/scope.js';
import { nextTrafficId } from '../core/ids.js';
import { computeFingerprint } from '../traffic/dedup.js';
import type { TrafficEntry, HttpRequest, HttpResponse } from '../traffic/http-message.js';
import { TrafficEntryBuilder } from '../traffic/http-message.js';
import type { RateLimiter } from './rate-limiter.js';

export interface RepeaterEdit {
  /** Replace method entirely. */
  readonly method?: HttpRequest['method'];
  /** Replace URL. */
  readonly url?: string;
  /** Merge headers (input wins over originals, names case-insensitive). */
  readonly headerOverrides?: Record<string, string>;
  /** Replace body entirely (raw bytes). */
  readonly body?: Buffer;
}

export interface RepeaterRunResult {
  readonly basedOn: string;
  readonly sent: HttpRequest;
  readonly response: HttpResponse;
  readonly entry: TrafficEntry;
}

export class Repeater {
  constructor(
    private readonly scope: ScopeManager,
    private readonly limiter: RateLimiter,
  ) {}

  /** Apply an edit spec to a captured request. Pure — returns a new request. */
  applyEdit(base: HttpRequest, edit: RepeaterEdit): HttpRequest {
    const method = edit.method ?? base.method;
    const url = edit.url ?? base.url;

    // Validate URL shape early with a clear typed error.
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new BugToolsError('E_REPEATER_TARGET_INVALID', `unsupported protocol: ${parsed.protocol}`, {
          url,
        });
      }
    } catch (err) {
      if (err instanceof BugToolsError) throw err;
      throw new BugToolsError('E_REPEATER_TARGET_INVALID', `malformed URL: ${url}`, { url }, err);
    }

    const headers: Record<string, string> = { ...base.headers };
    if (edit.headerOverrides) {
      for (const [name, value] of Object.entries(edit.headerOverrides)) {
        headers[name.toLowerCase()] = value;
      }
    }

    return Object.freeze({
      method,
      url,
      headers: Object.freeze(headers),
      body: edit.body !== undefined ? Buffer.from(edit.body) : Buffer.from(base.body),
    });
  }

  /** Send an edited request exactly once, scope-checked and rate-limited. */
  async send(base: HttpRequest, edit: RepeaterEdit): Promise<RepeaterRunResult> {
    const sent = this.applyEdit(base, edit);

    // Scope check on the *edited* URL — an analyst edit can point anywhere.
    this.scope.assertAllowed(new URL(sent.url));

    if (!this.limiter.tryConsume()) {
      const wait = this.limiter.msUntilNextToken();
      await new Promise((resolve) => setTimeout(resolve, wait));
    }

    const startedAt = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);

    try {
      const response = await fetch(sent.url, {
        method: sent.method,
        headers: sent.headers,
        body: sent.body.length > 0 && sent.method !== 'GET' && sent.method !== 'HEAD'
          ? new Uint8Array(sent.body)
          : undefined,
        signal: controller.signal,
        redirect: 'manual',
      });

      const body = Buffer.from(await response.arrayBuffer());
      const httpResponse: HttpResponse = Object.freeze({
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries([...response.headers.entries()].map(([k, v]) => [k.toLowerCase(), v])),
        body,
        durationMs: Date.now() - startedAt,
      });

      const { hash } = computeFingerprint(sent);
      const entry = new TrafficEntryBuilder(sent, hash, 'repeater')
        .withResponse(httpResponse)
        .build(nextTrafficId());

      return { basedOn: base.url, sent, response: httpResponse, entry };
    } finally {
      clearTimeout(timer);
    }
  }
}
