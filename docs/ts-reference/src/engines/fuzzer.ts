/**
 * Fuzzer engine — parameterized, rate-limited, scope-checked payload
 * injection (the "Intruder" analog).
 *
 * Payload generators are pure functions of position; the engine only
 * orchestrates concurrency, dedup, and safety checks. Payload content
 * is supplied by the analyst (wordlists, templates) — the engine never
 * invents attack payloads itself.
 */

import { BugToolsError } from '../core/errors.js';
import type { BugToolsConfig } from '../core/config.js';
import { ScopeManager } from '../core/scope.js';
import { nextTrafficId } from '../core/ids.js';
import { computeFingerprint } from '../traffic/dedup.js';
import type { TrafficEntry, HttpRequest } from '../traffic/http-message.js';
import { TrafficEntryBuilder } from '../traffic/http-message.js';
import type { RateLimiter } from './rate-limiter.js';

/** Markers: §name§ replaced per-iteration from the payload set. */
export type PayloadSet = readonly string[];
export type PayloadMarker = `§${string}§`;

export interface FuzzerPosition {
  readonly marker: PayloadMarker;
  readonly payloads: PayloadSet;
}

export interface FuzzerRunOptions {
  /** Max concurrent in-flight fuzz requests (bounded by rate limiter anyway). */
  readonly concurrency?: number;
  /** Abort the whole run after this many failures. */
  readonly maxFailures?: number;
}

export interface FuzzerIterationResult {
  readonly replacements: Readonly<Record<string, string>>;
  readonly status: number;
  readonly durationMs: number;
  readonly entry: TrafficEntry | null; // null when store deduped it
}

export interface FuzzerRunSummary {
  readonly total: number;
  readonly completed: number;
  readonly failed: number;
  readonly deduped: number;
  readonly results: readonly FuzzerIterationResult[];
}

export class Fuzzer {
  constructor(
    private readonly config: BugToolsConfig,
    private readonly scope: ScopeManager,
    private readonly limiter: RateLimiter,
  ) {}

  /** Expand payload positions into concrete replacement combos (cartesian, bounded). */
  expand(positions: readonly FuzzerPosition[]): Array<Readonly<Record<string, string>>> {
    if (positions.length === 0) {
      throw new BugToolsError('E_FUZZER_NO_PAYLOADS', 'no fuzz positions defined', {});
    }
    for (const pos of positions) {
      if (pos.payloads.length === 0) {
        throw new BugToolsError(
          'E_FUZZER_PAYLOAD_REJECTED',
          `position ${pos.marker} has an empty payload set`,
          { marker: pos.marker },
        );
      }
    }

    let combos: Array<Record<string, string>> = [{}];
    for (const pos of positions) {
      const next: Array<Record<string, string>> = [];
      for (const combo of combos) {
        for (const payload of pos.payloads) {
          next.push({ ...combo, [pos.marker.slice(1, -1)]: payload });
        }
        if (next.length > this.config.fuzzer.maxPayloadsPerRun) {
          throw new BugToolsError(
            'E_FUZZER_PAYLOAD_REJECTED',
            `expanded combos exceed maxPayloadsPerRun (${this.config.fuzzer.maxPayloadsPerRun})`,
            { count: next.length },
          );
        }
      }
      combos = next;
    }
    return combos;
  }

  /** Substitute markers in request template. Pure. */
  renderTemplate(base: HttpRequest, replacements: Readonly<Record<string, string>>): HttpRequest {
    let url = base.url;
    let bodyText = base.body.toString('utf8');
    for (const [marker, value] of Object.entries(replacements)) {
      url = url.replaceAll(`§${marker}§`, value);
      bodyText = bodyText.replaceAll(`§${marker}§`, value);
    }
    return Object.freeze({
      ...base,
      url,
      body: Buffer.from(bodyText, 'utf8'),
    });
  }

  /**
   * Execute a fuzz run: expand, render, scope-check each rendered URL,
   * rate-limit, dispatch with bounded concurrency, collect results.
   */
  async run(
    base: HttpRequest,
    positions: readonly FuzzerPosition[],
    options: FuzzerRunOptions = {},
  ): Promise<FuzzerRunSummary> {
    const combos = this.expand(positions);
    const concurrency = Math.max(1, Math.min(options.concurrency ?? 4, 32));
    const maxFailures = options.maxFailures ?? 20;

    const results: FuzzerIterationResult[] = [];
    let completed = 0;
    let failed = 0;
    let deduped = 0;

    const queue = [...combos];

    async function worker(
      this: Fuzzer,
      onFatal: () => void,
    ): Promise<void> {
      while (queue.length > 0 && failed <= maxFailures) {
        const replacements = queue.shift();
        if (!replacements) return;

        const rendered = this.renderTemplate(base, replacements);
        let url: URL;
        try {
          url = new URL(rendered.url);
        } catch {
          failed += 1;
          continue;
        }

        try {
          this.scope.assertAllowed(url);
        } catch {
          // Out-of-scope fuzz target — skip silently but count as failure signal.
          failed += 1;
          if (failed > maxFailures) onFatal();
          continue;
        }

        if (!this.limiter.tryConsume()) {
          await new Promise((resolve) => setTimeout(resolve, this.limiter.msUntilNextToken()));
        }

        const startedAt = Date.now();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.config.fuzzer.requestTimeoutMs);

        try {
          const response = await fetch(rendered.url, {
            method: rendered.method,
            headers: rendered.headers,
            body: rendered.body.length > 0 && rendered.method !== 'GET' && rendered.method !== 'HEAD'
              ? new Uint8Array(rendered.body)
              : undefined,
            signal: controller.signal,
            redirect: 'manual',
          });

          const body = Buffer.from(await response.arrayBuffer());
          const durationMs = Date.now() - startedAt;

          const { hash } = computeFingerprint(rendered);
          const entry = new TrafficEntryBuilder(rendered, hash, 'fuzzer')
            .withResponse(
              Object.freeze({
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(
                  [...response.headers.entries()].map(([k, v]) => [k.toLowerCase(), v]),
                ),
                body,
                durationMs,
              }),
            )
            .build(nextTrafficId());

          // Fuzzer results are inherently near-duplicates; the store's
          // exact-dedup applies, and we report which ones were collapsed.
          const stored = this.storeForRun().append(entry);
          if (!stored) {
            deduped += 1;
          }

          completed += 1;
          results.push({
            replacements,
            status: response.status,
            durationMs,
            entry: stored ? entry : null,
          });
        } catch {
          failed += 1;
          if (failed > maxFailures) onFatal();
        } finally {
          clearTimeout(timer);
        }
      }
    }

    // Bind run store via closure — keeps Fuzzer stateless per run.
    const runStore = this.currentStore;
    if (!runStore) {
      throw new BugToolsError('E_INTERNAL', 'fuzzer has no traffic store bound', {});
    }

    const workers = Array.from({ length: Math.min(concurrency, combos.length) }, () =>
      worker.call(this, () => {
        queue.length = 0;
      }),
    );
    await Promise.all(workers);

    return { total: combos.length, completed, failed, deduped, results };
  }

  private currentStore: import('../traffic/traffic-store.js').TrafficStore | null = null;

  /** Bind the store for subsequent runs (injected at construction by the shell). */
  withStore(store: import('../traffic/traffic-store.js').TrafficStore): this {
    this.currentStore = store;
    return this;
  }

  private storeForRun(): import('../traffic/traffic-store.js').TrafficStore {
    if (!this.currentStore) {
      throw new BugToolsError('E_INTERNAL', 'fuzzer store not bound — call withStore()', {});
    }
    return this.currentStore;
  }
}
