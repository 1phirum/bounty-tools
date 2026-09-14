/**
 * BugTools backend bootstrap — wires every engine into a single
 * `BugToolsBackend` facade with one entry point per UI concern.
 *
 * This is the surface the Tauri command layer (or CLI) imports.
 */

import { parseConfig, DEFAULT_CONFIG, type BugToolsConfig } from './core/config.js';
import { ScopeManager } from './core/scope.js';
import { TrafficStore } from './traffic/traffic-store.js';
import { RateLimiter } from './engines/rate-limiter.js';
import { ProxyEngine } from './engines/proxy-engine.js';
import { Repeater } from './engines/repeater.js';
import { Fuzzer } from './engines/fuzzer.js';

export interface BugToolsBackend {
  readonly config: BugToolsConfig;
  readonly scope: ScopeManager;
  readonly store: TrafficStore;
  readonly proxy: ProxyEngine;
  readonly repeater: Repeater;
  readonly fuzzer: Fuzzer;
  readonly limiter: RateLimiter;
}

export function createBackend(
  configInput?: unknown,
  overrides: Partial<{ interceptMode: boolean }> = {},
): BugToolsBackend {
  const config = parseConfig(configInput ?? DEFAULT_CONFIG);
  const scope = new ScopeManager();
  const store = new TrafficStore(config.trafficCapacity);
  const limiter = new RateLimiter(config.rateLimit);

  const proxy = new ProxyEngine({
    config,
    scope,
    store,
    limiter,
    interceptMode: overrides.interceptMode ?? false,
  });

  const repeater = new Repeater(scope, limiter);
  const fuzzer = new Fuzzer(config, scope, limiter).withStore(store);

  return Object.freeze({ config, scope, store, proxy, repeater, fuzzer, limiter });
}
