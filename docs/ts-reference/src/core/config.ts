/**
 * Runtime configuration with strict validation.
 *
 * The workstation loads this once at boot; all engines receive an
 * immutable snapshot so behavior is deterministic per session.
 */

import { BugToolsError } from './errors.js';

export interface ProxyConfig {
  /** Interface the intercept proxy binds to. Loopback by default — never expose. */
  readonly bindHost: string;
  readonly bindPort: number;
  /** Max concurrent in-flight proxied requests. */
  readonly maxConcurrency: number;
  /** Request header timeout in milliseconds. */
  readonly headerTimeoutMs: number;
}

export interface RateLimitConfig {
  /** Token bucket size (burst capacity). */
  readonly burst: number;
  /** Sustained refill rate in tokens per second. */
  readonly refillPerSecond: number;
}

export interface FuzzerConfig {
  /** Hard ceiling on total payloads per run regardless of wordlist size. */
  readonly maxPayloadsPerRun: number;
  /** Per-request timeout during fuzzing. */
  readonly requestTimeoutMs: number;
}

export interface BugToolsConfig {
  readonly proxy: ProxyConfig;
  readonly rateLimit: RateLimitConfig;
  readonly fuzzer: FuzzerConfig;
  /** Traffic ring buffer size per store. */
  readonly trafficCapacity: number;
}

export const DEFAULT_CONFIG: BugToolsConfig = Object.freeze({
  proxy: Object.freeze({
    bindHost: '127.0.0.1',
    bindPort: 8080,
    maxConcurrency: 64,
    headerTimeoutMs: 10_000,
  }),
  rateLimit: Object.freeze({
    burst: 20,
    refillPerSecond: 10,
  }),
  fuzzer: Object.freeze({
    maxPayloadsPerRun: 10_000,
    requestTimeoutMs: 15_000,
  }),
  trafficCapacity: 50_000,
});

function assertPositiveInt(value: number, path: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new BugToolsError('E_CONFIG_INVALID', `${path} must be a positive integer`, {
      path,
      value,
    });
  }
}

/** Validate a partial config against defaults; unknown keys are rejected. */
export function parseConfig(input: unknown): BugToolsConfig {
  if (input === undefined || input === null) return DEFAULT_CONFIG;
  if (typeof input !== 'object') {
    throw new BugToolsError('E_CONFIG_INVALID', 'config must be an object', {
      received: typeof input,
    });
  }

  const raw = input as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    if (!['proxy', 'rateLimit', 'fuzzer', 'trafficCapacity'].includes(key)) {
      throw new BugToolsError('E_CONFIG_INVALID', `unknown config key "${key}"`, { key });
    }
  }

  const proxyRaw = (raw.proxy ?? {}) as Record<string, unknown>;
  const rateRaw = (raw.rateLimit ?? {}) as Record<string, unknown>;
  const fuzzRaw = (raw.fuzzer ?? {}) as Record<string, unknown>;

  const proxy: ProxyConfig = {
    bindHost: typeof proxyRaw.bindHost === 'string' ? proxyRaw.bindHost : DEFAULT_CONFIG.proxy.bindHost,
    bindPort: proxyRaw.bindPort !== undefined ? Number(proxyRaw.bindPort) : DEFAULT_CONFIG.proxy.bindPort,
    maxConcurrency:
      proxyRaw.maxConcurrency !== undefined
        ? Number(proxyRaw.maxConcurrency)
        : DEFAULT_CONFIG.proxy.maxConcurrency,
    headerTimeoutMs:
      proxyRaw.headerTimeoutMs !== undefined
        ? Number(proxyRaw.headerTimeoutMs)
        : DEFAULT_CONFIG.proxy.headerTimeoutMs,
  };

  const rateLimit: RateLimitConfig = {
    burst: rateRaw.burst !== undefined ? Number(rateRaw.burst) : DEFAULT_CONFIG.rateLimit.burst,
    refillPerSecond:
      rateRaw.refillPerSecond !== undefined
        ? Number(rateRaw.refillPerSecond)
        : DEFAULT_CONFIG.rateLimit.refillPerSecond,
  };

  const fuzzer: FuzzerConfig = {
    maxPayloadsPerRun:
      fuzzRaw.maxPayloadsPerRun !== undefined
        ? Number(fuzzRaw.maxPayloadsPerRun)
        : DEFAULT_CONFIG.fuzzer.maxPayloadsPerRun,
    requestTimeoutMs:
      fuzzRaw.requestTimeoutMs !== undefined
        ? Number(fuzzRaw.requestTimeoutMs)
        : DEFAULT_CONFIG.fuzzer.requestTimeoutMs,
  };

  const trafficCapacity =
    raw.trafficCapacity !== undefined ? Number(raw.trafficCapacity) : DEFAULT_CONFIG.trafficCapacity;

  assertPositiveInt(proxy.bindPort, 'proxy.bindPort');
  if (proxy.bindPort > 65_535) {
    throw new BugToolsError('E_CONFIG_INVALID', 'proxy.bindPort exceeds 65535', {
      value: proxy.bindPort,
    });
  }
  assertPositiveInt(proxy.maxConcurrency, 'proxy.maxConcurrency');
  assertPositiveInt(proxy.headerTimeoutMs, 'proxy.headerTimeoutMs');
  assertPositiveInt(rateLimit.burst, 'rateLimit.burst');
  assertPositiveInt(rateLimit.refillPerSecond, 'rateLimit.refillPerSecond');
  assertPositiveInt(fuzzer.maxPayloadsPerRun, 'fuzzer.maxPayloadsPerRun');
  assertPositiveInt(fuzzer.requestTimeoutMs, 'fuzzer.requestTimeoutMs');
  assertPositiveInt(trafficCapacity, 'trafficCapacity');

  return Object.freeze({ proxy, rateLimit, fuzzer, trafficCapacity });
}
