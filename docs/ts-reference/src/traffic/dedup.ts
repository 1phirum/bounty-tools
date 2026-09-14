/**
 * Dedup pipeline — fingerprint computation and near-duplicate
 * clustering for the traffic stream.
 *
 * Exact dedup: SHA-256 over method + host + path + sorted query keys
 * (ignoring volatile query values via `volatileParams`).
 *
 * Near-dup detection: requests that differ only in one parameter's
 * value are collapsed into the same cluster so analysts see one row
 * per logical endpoint/param pair, not one row per fuzz payload.
 */

import { createHash } from 'node:crypto';
import type { HttpRequest } from './http-message.js';

export interface TrafficFingerprintParts {
  readonly method: string;
  readonly host: string;
  readonly path: string;
  readonly queryKeys: readonly string[];
}

/** Parameters whose values change per-request and should be ignored in fingerprints. */
const DEFAULT_VOLATILE_PARAMS: readonly string[] = Object.freeze([
  'csrf',
  'csrf_token',
  '_',
  'timestamp',
  'nonce',
]);

export interface FingerprintOptions {
  readonly volatileParams?: readonly string[];
}

export function computeFingerprint(
  request: HttpRequest,
  options: FingerprintOptions = {},
): { hash: string; parts: TrafficFingerprintParts } {
  const url = new URL(request.url);
  const volatile = new Set(options.volatileParams ?? DEFAULT_VOLATILE_PARAMS);

  const queryKeys: string[] = [];
  for (const key of new URLSearchParams(url.search).keys()) {
    if (!volatile.has(key.toLowerCase())) queryKeys.push(key.toLowerCase());
  }
  queryKeys.sort();

  const parts: TrafficFingerprintParts = {
    method: request.method,
    host: url.hostname,
    path: url.pathname,
    queryKeys,
  };

  const hash = createHash('sha256')
    .update(parts.method)
    .update('|')
    .update(parts.host)
    .update('|')
    .update(parts.path)
    .update('|')
    .update(queryKeys.join(','))
    .digest('hex')
    .slice(0, 32);

  return { hash, parts };
}

export interface DedupCluster {
  readonly fingerprint: string;
  readonly memberIds: readonly string[];
  /** Parameters that varied across cluster members (near-dup evidence). */
  readonly variedParams: readonly string[];
}

/**
 * Cluster a list of requests: exact duplicates share a fingerprint;
 * requests with the same fingerprint *except* one extra query param
 * value are near-dups of the base endpoint.
 */
export function clusterRequests(requests: readonly HttpRequest[]): DedupCluster[] {
  const clusters = new Map<string, string[]>();
  const varied = new Map<string, Set<string>>();

  for (const request of requests) {
    const { hash, parts } = computeFingerprint(request);
    const key = `${parts.method}|${parts.host}|${parts.path}`;
    if (!clusters.has(key)) {
      clusters.set(key, []);
      varied.set(key, new Set());
    }
    clusters.get(key)!.push(hash);
    const url = new URL(request.url);
    for (const queryKey of new URLSearchParams(url.search).keys()) {
      varied.get(key)!.add(queryKey.toLowerCase());
    }
  }

  return [...clusters.entries()].map(([key, fingerprints]) => ({
    fingerprint: key,
    memberIds: fingerprints,
    variedParams: [...varied.get(key)!].sort(),
  }));
}
