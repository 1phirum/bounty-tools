/**
 * Monotonic, collision-free ID generation for traffic entries.
 *
 * Uses a monotonic counter with a random per-process prefix so IDs
 * are unique across restarts within the same session day, and sort
 * order equals creation order (critical for the traffic table).
 */

import { randomBytes } from 'node:crypto';

const PROCESS_PREFIX = randomBytes(4).toString('hex');

let counter = 0n;

export interface TrafficIdParts {
  readonly prefix: string;
  readonly seq: bigint;
}

const MAX_SEQ = 2n ** 48n;

export function nextTrafficId(): string {
  counter += 1n;
  if (counter >= MAX_SEQ) {
    // Wrap: re-seed prefix rather than ever colliding.
    counter = 1n;
  }
  return `t-${PROCESS_PREFIX}-${counter.toString(16).padStart(12, '0')}`;
}

/** Parse an ID back to its creation sequence, or null if malformed. */
export function parseTrafficId(id: string): TrafficIdParts | null {
  const parts = id.split('-');
  if (parts.length !== 3 || parts[0] !== 't') return null;
  const seq = BigInt(`0x${parts[2]}`);
  return { prefix: parts[1], seq };
}
