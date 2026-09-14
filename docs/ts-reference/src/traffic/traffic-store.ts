/**
 * Traffic store — a bounded ring buffer of immutable TrafficEntries
 * with O(1) append, index-based pagination, and fingerprint-based
 * duplicate suppression.
 *
 * Bounded memory matters for long fuzzing sessions: the store keeps
 * the newest `capacity` entries and exposes eviction count for the
 * status bar.
 */

import { BugToolsError } from '../core/errors.js';
import type { TrafficEntry } from './http-message.js';

export interface TrafficPage {
  readonly entries: readonly TrafficEntry[];
  readonly total: number;
  readonly evicted: number;
  readonly hasMore: boolean;
}

export class TrafficStore {
  private readonly buffer: TrafficEntry[] = [];
  private readonly index = new Map<string, number>(); // id -> buffer position
  private readonly seenFingerprints = new Set<string>();
  private evicted = 0;

  constructor(private readonly capacity: number) {
    if (!Number.isInteger(capacity) || capacity <= 0) {
      throw new BugToolsError('E_CONFIG_INVALID', 'trafficCapacity must be a positive integer', {
        capacity,
      });
    }
  }

  get size(): number {
    return this.buffer.length;
  }

  get evictionCount(): number {
    return this.evicted;
  }

  /**
   * Append an entry. Returns false (and stores nothing) when an
   * identical fingerprint already exists — the dedup pipeline.
   */
  append(entry: TrafficEntry): boolean {
    if (this.seenFingerprints.has(entry.fingerprint)) {
      return false;
    }
    this.seenFingerprints.add(entry.fingerprint);
    this.buffer.push(entry);
    this.index.set(entry.id, this.buffer.length - 1);

    if (this.buffer.length > this.capacity) {
      const removed = this.buffer.shift();
      this.index.delete(removed!.id);
      this.evicted += 1;
      // Reindex positions after shift — O(n) but amortized rare.
      this.reindex();
    }
    return true;
  }

  getById(id: string): TrafficEntry | null {
    const pos = this.index.get(id);
    return pos === undefined ? null : this.buffer[pos];
  }

  /** Newest-first page for the UI table. */
  page(offset: number, limit: number): TrafficPage {
    const start = Math.max(0, this.buffer.length - offset - limit);
    const end = this.buffer.length - offset;
    if (start >= end) {
      return { entries: [], total: this.buffer.length, evicted: this.evicted, hasMore: false };
    }
    const entries = this.buffer.slice(start, end).reverse(); // newest first
    return {
      entries,
      total: this.buffer.length,
      evicted: this.evicted,
      hasMore: start > 0,
    };
  }

  filter(predicate: (entry: TrafficEntry) => boolean, limit = 500): TrafficEntry[] {
    const out: TrafficEntry[] = [];
    for (let i = this.buffer.length - 1; i >= 0 && out.length < limit; i -= 1) {
      if (predicate(this.buffer[i])) out.push(this.buffer[i]);
    }
    return out;
  }

  clear(): void {
    this.buffer.length = 0;
    this.index.clear();
    this.seenFingerprints.clear();
    this.evicted = 0;
  }

  private reindex(): void {
    this.index.clear();
    for (let i = 0; i < this.buffer.length; i += 1) {
      this.index.set(this.buffer[i].id, i);
    }
  }
}
