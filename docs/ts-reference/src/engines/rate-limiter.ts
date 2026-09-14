/**
 * Token-bucket rate limiter — protects target infrastructure during
 * aggressive testing. Shared by repeater and fuzzer engines.
 *
 * Tokens refill continuously; `tryConsume` is a synchronous,
 * allocation-free check that returns immediately (no queueing), so
 * engines can decide to wait, defer, or fail fast.
 */

import { BugToolsError } from '../core/errors.js';
import type { RateLimitConfig } from '../core/config.js';

export class RateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(private readonly config: RateLimitConfig) {
    if (config.burst <= 0 || config.refillPerSecond <= 0) {
      throw new BugToolsError(
        'E_CONFIG_INVALID',
        'rate limiter requires burst > 0 and refillPerSecond > 0',
        config,
      );
    }
    this.tokens = config.burst;
    this.lastRefill = Date.now();
  }

  /** Refill based on elapsed wall time. */
  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    if (elapsed <= 0) return;
    this.tokens = Math.min(this.config.burst, this.tokens + elapsed * this.config.refillPerSecond);
    this.lastRefill = now;
  }

  /** Attempt to consume one token. Returns false if the bucket is empty. */
  tryConsume(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /** Milliseconds until the next token is available (0 if available now). */
  msUntilNextToken(): number {
    this.refill();
    if (this.tokens >= 1) return 0;
    const deficit = 1 - this.tokens;
    return Math.ceil((deficit / this.config.refillPerSecond) * 1000);
  }

  currentTokens(): number {
    this.refill();
    return this.tokens;
  }
}
