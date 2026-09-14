/**
 * Typed error taxonomy for the entire BugTools backend.
 *
 * Design rule: every failure crossing a subsystem boundary is a
 * BugToolsError with a machine-readable `code`, so the UI can render
 * precise, actionable status chips instead of stringly-typed messages.
 */

export type BugToolsErrorCode =
  | 'E_SCOPE_VIOLATION'
  | 'E_SCOPE_EMPTY'
  | 'E_RATE_LIMIT_EXCEEDED'
  | 'E_FUZZER_PAYLOAD_REJECTED'
  | 'E_FUZZER_NO_PAYLOADS'
  | 'E_CONFIG_INVALID'
  | 'E_REPEATER_TARGET_INVALID'
  | 'E_PROXY_BIND_FAILED'
  | 'E_TRAFFIC_ENTRY_NOT_FOUND'
  | 'E_INTERNAL';

export interface BugToolsErrorContext {
  readonly [key: string]: unknown;
}

export class BugToolsError extends Error {
  override readonly name: string = 'BugToolsError';

  constructor(
    public readonly code: BugToolsErrorCode,
    message: string,
    public readonly context: BugToolsErrorContext = {},
    public readonly cause?: unknown,
  ) {
    super(message);
    // Maintain correct prototype chain when compiled down to ES5 targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Wire-format for the frontend: flat, serializable, stable keys. */
  toJSON(): {
    code: BugToolsErrorCode;
    message: string;
    context: BugToolsErrorContext;
  } {
    return {
      code: this.code,
      message: this.message,
      context: this.context,
    };
  }
}

export function isBugToolsError(value: unknown): value is BugToolsError {
  return value instanceof BugToolsError;
}

/** Wrap an unknown throw into a typed internal error without losing detail. */
export function normalizeError(value: unknown, where: string): BugToolsError {
  if (isBugToolsError(value)) return value;
  const message = value instanceof Error ? value.message : String(value);
  return new BugToolsError('E_INTERNAL', `${where}: ${message}`, {}, value);
}
