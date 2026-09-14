/**
 * HTTP message model shared by every engine.
 *
 * Deliberately minimal and immutable: once captured, a request or
 * response is never mutated — derivatives (repeater edits, fuzz
 * variants) create new messages. This gives the UI a stable
 * audit trail.
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

export interface HttpHeaders {
  readonly [name: string]: string; // names stored lowercased
}

export interface HttpRequest {
  readonly method: HttpMethod;
  readonly url: string;
  readonly headers: HttpHeaders;
  readonly body: Buffer;
}

export interface HttpResponse {
  readonly status: number;
  readonly statusText: string;
  readonly headers: HttpHeaders;
  readonly body: Buffer;
  /** Wall-clock duration of the exchange in milliseconds. */
  readonly durationMs: number;
}

export interface TrafficEntry {
  readonly id: string;
  readonly request: HttpRequest;
  readonly response: HttpResponse | null; // null while in-flight or failed
  readonly capturedAt: number; // epoch millis
  /** SHA-256 of method + host + path + sorted query keys — dedup fingerprint. */
  readonly fingerprint: string;
  readonly source: 'proxy' | 'repeater' | 'fuzzer';
}

export class TrafficEntryBuilder {
  private response: HttpResponse | null = null;

  constructor(
    private readonly request: HttpRequest,
    private readonly fingerprint: string,
    private readonly source: TrafficEntry['source'],
    private readonly capturedAt: number = Date.now(),
  ) {}

  withResponse(response: HttpResponse): TrafficEntryBuilder {
    this.response = response;
    return this;
  }

  build(id: string): TrafficEntry {
    return Object.freeze({
      id,
      request: this.request,
      response: this.response,
      capturedAt: this.capturedAt,
      fingerprint: this.fingerprint,
      source: this.source,
    });
  }
}

export function normalizeHeaders(
  input: Record<string, string | string[] | undefined>,
): HttpHeaders {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(input)) {
    const key = name.toLowerCase();
    if (Array.isArray(value)) {
      out[key] = value.join(', ');
    } else if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}

export function safeParseJson(body: Buffer): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(body.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}
