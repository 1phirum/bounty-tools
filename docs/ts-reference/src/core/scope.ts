/**
 * Scope manager — the single source of truth for what BugTools is
 * allowed to touch. Every outbound request from every engine passes
 * through `scope.isAllowed()` before hitting the wire.
 *
 * This is the defensive backbone: it prevents accidental traffic to
 * out-of-scope hosts, which is both a safety and a legal boundary in
 * authorized security research.
 */

import { BugToolsError } from './errors.js';

export type ScopeProtocol = 'http' | 'https';

export interface ScopeRule {
  readonly id: string;
  readonly protocol: ScopeProtocol | '*';
  readonly host: string; // lowercased; may lead with "*." for wildcard subdomains
  readonly port: number | '*';
  readonly pathPrefix: string; // must start with "/"
  readonly note?: string;
}

export interface ScopeDecision {
  readonly allowed: boolean;
  /** Which rule allowed (or the reason it was denied). */
  readonly reason: string;
}

export class ScopeManager {
  private readonly rules: ScopeRule[] = [];
  private readonly ruleIds = new Set<string>();

  addRule(rule: Omit<ScopeRule, 'id'>): ScopeRule {
    const id = `scope-${this.rules.length + 1}-${rule.host.replace(/[^a-z0-9.]/g, '')}`;
    if (this.ruleIds.has(id)) {
      throw new BugToolsError('E_CONFIG_INVALID', `duplicate scope rule id "${id}"`, { id });
    }
    const normalized: ScopeRule = {
      ...rule,
      id,
      host: rule.host.toLowerCase(),
      pathPrefix: rule.pathPrefix.startsWith('/') ? rule.pathPrefix : `/${rule.pathPrefix}`,
    };
    this.rules.push(normalized);
    this.ruleIds.add(id);
    return normalized;
  }

  removeRule(id: string): boolean {
    const index = this.rules.findIndex((r) => r.id === id);
    if (index === -1) return false;
    this.ruleIds.delete(id);
    this.rules.splice(index, 1);
    return true;
  }

  listRules(): readonly ScopeRule[] {
    return [...this.rules];
  }

  count(): number {
    return this.rules.length;
  }

  /**
   * Decide whether a request is in scope.
   *
   * Matching semantics:
   *  - host: exact match, or "*.example.com" matches any single-label
   *    subtree beneath example.com (multi-level included).
   *  - port: exact match or "*".
   *  - pathPrefix: request path must start with the rule prefix.
   */
  isAllowed(url: URL): ScopeDecision {
    for (const rule of this.rules) {
      if (rule.protocol !== '*' && rule.protocol !== url.protocol.replace(':', '')) continue;
      if (rule.port !== '*' && rule.port !== Number(url.port || (url.protocol === 'https:' ? 443 : 80)))
        continue;
      if (!hostMatches(rule.host, url.hostname.toLowerCase())) continue;
      if (!url.pathname.startsWith(rule.pathPrefix)) continue;
      return { allowed: true, reason: `matched rule ${rule.id}` };
    }
    return {
      allowed: false,
      reason: this.rules.length === 0 ? 'scope is empty — no rules defined' : 'no rule matched',
    };
  }

  /** Convenience for engines: throws E_SCOPE_VIOLATION when denied. */
  assertAllowed(url: URL): void {
    const decision = this.isAllowed(url);
    if (!decision.allowed) {
      throw new BugToolsError('E_SCOPE_VIOLATION', `out-of-scope target blocked: ${url.host}`, {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        reason: decision.reason,
      });
    }
  }
}

function hostMatches(pattern: string, host: string): boolean {
  if (pattern === host) return true;
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2); // e.g. "example.com"
    return host === base || host.endsWith(`.${base}`);
  }
  return false;
}
