/**
 * End-to-end smoke: bootstrap the full backend against a live,
 * sandbox-safe public API target to prove the engines work together.
 */

import { createBackend } from './index.js';

const backend = createBackend(undefined, { interceptMode: false });

backend.scope.addRule({
  protocol: 'https',
  host: 'jsonplaceholder.typicode.com',
  port: 443,
  pathPrefix: '/',
  note: 'public JSON fixture API used for smoke testing only',
});

const req = Object.freeze({
  method: 'GET',
  url: 'https://jsonplaceholder.typicode.com/todos/1',
  headers: Object.freeze({ accept: 'application/json' }),
  body: Buffer.alloc(0),
});

const decision = backend.proxy.classify(req);
console.log('classify:', JSON.stringify(decision));

const entry = await backend.proxy.forward(req);
console.log('forwarded:', entry.id, '| status:', entry.response?.status, '| duration:', entry.response?.durationMs + 'ms');

console.log('store size:', backend.store.size, '| scope rules:', backend.scope.count());

const run = await backend.repeater.send(req, {
  headerOverrides: { 'x-bugtools-probe': 'repeater-smoke' },
});
console.log('repeater replay status:', run.response.status, '| header merged:', run.sent.headers['x-bugtools-probe']);

console.log('store total after repeater:', backend.store.size);

// Scope enforcement smoke: out-of-scope target must be blocked.
try {
  await backend.proxy.forward({
    method: 'GET',
    url: 'https://definitely-out-of-scope.example.net/nope',
    headers: {},
    body: Buffer.alloc(0),
  });
  console.error('SCOPE BYPASS — this must never happen');
  process.exit(1);
} catch (err) {
  console.log('scope blocked out-of-scope target ✓ (code:', err.code + ')');
}

// Fuzzer smoke: tiny run against in-scope endpoint with 2 payloads.
const fuzzBase = Object.freeze({
  method: 'GET',
  url: 'https://jsonplaceholder.typicode.com/todos/§id§',
  headers: Object.freeze({ accept: 'application/json' }),
  body: Buffer.alloc(0),
});
const summary = await backend.fuzzer.run(fuzzBase, [
  { marker: '§id§', payloads: ['1', '2'] },
], { concurrency: 2 });
console.log('fuzzer run: total', summary.total, '| completed', summary.completed, '| failed', summary.failed, '| deduped', summary.deduped);

console.log('\nAll smoke checks passed.');
