import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

register(new URL('./resolve-ts-hook.mjs', import.meta.url).href, pathToFileURL('./'));
await import('./test/bugtools.test.ts');
