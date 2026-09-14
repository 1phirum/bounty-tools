/**
 * Module resolution hook: maps ".js" import specifiers to ".ts" files on disk.
 * Lets Node run TypeScript sources directly with `--experimental-transform-types`.
 * (Until tsgo ships full project references, this is the zero-build dev loop.)
 */

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (specifier.endsWith('.js') && (err.code === 'ERR_MODULE_NOT_FOUND')) {
      const tsSpecifier = specifier.replace(/\.js$/, '.ts');
      return nextResolve(tsSpecifier, context);
    }
    throw err;
  }
}
