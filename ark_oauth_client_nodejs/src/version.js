import { createRequire } from 'node:module';

/**
 * The version of this package, read from its own package.json.
 *
 * Read rather than written here, so `scripts/version.sh set` has one manifest to stamp and this can
 * never drift from what npm published — the Python client's `__version__` did, more than once, and
 * the access-denied page then named the wrong release.
 */
export const VERSION = createRequire(import.meta.url)('../package.json').version;
