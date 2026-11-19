// Builds the files for apps with no bundler at all. Bundler users import `src/` directly (plain
// ES modules, no build step); this only produces:
//
//   dist/ark-oauth-client.global.js      <script src> → window.ArkOAuth   (readable)
//   dist/ark-oauth-client.global.min.js  the same, minified               (unpkg/jsdelivr default)
//   dist/ark-oauth-client.esm.min.js     one-file ES module, for <script type="module"> or an import map
//
// Runs on `npm pack` / `npm publish` (prepack), so dist/ is in the package but not in git.
import { build } from 'esbuild';
import { readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const banner = `/*! ark-oauth-client-js ${version} | MIT | https://github.com/ir-dev/ark-oauth-oidc */`;

const common = {
  entryPoints: [join(root, 'src/index.js')],
  bundle: true,
  // Private class fields and ??= are ES2022; every browser this targets (Chrome/Edge 94+,
  // Firefox 93+, Safari 15.4+) runs them natively, so nothing is down-levelled.
  target: ['es2022'],
  banner: { js: banner },
  legalComments: 'none',
  logLevel: 'warning'
};

await rm(join(root, 'dist'), { recursive: true, force: true });
await Promise.all([
  build({ ...common, format: 'iife', globalName: 'ArkOAuth', outfile: join(root, 'dist/ark-oauth-client.global.js') }),
  build({ ...common, format: 'iife', globalName: 'ArkOAuth', minify: true, sourcemap: true, outfile: join(root, 'dist/ark-oauth-client.global.min.js') }),
  build({ ...common, format: 'esm', minify: true, sourcemap: true, outfile: join(root, 'dist/ark-oauth-client.esm.min.js') })
]);

const size = async (file) => `${((await readFile(join(root, 'dist', file))).length / 1024).toFixed(1)} KiB`;
console.log(`built dist/ for ${version}: global ${await size('ark-oauth-client.global.js')}, global.min ${await size('ark-oauth-client.global.min.js')}, esm.min ${await size('ark-oauth-client.esm.min.js')}`);
