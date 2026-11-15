// Runs every compiled *.test.js under dist/test with the built-in node:test runner.
// (A directory argument to `node --test` is handled differently across Node 20-24,
// and glob arguments need Node 21+, so the files are listed here.)
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run } from 'node:test';
import { spec } from 'node:test/reporters';

function findTests(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? findTests(join(dir, e.name)) : e.name.endsWith('.test.js') ? [join(dir, e.name)] : []))
    .sort();
}

const files = findTests(join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'test'));
const stream = run({ files, concurrency: true });
stream.on('test:fail', () => {
  process.exitCode = 1;
});
stream.compose(spec).pipe(process.stdout);
