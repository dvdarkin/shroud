// Port of src/Shroud.Tests.Integration/CliBehaviourTests.cs
// The CLI reads shroud.json and .shroud/vault.key relative to the current directory and
// writes to its output streams, both process-global, so these tests run one at a time
// (node:test runs the tests of one file sequentially, each test file in its own process).
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { main, setCliIo, setVaultMaskingKeyOverride } from '../../src/cli-program.js';

describe('CliBehaviourTests', () => {
  let dir = '';
  let oldCwd = '';

  beforeEach(() => {
    dir = join(tmpdir(), `shroud-cli-${randomUUID().replace(/-/g, '')}`);
    mkdirSync(dir, { recursive: true });
    oldCwd = process.cwd();
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(oldCwd);
    setVaultMaskingKeyOverride(null);
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  async function run(...args: string[]): Promise<{ exit: number; out: string; err: string }> {
    let out = '';
    let err = '';
    setCliIo({ stdout: (t) => void (out += t), stderr: (t) => void (err += t) });
    try {
      const exit = await main(args);
      return { exit, out, err };
    } finally {
      setCliIo(null);
    }
  }

  // ---- Fix 6 (CLI side) ----

  test('vault token collision, prints one line error, exits non zero, writes nothing', async () => {
    mkdirSync('src');
    const a = 'ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF71177';
    const b = 'ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF105486';
    writeFileSync(join('src', 'a.md'), `first ${a}\nsecond ${b}\n`);
    setVaultMaskingKeyOverride(Uint8Array.from({ length: 32 }, (_, i) => i));

    const { exit, out, err } = await run('vault', 'src', '-p', 'pw', '-o', 'out');

    assert.notEqual(exit, 0);
    const errorLines = err
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l !== '');
    assert.equal(errorLines.length, 1);
    assert.ok(errorLines[0]!.includes('TOKEN:908a4613'));
    assert.ok(!(out + err).includes(a) && !(out + err).includes(b));
    assert.equal(existsSync('out'), false);
  });

  // ---- Fix 7 (relative source) ----

  test('vault dot source, manifest source is the resolved directory name', async () => {
    const project = join(dir, 'alice-project');
    mkdirSync(project);
    writeFileSync(join(project, 'a.md'), 'wallet 0x1111111111111111111111111111111111111111\n');
    process.chdir(project);

    const { exit } = await run('vault', '.', '-p', 'pw', '-o', join(dir, 'out'));

    assert.equal(exit, 0);
    const manifest = JSON.parse(readFileSync(join(dir, 'out', 'manifest.json'), 'utf8')) as { source: string };
    assert.equal(manifest.source, 'alice-project');
  });

  // ---- Fix 8 ----

  test('mask several inputs with output file, is refused before writing anything', async () => {
    const a = 'wallet 0x1111111111111111111111111111111111111111\n';
    const b = 'wallet 0x2222222222222222222222222222222222222222\n';
    writeFileSync('a.md', a);
    writeFileSync('b.md', b);

    const { exit, err } = await run('mask', 'a.md', 'b.md', '-o', 'out.md');

    assert.notEqual(exit, 0);
    assert.ok(err.includes('-o'));
    assert.equal(existsSync('out.md'), false);
    assert.equal(readFileSync('a.md', 'utf8'), a);
    assert.equal(readFileSync('b.md', 'utf8'), b);
    assert.equal(existsSync('.shroud'), false, 'no key file is generated either');
  });

  test('mask glob expanding to several files with output file, is refused', async () => {
    writeFileSync('a.md', 'wallet 0x1111111111111111111111111111111111111111\n');
    writeFileSync('b.md', 'wallet 0x2222222222222222222222222222222222222222\n');

    const { exit } = await run('mask', '*.md', '-o', 'out.md');

    assert.notEqual(exit, 0);
    assert.equal(existsSync('out.md'), false);
  });

  test('mask single input with output file, still works', async () => {
    writeFileSync('a.md', 'wallet 0x1111111111111111111111111111111111111111\n');

    const { exit } = await run('mask', 'a.md', '-o', 'out.md');

    assert.equal(exit, 0);
    assert.ok(readFileSync('out.md', 'utf8').startsWith('wallet [ADDR:'));
  });

  // ---- Fix 9 ----

  test('init unknown preset, fails listing valid presets, writes nothing', async () => {
    const { exit, out, err } = await run('init', '--preset', 'bogus');

    assert.notEqual(exit, 0);
    assert.equal(existsSync('shroud.json'), false);
    for (const s of ['bogus', 'paranoid', 'financial', 'dev']) assert.ok(err.includes(s), s);
    assert.ok(!out.includes('Created'));
  });

  test('init known preset, still works', async () => {
    const { exit } = await run('init', '--preset', 'dev');

    assert.equal(exit, 0);
    assert.ok(readFileSync('shroud.json', 'utf8').includes('"preset": "dev"'));
  });

  // ---- Fix 10 ----

  test('scan verbose, structural pattern with context words, shows real breakdown', async () => {
    // visa: base 0.80, context "card" +0.15 -> 0.95
    writeFileSync('a.md', 'card 4111 1111 1111 1111\n');

    const { exit, out } = await run('scan', 'a.md', '--verbose');

    assert.equal(exit, 0);
    assert.ok(out.includes('0.95  4111 1111 1111 1111'));
    assert.ok(!out.includes('structural match (base: 0.80)\n') && !out.includes('structural match (base: 0.80)\r'));
    assert.ok(out.includes('(base: 0.80 + context: +0.15)'));
    assert.ok(out.includes('"card"'));
  });

  test('scan verbose, structural pattern without context words, unchanged', async () => {
    writeFileSync('a.md', 'wallet 0x1111111111111111111111111111111111111111\n');

    const { out } = await run('scan', 'a.md', '--verbose');

    assert.ok(out.includes('structural match (base: 0.95)'));
  });

  test('scan verbose, two same type patterns on one span, shows the winners scoring', async () => {
    // "1234.56" is a Quantity for large_number (0.20 + 0.45) and table_quantity (0.15 + 0.55);
    // table_quantity wins with 0.70, but large_number comes first in pattern order.
    writeFileSync('a.md', 'balance 1234.56\n');

    const { out } = await run('scan', 'a.md', '--verbose');

    assert.ok(out.includes('table_quantity'));
    assert.ok(out.includes('(base: 0.15 + context: +0.55)'));
    assert.ok(!out.includes('(base: 0.20 + context: +0.45)'));
  });
});
