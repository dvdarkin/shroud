// Port of src/Shroud.Tests.Integration/CliBehaviourTests.cs
// The CLI reads shroud.json and .shroud/vault.key relative to the current directory and
// writes to its output streams, both process-global, so these tests run one at a time
// (node:test runs the tests of one file sequentially, each test file in its own process).
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { type Dirent, appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
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

  // ---- Culture independence: numbers in CLI output are invariant ----
  // The C# tests run these under tr-TR; Node formats numbers without a culture.

  test('scan verbose, under turkish culture, prints invariant numbers', async () => {
    // tr-TR writes 0.95 as "0,95"; the report must not depend on the user's locale.
    writeFileSync('a.md', 'card 4111 1111 1111 1111\nseed abandon\n');

    const { exit, out } = await run('scan', 'a.md', '--verbose', '--debug');

    assert.equal(exit, 0);
    assert.ok(out.includes('0.95  4111 1111 1111 1111'));
    assert.ok(out.includes('(base: 0.80 + context: +0.15)'));
    assert.ok(out.includes('Below threshold (0.50):'));
    for (const s of ['0,95', '0,80', '0,15', '0,50']) assert.ok(!out.includes(s), s);
  });

  test('init, under turkish culture, prints invariant threshold', async () => {
    const { exit, out } = await run('init', '--preset', 'dev');

    assert.equal(exit, 0);
    assert.ok(out.includes('Threshold: 0.7'));
    assert.ok(!out.includes('0,7'));
  });

  // ---- CLI audit: output locations ----

  const WALLET = '0x1111111111111111111111111111111111111111';

  function filesUnder(root: string): string[] {
    return (readdirSync(root, { recursive: true, withFileTypes: true }) as Dirent[])
      .filter((e) => e.isFile())
      .map((e) => relative(root, join(e.parentPath, e.name)).replaceAll('\\', '/'))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  }

  test('reveal vault dir without shroud suffix, reveals next to it, never into the vault', async () => {
    mkdirSync('notes');
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);
    assert.equal((await run('vault', 'notes', '-p', 'pw', '-o', 'out')).exit, 0);

    const { exit } = await run('reveal', 'out', '-p', 'pw');

    assert.equal(exit, 0);
    assert.deepEqual(filesUnder('out'), ['manifest.json', 'public/a.md', 'vault.shroud']);
    assert.equal(readFileSync(join('out.revealed', 'a.md'), 'utf8'), `wallet ${WALLET}\n`);
  });

  test('reveal default output, replaces only the trailing shroud suffix', async () => {
    const notes = join('my.shroud.stuff', 'notes');
    mkdirSync(notes, { recursive: true });
    writeFileSync(join(notes, 'a.md'), `wallet ${WALLET}\n`);
    assert.equal((await run('vault', notes, '-p', 'pw')).exit, 0);

    const { exit } = await run('reveal', notes + '.shroud' + sep, '-p', 'pw');

    assert.equal(exit, 0);
    assert.ok(existsSync(join('my.shroud.stuff', 'notes.revealed', 'a.md')));
    assert.equal(existsSync('my.revealed.stuff'), false);
  });

  test('reveal output inside the vault directory, is refused', async () => {
    mkdirSync('notes');
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);
    assert.equal((await run('vault', 'notes', '-p', 'pw')).exit, 0);

    const { exit, err } = await run('reveal', 'notes.shroud', '-p', 'pw', '-o', join('notes.shroud', 'public'));

    assert.notEqual(exit, 0);
    assert.ok(err.includes('inside the vault directory'));
    assert.ok(!readFileSync(join('notes.shroud', 'public', 'a.md'), 'utf8').includes(WALLET));
  });

  test('vault dot source, default output is a sibling of the source, and a second run does not nest', async () => {
    const project = join(dir, 'alice-project');
    mkdirSync(project);
    writeFileSync(join(project, 'a.md'), `wallet ${WALLET}\n`);
    process.chdir(project);

    assert.equal((await run('vault', '.', '-p', 'pw')).exit, 0);
    assert.equal((await run('vault', '.', '-p', 'pw')).exit, 0);

    assert.deepEqual(filesUnder(project), ['a.md']);
    assert.deepEqual(filesUnder(join(dir, 'alice-project.shroud')), ['manifest.json', 'public/a.md', 'vault.shroud']);
  });

  test('vault output inside the source, is refused, writes nothing', async () => {
    mkdirSync('notes');
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);

    const { exit, err } = await run('vault', 'notes', '-p', 'pw', '-o', join('notes', 'out'));

    assert.notEqual(exit, 0);
    assert.ok(err.includes('inside the source directory'));
    assert.equal(existsSync(join('notes', 'out')), false);
  });

  test('vault second run, removes masked copies of files no longer in the source', async () => {
    mkdirSync(join('notes', 'sub'), { recursive: true });
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);
    writeFileSync(join('notes', 'sub', 'gone.md'), 'wallet 0x2222222222222222222222222222222222222222\n');
    assert.equal((await run('vault', 'notes', '-p', 'pw')).exit, 0);
    writeFileSync(join('notes.shroud', 'public', 'keep.txt'), 'not ours');
    rmSync(join('notes', 'sub', 'gone.md'));

    assert.equal((await run('vault', 'notes', '-p', 'pw')).exit, 0);

    assert.deepEqual(filesUnder('notes.shroud'), ['manifest.json', 'public/a.md', 'public/keep.txt', 'vault.shroud']);
    const { exit, err } = await run('reveal', 'notes.shroud', '-p', 'pw');
    assert.equal(exit, 0);
    assert.equal(err, '');
  });

  // ---- CLI audit: reveal integrity ----

  test('reveal public file changed or added, warns, and leaves unknown tokens in place', async () => {
    mkdirSync('notes');
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);
    assert.equal((await run('vault', 'notes', '-p', 'pw')).exit, 0);
    const publicDir = join('notes.shroud', 'public');
    appendFileSync(join(publicDir, 'a.md'), 'edited [ADDR:00000000]\n');
    writeFileSync(join(publicDir, 'extra.md'), 'hello\n');

    const { exit, err } = await run('reveal', 'notes.shroud', '-p', 'pw');

    assert.equal(exit, 0);
    assert.ok(err.includes('a.md was changed after it was vaulted'));
    assert.ok(err.includes('a.md: 1 token(s) are not in this vault'));
    assert.ok(err.includes('extra.md is not part of this vault'));
    assert.equal(readFileSync(join('notes.revealed', 'a.md'), 'utf8'), `wallet ${WALLET}\nedited [ADDR:00000000]\n`);
  });

  // ---- CLI audit: arguments and exit codes ----

  test('scan missing file, exits one, but still scans the others', async () => {
    writeFileSync('a.md', `wallet ${WALLET}\n`);

    const { exit, out, err } = await run('scan', 'nope.md', 'a.md');

    assert.equal(exit, 1);
    assert.ok(err.includes('File not found: nope.md'));
    assert.ok(out.includes('evm_address'));
  });

  test('scan unknown option, is refused, not treated as a file', async () => {
    writeFileSync('a.md', `wallet ${WALLET}\n`);

    const { exit, out, err } = await run('scan', 'a.md', '--json');

    assert.equal(exit, 1);
    assert.ok(err.includes('Unknown option: --json'));
    assert.equal(out, '');
  });

  test('scan exit code flag, two when something would be tokenized, zero when clean', async () => {
    writeFileSync('dirty.md', `wallet ${WALLET}\n`);
    writeFileSync('clean.md', 'nothing to see here\n');

    assert.equal((await run('scan', 'dirty.md')).exit, 0);
    assert.equal((await run('scan', 'dirty.md', '--exit-code')).exit, 2);
    assert.equal((await run('scan', 'clean.md', 'dirty.md', '--exit-code')).exit, 2);
    assert.equal((await run('scan', 'clean.md', '--exit-code')).exit, 0);
  });

  test('options without a value, or unknown, are refused', async () => {
    mkdirSync('notes');
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);

    let r = await run('vault', 'notes', '-p');
    assert.equal(r.exit, 1);
    assert.ok(r.err.includes('Option -p needs a value.'));

    r = await run('vault', 'notes', '-p', 'pw', '--force');
    assert.equal(r.exit, 1);
    assert.ok(r.err.includes('Unknown option: --force'));
    assert.equal(existsSync('notes.shroud'), false);
  });

  test('command name, wins over a directory of the same name', async () => {
    mkdirSync('scan');
    writeFileSync(join('scan', 'a.md'), `wallet ${WALLET}\n`);
    writeFileSync('a.md', `wallet ${WALLET}\n`);

    const { exit, out } = await run('scan', 'a.md');

    assert.equal(exit, 0);
    assert.ok(out.includes('evm_address'));
    assert.equal(existsSync('scan.shroud'), false);
  });

  test('directory as first argument, is still the vault command', async () => {
    mkdirSync('notes');
    writeFileSync(join('notes', 'a.md'), `wallet ${WALLET}\n`);

    assert.equal((await run('notes', '-p', 'pw')).exit, 0);

    assert.ok(existsSync(join('notes.shroud', 'vault.shroud')));
  });

  // ---- CLI audit: init and mask wording ----

  test('init without preset, writes paranoid, the same as having no config', async () => {
    const { exit, out } = await run('init');

    assert.equal(exit, 0);
    assert.ok(readFileSync('shroud.json', 'utf8').includes('"preset": "paranoid"'));
    assert.ok(out.includes('Threshold: 0.5'));
    assert.ok(out.includes('credentials=True, secrets=True'));
  });

  test('mask in place, says it is one way, and the key message does not promise unmasking', async () => {
    writeFileSync('a.md', `wallet ${WALLET}\n`);

    const { exit, err } = await run('mask', 'a.md');

    assert.equal(exit, 0);
    assert.ok(err.includes('Generated new key'));
    assert.ok(err.includes('cannot unmask'));
    assert.ok(err.includes('one-way'));
    assert.ok(!err.includes('cannot be unmasked'));
  });

  test('mask to output file, prints no in place note', async () => {
    writeFileSync('a.md', `wallet ${WALLET}\n`);

    const { err } = await run('mask', 'a.md', '-o', 'out.md');

    assert.ok(!err.includes('one-way'));
    assert.equal(readFileSync('a.md', 'utf8'), `wallet ${WALLET}\n`);
  });
});
