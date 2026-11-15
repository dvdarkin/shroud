// Port of src/Shroud.Tests.Integration/VaultBuilderIntegrityTests.cs
// VaultBuilder correctness: manifest service ids, token id collisions, and no absolute
// paths in the public manifest.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { sep } from 'node:path';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { defaultConfig } from '../../src/config.js';
import { pathCombine } from '../../src/internal/dotnet-path.js';
import { readAllText } from '../../src/internal/text-io.js';
import { ENTITY_TYPES, type EntityType } from '../../src/models.js';
import { getAllPatterns } from '../../src/pattern-library.js';
import { SensitivityScanner } from '../../src/scanner.js';
import { TokenCollisionException, VaultBuilder } from '../../src/vault-builder.js';

// Two different GitHub PAT-shaped fake values whose 4-byte HMAC prefix collides under
// the fixed key 0x00..0x1f (found by brute force): both mask to TOKEN:908a4613.
const COLLIDING_A = 'ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF71177';
const COLLIDING_B = 'ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF105486';
const COLLIDING_ID = 'TOKEN:908a4613';
const FIXED_KEY = Uint8Array.from({ length: 32 }, (_, i) => i);

/** Path.GetTempPath(): the temp directory with a trailing separator. */
const tempPath = () => (tmpdir().endsWith(sep) ? tmpdir() : tmpdir() + sep);

describe('VaultBuilderIntegrityTests', () => {
  let root = '';
  let sourceDir = '';

  beforeEach(() => {
    root = pathCombine(tmpdir(), `shroud-vb-${randomUUID().replace(/-/g, '')}`);
    sourceDir = pathCombine(root, 'my-notes');
    mkdirSync(sourceDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(root)) rmSync(root, { recursive: true, force: true });
  });

  const fixedKeyBuilder = () => new VaultBuilder(new SensitivityScanner(defaultConfig()), FIXED_KEY);

  // ---- Fix 5 ----

  test('manifest service, belongs to a pattern of the tokens own entity type', () => {
    // The same text "1,234" is a Quantity on line 1 and an Amount on line 3.
    writeFileSync(pathCombine(sourceDir, 'a.md'), 'bought 1,234 units.\n\nfee 1,234 = 5 usd\n');

    const result = new VaultBuilder(defaultConfig()).build(sourceDir);

    const byService = new Map<string, Set<EntityType>>();
    for (const p of getAllPatterns()) {
      const set = byService.get(p.service) ?? new Set<EntityType>();
      set.add(p.entityType);
      byService.set(p.service, set);
    }
    assert.ok([...result.tokens.keys()].some((k) => k.startsWith('AMT:')), 'the Amount token exists');
    assert.ok([...result.tokens.keys()].some((k) => k.startsWith('QTY:')), 'the Quantity token exists');
    for (const [tokenId, entry] of result.tokens) {
      assert.ok(byService.has(entry.serviceId), `${tokenId} has a known service id`);
      // Enum.Parse<EntityType>(entry.Service)
      assert.ok((ENTITY_TYPES as readonly string[]).includes(entry.service));
      assert.ok(
        byService.get(entry.serviceId)!.has(entry.service as EntityType),
        `${tokenId} (${entry.service}) must not be labelled with another type's pattern '${entry.serviceId}'`,
      );
    }
  });

  // ---- Fix 6 ----

  test('seam, the two fixture values really collide', () => {
    const builder = fixedKeyBuilder();
    writeFileSync(pathCombine(sourceDir, 'a.md'), `token ${COLLIDING_A}\n`);
    const r1 = builder.build(sourceDir);
    writeFileSync(pathCombine(sourceDir, 'a.md'), `token ${COLLIDING_B}\n`);
    const r2 = builder.build(sourceDir);

    assert.deepEqual([...r1.tokens.keys()], [COLLIDING_ID]);
    assert.deepEqual([...r2.tokens.keys()], [COLLIDING_ID]);
  });

  test('token id collision in one file, throws without printing values', () => {
    writeFileSync(pathCombine(sourceDir, 'a.md'), `first ${COLLIDING_A}\nsecond ${COLLIDING_B}\n`);

    let ex: unknown;
    try {
      fixedKeyBuilder().build(sourceDir);
    } catch (e) {
      ex = e;
    }

    assert.ok(ex instanceof TokenCollisionException, 'TokenCollisionException is thrown');
    assert.equal(ex.tokenId, COLLIDING_ID);
    assert.ok(ex.message.includes(COLLIDING_ID));
    assert.ok(!ex.message.includes(COLLIDING_A) && !ex.message.includes(COLLIDING_B));
    assert.ok(!ex.message.includes('FFFFFFFF'), 'no fragment of an original value is printed');
  });

  test('token id collision across files, throws', () => {
    writeFileSync(pathCombine(sourceDir, 'a.md'), `first ${COLLIDING_A}\n`);
    writeFileSync(pathCombine(sourceDir, 'b.md'), `second ${COLLIDING_B}\n`);

    assert.throws(
      () => fixedKeyBuilder().build(sourceDir),
      (e: unknown) => e instanceof TokenCollisionException && e.tokenId === COLLIDING_ID,
    );
  });

  test('same value seen again, is not a collision', () => {
    writeFileSync(pathCombine(sourceDir, 'a.md'), `first ${COLLIDING_A}\nagain ${COLLIDING_A}\n`);
    writeFileSync(pathCombine(sourceDir, 'b.md'), `third ${COLLIDING_A}\n`);

    const result = fixedKeyBuilder().build(sourceDir);

    assert.ok(result.tokens.has(COLLIDING_ID));
    assert.equal(result.tokens.get(COLLIDING_ID)!.value, COLLIDING_A);
    assert.equal(result.tokens.get(COLLIDING_ID)!.occurrences, 3);
  });

  // ---- Fix 7 ----

  describe('manifest source, is only the directory name', () => {
    for (const trailingSeparator of [false, true]) {
      test(String(trailingSeparator), () => {
        writeFileSync(pathCombine(sourceDir, 'a.md'), 'wallet 0x1111111111111111111111111111111111111111\n');
        const source = trailingSeparator ? sourceDir + sep : sourceDir;
        const outDir = pathCombine(root, 'out');

        const builder = new VaultBuilder(defaultConfig());
        builder.writeOutput(builder.build(source), outDir, 'pw');

        const manifestText = readAllText(pathCombine(outDir, 'manifest.json'));
        assert.equal((JSON.parse(manifestText) as { source: string }).source, 'my-notes');
        const tempWithoutSep = tempPath().slice(0, -sep.length).replace(/\\/g, '\\\\');
        assert.ok(!manifestText.includes(tempWithoutSep), 'the public manifest must not leak the absolute location');
      });
    }
  });
});
