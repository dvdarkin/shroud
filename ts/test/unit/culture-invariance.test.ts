// Port of src/Shroud.Tests.Unit/CultureInvarianceTests.cs
// Detection, token input and vault file order must not depend on the process culture.
// The C# tests switch CultureInfo.CurrentCulture to tr-TR; JavaScript regexes and
// Array.prototype.sort have no culture, so the port asserts the same results directly:
// the translated regexes use the .NET culture-invariant IgnoreCase table and files are
// ordered by UTF-16 code unit, which is what the fixed C# build does under every culture.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { describe, test } from 'node:test';
import { formatDouble } from '../../src/internal/dotnet-format.js';
import type { ScanResult } from '../../src/models.js';
import { getAllPatterns } from '../../src/pattern-library.js';
import { EXCLUSION_REGEXES, SensitivityScanner, matchesOf } from '../../src/scanner.js';
import { VaultBuilder } from '../../src/vault-builder.js';
import { decryptString } from '../../src/vault-encryption.js';

const ADDR_A = '0x1111111111111111111111111111111111111111';

const describeResult = (result: ScanResult) =>
  result.allDetected.map((s) => `${s.start}-${s.end} ${s.service} ${formatDouble(s.confidence)} ${s.matchedText}`);

function withTempDir<T>(action: (dir: string) => T): T {
  const dir = join(tmpdir(), `shroud-order-${randomUUID().replace(/-/g, '')}`);
  try {
    return action(dir);
  } finally {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
}

describe('CultureInvarianceTests', () => {
  test('every library regex, is culture invariant', () => {
    // The C# test checks RegexOptions.CultureInvariant on every regex. In the port that means:
    // no JS flags (so no `i` folding or locale), and no code unit of the culture-dependent
    // dotted/dotless I pair (U+0130, U+0131) added by the IgnoreCase expansion.
    const regexes = [...getAllPatterns().map((p) => p.regex), ...EXCLUSION_REGEXES];
    assert.ok(regexes.length > 100, 'the pattern library and the exclusion regexes are all checked');
    for (const re of regexes) {
      assert.equal(re.flags, '', re.source.slice(0, 60));
      assert.ok(!/\\u013[01]/i.test(re.source), re.source.slice(0, 60));
    }
  });

  describe('pattern library, under turkish culture, matches uppercase ascii i', () => {
    for (const [line, service] of [
      ['VALIDATOR #548231', 'eth_validator_index'],
      ['LOGIN = "bobby"', 'login_assignment'],
      ['API_KEY = "key-67890"', 'password_assignment'],
      ['POSITION #77 UNISWAP LIQUIDITY', 'lp_position_id'],
    ] as const) {
      test(line, () => {
        const result = new SensitivityScanner().scan(line);
        assert.ok(result.aboveThreshold.some((s) => s.service === service), service);
      });
    }
  });

  test('exclusion regexes, rebuilt under turkish culture, match like the invariant ones', () => {
    // Front matter, file path and the nine date/time regexes, in that order (EXCLUSION_REGEXES).
    const text = 'FILE: ' + ADDR_A + '\nSOURCE_FILE: x\nPATH: y\nATTACHMENT: z\nAPRIL 8, 2025 at 5 PM\n';
    const zones = EXCLUSION_REGEXES.map((re) => matchesOf(re, text).map((m) => [m.index, m.length]));
    assert.deepEqual(zones, [
      [],
      [[0, 48], [49, 14], [64, 7], [72, 13]], // every uppercase key is a metadata key
      [], [], [], [], [],
      [[86, 13]], // APRIL 8, 2025: month-name date
      [],
      [[103, 4]], // 5 PM: 12-hour clock
      [[95, 4]], // 2025: bare year
    ]);
  });

  test('freshly loaded scanner, under turkish culture, scans like the invariant one', () => {
    const text =
      '## Notes\n\nVALIDATOR #548231\nFILE: ' + ADDR_A + '\nLOGIN = "bobby"\n' +
      'API_KEY = "key-67890"\nPOSITION #77 UNISWAP LIQUIDITY\n';
    const actual = describeResult(new SensitivityScanner().scan(text));

    // The C# invariant-culture result for the same text.
    assert.deepEqual(actual, [
      '10-27 eth_validator_index 0.85 VALIDATOR #548231',
      '77-92 login_assignment 0.7 LOGIN = "bobby"',
      '93-114 password_assignment 0.85 API_KEY = "key-67890"',
      '115-127 lp_position_id 0.9500000000000001 POSITION #77',
    ]);
    assert.ok(!actual.some((s) => s.includes(ADDR_A)), 'the FILE: line is a metadata line in every culture');
  });

  test('build, under turkish culture, orders files ordinally by relative path', () => {
    withTempDir((dir) => {
      mkdirSync(join(dir, 'sub'), { recursive: true });
      for (const name of ['c.md', 'sub_y.md', 'a.md', 'Index.md', 'sub-x.md', 'B.md', join('sub', 'z.md'), 'ilk.md']) {
        writeFileSync(join(dir, name), 'plain text\n');
      }

      const result = new VaultBuilder().build(dir);

      // Ordinal (UTF-16 code unit) order of the stored relative path, separator included:
      // '-' (0x2D) < '/' (0x2F) and '\' (0x5C) < '_' (0x5F); uppercase before lowercase.
      const expected = ['B.md', 'Index.md', 'a.md', 'c.md', 'ilk.md', 'sub-x.md', `sub${sep}z.md`, 'sub_y.md'];
      assert.deepEqual(result.maskedFiles.map((f) => f.relativePath), expected);
    });
  });

  test('write output, under turkish culture, manifest and vault follow the ordinal file order', () => {
    withTempDir((dir) => {
      const src = join(dir, 'src');
      mkdirSync(src, { recursive: true });
      // The same address in every file: its manifest "files" list is the file order.
      for (const name of ['b.md', 'README.md', 'a.md']) writeFileSync(join(src, name), `wallet ${ADDR_A}\n`);

      const output = join(dir, 'out');
      const builder = new VaultBuilder();
      builder.writeOutput(builder.build(src), output, 'pw');

      const manifest = JSON.parse(readFileSync(join(output, 'manifest.json'), 'utf8')) as {
        tokens: Record<string, { files: string[] }>;
      };
      const tokens = Object.values(manifest.tokens);
      assert.equal(tokens.length, 1);
      assert.deepEqual(tokens[0]!.files, ['README.md', 'a.md', 'b.md']);

      const json = decryptString(readFileSync(join(output, 'vault.shroud')), 'pw')!;
      const vault = JSON.parse(json) as { fileHashes: Record<string, string> };
      assert.deepEqual(Object.keys(vault.fileHashes), ['README.md', 'a.md', 'b.md']);
    });
  });
});
