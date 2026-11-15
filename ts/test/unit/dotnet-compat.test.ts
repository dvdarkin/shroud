// Pins the .NET behaviours the port reproduces where JavaScript differs. Expected values
// were observed on .NET 8 (tools/dotnet-probe); tools/differential.mjs checks the same
// behaviours at scale. This file has no C# counterpart.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { describe, test } from 'node:test';
import { formatDouble, formatFixed } from '../../src/internal/dotnet-format.js';
import { escapeJsonString } from '../../src/internal/dotnet-json.js';
import { compileSearchPattern } from '../../src/internal/dotnet-path.js';
import { UnsupportedRegexError, dotnetRegex } from '../../src/internal/dotnet-regex.js';
import { containsOrdinalIgnoreCase } from '../../src/internal/ordinal.js';
import { readAllText } from '../../src/internal/text-io.js';
import { isValidLuhn } from '../../src/luhn.js';
import { sourceDirectoryName } from '../../src/vault-builder.js';

const all = (re: RegExp, s: string) => [...s.matchAll(new RegExp(re, 'g'))].map((m) => [m.index, m[0]]);

describe('DotnetCompatTests', () => {
  describe('regex translation', () => {
    test('\\d is Unicode Nd on UTF-16 code units (BMP only)', () => {
      const d = dotnetRegex(String.raw`^\d+$`);
      assert.ok(d.test('١٢٣')); // Arabic-Indic
      assert.ok(d.test('１２')); // fullwidth
      assert.ok(!d.test('𝟎')); // MATHEMATICAL BOLD DIGIT ZERO is a surrogate pair in .NET
      assert.ok(!d.test('²')); // superscript two is No, not Nd
    });

    test('\\s includes U+0085 and excludes U+FEFF', () => {
      const s = dotnetRegex(String.raw`^\s$`);
      assert.ok(s.test('\u0085'));
      assert.ok(!s.test('﻿'));
      assert.ok(s.test(' '));
    });

    test('\\w uses .NET 8 Unicode data, not the JS engine\'s', () => {
      const w = dotnetRegex(String.raw`^\w$`);
      assert.ok(w.test('é'));
      assert.ok(w.test('́')); // Mn
      assert.ok(!w.test('ः')); // Mc is not a .NET word character
      assert.ok(!w.test('ࢗ')); // assigned after .NET 8's Unicode version; JS \p{L} etc. may include it
    });

    test('\\b counts ZWJ/ZWNJ and non-ASCII letters as word characters', () => {
      const b = dotnetRegex(String.raw`\bab\b`);
      assert.deepEqual(all(b, 'xab ab éab ab‍'), [[4, 'ab']]);
    });

    test('. matches \\r and U+2028 (only \\n is excluded)', () => {
      assert.deepEqual(all(dotnetRegex('a.b'), 'a\rb a b a\nb'), [[0, 'a\rb'], [4, 'a b']]);
    });

    test('multiline ^ and $ anchor at \\n only', () => {
      const re = dotnetRegex('^x$', { multiline: true });
      // "x\r" is not at an end of line for .NET: only the first and last x match.
      assert.deepEqual(all(re, 'x\nx\r\nx'), [[0, 'x'], [5, 'x']]);
    });

    test('non-multiline $ also matches before a final \\n', () => {
      assert.ok(dotnetRegex('x$').test('x\n'));
      assert.ok(!dotnetRegex('x$').test('x\n\n'));
    });

    test('IgnoreCase uses the .NET case table (KELVIN SIGN, dotted I) and not JS folding', () => {
      const k = dotnetRegex('(?i)block');
      assert.ok(k.test('BLOCK'));
      const i = dotnetRegex('(?i)validator');
      assert.ok(i.test('VALİDATOR'));
      assert.ok(!i.test('valıdator')); // dotless i does not match
      assert.ok(!dotnetRegex('(?i)position').test('poſition')); // long s does not match
    });

    test('lookbehind and lazy quantifiers keep .NET semantics', () => {
      assert.deepEqual(all(dotnetRegex(String.raw`(?<=(?<!=)=\s?)\d+`), 'a = 5, b == 6'), [[4, '5']]);
      assert.deepEqual(all(dotnetRegex('a.*?b'), 'aXbYb'), [[0, 'aXb']]);
    });

    test('\\p{L} and \\p{Nd} use .NET 8 Unicode data, also inside a class and under IgnoreCase', () => {
      // Membership observed on .NET 8 (probe "classes": letter, pNd, metadataKeyGuardCi).
      const letter = dotnetRegex(String.raw`^\p{L}$`);
      for (const c of ['é', 'Ж', '中', 'ʰ', 'ª', 'ǅ', '々']) assert.ok(letter.test(c), c);
      for (const c of ['٣', '_', '-', '́', '²', '‿', 'ः', 'Ⅰ', '〇', '😀']) assert.ok(!letter.test(c), c);
      const digit = dotnetRegex(String.raw`^\p{Nd}$`);
      assert.ok(digit.test('٣') && digit.test('３') && !digit.test('²') && !digit.test('a'));
      assert.ok(dotnetRegex(String.raw`^\P{L}$`).test('٣'));
      const guard = dotnetRegex(String.raw`^[\p{L}\p{Nd}_\-]$`, { ignoreCase: true, multiline: true });
      for (const c of ['é', 'ʰ', '٣', '_', '-', 'K']) assert.ok(guard.test(c), c);
      for (const c of ['́', '²', '‿', ' ', '(', '.']) assert.ok(!guard.test(c), c);
    });

    test('\\A anchors at the start of the input only, also in multiline mode', () => {
      assert.deepEqual(all(dotnetRegex(String.raw`\A-`, { multiline: true }), '-\n-\r\n-'), [[0, '-']]);
      assert.deepEqual(all(dotnetRegex(String.raw`\A-`), 'x-'), []);
    });

    test('constructs outside the supported subset throw instead of translating approximately', () => {
      // \p{L} and \p{Nd} are supported since the C# file-path exclusion uses them; other categories are not.
      for (const p of [String.raw`(?>a)`, String.raw`(?<n>a)`, String.raw`\p{Lu}`, String.raw`[\p{Mn}]`, String.raw`a(?i)b`, String.raw`[a-z-[aeiou]]`, String.raw`\1`, String.raw`\A*`]) {
        assert.throws(() => dotnetRegex(p), UnsupportedRegexError, p);
      }
    });
  });

  describe('number formatting', () => {
    test('F2 breaks exact ties to even, like .NET (unlike toFixed)', () => {
      const cases: [number, string][] = [
        [0.125, '0.12'], [0.375, '0.38'], [0.625, '0.62'], [0.875, '0.88'], [2.675, '2.67'],
        [1.005, '1.00'], [0.005, '0.01'], [99.995, '100.00'], [0.9999, '1.00'], [-0.005, '-0.01'],
        [-0.001, '-0.00'], [-0, '-0.00'], [1e21, '1000000000000000000000.00'],
      ];
      for (const [value, expected] of cases) assert.equal(formatFixed(value, 2), expected, String(value));
    });

    test('double.ToString switches to E notation at exponent >= 17 or < -4', () => {
      const cases: [number, string][] = [
        [0.7, '0.7'], [1, '1'], [0.0001, '0.0001'], [0.00001, '1E-05'], [1e-7, '1E-07'],
        [1e16, '10000000000000000'], [1e17, '1E+17'], [1.2345678901234568e17, '1.2345678901234568E+17'],
        [5e-324, '5E-324'], [-0, '-0'], [0.30000000000000004, '0.30000000000000004'],
      ];
      for (const [value, expected] of cases) assert.equal(formatDouble(value), expected, String(value));
    });
  });

  describe('System.Text.Json escaping', () => {
    test('HTML-sensitive ASCII, controls and all non-ASCII are \\u-escaped', () => {
      // esc('0022') is the six-character JSON escape for U+0022 (built so no literal
      // backslash-u sequence appears in this source file).
      const esc = (...hex: string[]) => hex.map((h) => '\\' + 'u' + h).join('');
      const ch = (...codes: number[]) => String.fromCharCode(...codes);
      assert.equal(escapeJsonString('"&\'+<>`\\/'), '"' + esc('0022', '0026', '0027', '002B', '003C', '003E', '0060') + '\\\\/"');
      assert.equal(escapeJsonString('\b\t\n\f\r' + ch(0x01, 0x7f)), '"\\b\\t\\n\\f\\r' + esc('0001', '007F') + '"');
      assert.equal(escapeJsonString(ch(0xe9, 0xd83d, 0xde00)), '"' + esc('00E9', 'D83D', 'DE00') + '"');
      assert.equal(escapeJsonString('a' + ch(0xd800) + 'b' + ch(0xdc00)), '"a' + esc('FFFD') + 'b' + esc('FFFD') + '"');
    });
  });

  describe('text and comparison helpers', () => {
    test('OrdinalIgnoreCase never equates non-ASCII with ASCII letters', () => {
      assert.ok(containsOrdinalIgnoreCase('xUSDx', 'usd'));
      assert.ok(!containsOrdinalIgnoreCase('UNİ', 'uni'));
      assert.ok(!containsOrdinalIgnoreCase('K', 'k'));
      assert.ok(!containsOrdinalIgnoreCase('straße', 'strasse'));
    });

    test('ReadAllText strips a byte order mark and decodes UTF-16', () => {
      const dir = mkdtempSync(join(tmpdir(), 'shroud-bom-'));
      try {
        writeFileSync(join(dir, 'a'), Buffer.from([0xef, 0xbb, 0xbf, 0x61]));
        writeFileSync(join(dir, 'b'), Buffer.from([0xff, 0xfe, 0x62, 0x00]));
        writeFileSync(join(dir, 'c'), Buffer.from([0x63, 0xff]));
        assert.equal(readAllText(join(dir, 'a')), 'a');
        assert.equal(readAllText(join(dir, 'b')), 'b');
        assert.equal(readAllText(join(dir, 'c')), 'c' + String.fromCharCode(0xfffd));
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    test('Win32 search patterns: * and ?, with ? matching nothing before a dot', () => {
      assert.ok(compileSearchPattern('*.md')('notes.md'));
      assert.ok(!compileSearchPattern('*.md')('notes.mdx'));
      assert.ok(compileSearchPattern('a?.md')('a.md'));
      assert.ok(compileSearchPattern('a?.md')('ab.md'));
      assert.ok(compileSearchPattern('*.*')('README'));
    });

    test('Luhn treats any Unicode decimal digit as a digit, valued code - 0x30', () => {
      assert.ok(isValidLuhn('4532015112830366'));
      assert.ok(isValidLuhn('4532-0151-1283-0366'));
      assert.ok(!isValidLuhn('4532015112830367'));
      assert.ok(!isValidLuhn('453201511283'));
    });

    test('manifest source: GetFullPath + TrimEndingDirectorySeparator + GetFileName', () => {
      // Observed on .NET 8 (tools/dotnet-probe mode "paths"), relative to the current directory.
      const cwdName = basename(process.cwd());
      assert.equal(sourceDirectoryName('.'), cwdName);
      assert.equal(sourceDirectoryName('notes'), 'notes');
      assert.equal(sourceDirectoryName('notes/'), 'notes');
      assert.equal(sourceDirectoryName('a/./b/../c'), 'c');
      assert.equal(sourceDirectoryName('x//y'), 'y');
      if (process.platform === 'win32') {
        assert.equal(sourceDirectoryName('notes\\'), 'notes');
        assert.equal(sourceDirectoryName('notes.'), 'notes'); // Win32: trailing dots and spaces trimmed
        assert.equal(sourceDirectoryName('notes. '), 'notes');
        assert.equal(sourceDirectoryName('notes...'), 'notes');
        assert.equal(sourceDirectoryName('notes.\\'), 'notes'); // one trailing dot of a non-final segment
        assert.equal(sourceDirectoryName('notes. \\'), 'notes. ');
        assert.equal(sourceDirectoryName('a..\\b'), 'b');
        assert.equal(sourceDirectoryName('C:\\'), 'C:\\');
        assert.equal(sourceDirectoryName('C:/'), 'C:\\');
        assert.equal(sourceDirectoryName('C:\\..\\..'), 'C:\\');
        assert.equal(sourceDirectoryName('\\\\server\\share'), '\\\\server\\share');
        assert.equal(sourceDirectoryName('\\\\server\\share\\'), '\\\\server\\share');
        assert.equal(sourceDirectoryName('\\\\server\\share\\dir\\'), 'dir');
        assert.equal(sourceDirectoryName('\\\\?\\C:\\x\\y.'), 'y.'); // device paths are not normalized
        assert.equal(sourceDirectoryName('x\t'), 'x\t');
      } else {
        assert.equal(sourceDirectoryName('/'), '/');
      }
    });
  });
});
