// Port of src/Shroud.Tests.Unit/ExclusionZoneLeakTests.cs
// Exclusion zones must not hide secrets that are not really metadata:
// front matter only at offset 0, metadata keys only as whole words.
// Each xUnit [InlineData] case of a [Theory] is its own test here.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { SensitivityScanner } from '../../src/scanner.js';

const ADDR_A = '0x1111111111111111111111111111111111111111';
const ADDR_B = '0x2222222222222222222222222222222222222222';
const GITHUB_PAT = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const NEWLINES: readonly [string, string][] = [
  ['\\n', '\n'],
  ['\\r\\n', '\r\n'],
];

describe('ExclusionZoneLeakTests', () => {
  const scanner = new SensitivityScanner();

  const detects = (text: string, value: string) => scanner.scan(text).aboveThreshold.some((s) => s.matchedText === value);

  // ---- Fix 1: front matter only at the very start of the text ----

  describe('front matter, at offset zero, is still excluded', () => {
    for (const [label, nl] of NEWLINES) {
      test(label, () => {
        const text = `---${nl}title: Notes${nl}wallet: ${ADDR_A}${nl}---${nl}${nl}Body wallet: ${ADDR_B}${nl}`;

        assert.equal(detects(text, ADDR_A), false, 'a real front matter block at offset 0 is excluded');
        assert.equal(detects(text, ADDR_B), true, 'the body after the front matter is scanned');
      });
    }
  });

  describe('horizontal rules, mid document, do not hide secrets', () => {
    for (const [label, nl] of NEWLINES) {
      test(label, () => {
        const text = `# Title${nl}${nl}Intro text.${nl}${nl}---${nl}${nl}Wallet: ${ADDR_A}${nl}${nl}---${nl}${nl}Footer.${nl}`;

        assert.equal(detects(text, ADDR_A), true, 'two horizontal rules are not front matter');
      });
    }
  });

  test('front matter, preceded by blank line, is not front matter', () => {
    const text = `\n---\nwallet: ${ADDR_A}\n---\n`;

    assert.equal(detects(text, ADDR_A), true, 'front matter must start at offset 0');
  });

  test('rule pair after real front matter, is scanned', () => {
    const text = `---\ntitle: x\n---\n\nText\n\n---\n\nwallet: ${ADDR_B}\n\n---\n`;

    assert.equal(detects(text, ADDR_B), true, 'only the first block at offset 0 is front matter');
  });

  test('front matter, ends at first closing line', () => {
    const text = `---\ntitle: x\n---\nwallet: ${ADDR_B}\n---\n`;

    assert.equal(detects(text, ADDR_B), true, 'front matter ends at the next --- line');
  });

  test('empty front matter, does not swallow following block', () => {
    const text = `---\n---\nwallet: ${ADDR_B}\n\n---\n`;

    assert.equal(detects(text, ADDR_B), true, 'an empty front matter block ends at its own closing line');
  });

  // ---- Fix 2: metadata keys must be whole words ----

  describe('key substring of longer word, does not hide line', () => {
    for (const [line, value] of [
      ['Your profile: ' + ADDR_A, ADDR_A],
      ['profile: ' + ADDR_A, ADDR_A],
      ['classpath: ' + GITHUB_PAT, GITHUB_PAT],
      ['my-file: ' + ADDR_A, ADDR_A],
      ['my_file: ' + ADDR_A, ADDR_A],
      ['Docfile: ' + ADDR_A, ADDR_A],
      ['file2path: ' + ADDR_A, ADDR_A],
    ] as const) {
      test(line, () => {
        assert.equal(detects('## Notes\n\n' + line + '\n', value), true, `'${line}' is not a file-path metadata line`);
      });
    }
  });

  describe('genuine metadata line, is still excluded', () => {
    for (const line of [
      'file: C:\\wallets\\' + ADDR_A, // C# @"file: C:\wallets\" + AddrA
      'FILE: wallet-' + ADDR_A + '.txt',
      'source_file: notes/' + ADDR_A + '.md',
      'path: /home/x/' + ADDR_A,
      'Attachment: ' + ADDR_A,
      '- file: ' + ADDR_A,
    ]) {
      test(line, () => {
        assert.equal(detects('## Notes\n\n' + line + '\n', ADDR_A), false, `'${line}' is a genuine metadata line`);
      });
    }
  });

  describe('metadata key at end of line, does not hide the next line', () => {
    for (const text of ['file:\n' + ADDR_A + '\n', 'path:   \n' + ADDR_A + '\n', 'attachment:\r\n' + ADDR_A + '\r\n']) {
      test(JSON.stringify(text), () => {
        assert.equal(
          detects('## Notes\n\n' + text, ADDR_A),
          true,
          'a metadata key with nothing after it must not exclude the following line',
        );
      });
    }
  });
});
