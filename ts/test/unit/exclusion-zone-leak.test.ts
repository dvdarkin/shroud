// Port of src/Shroud.Tests.Unit/ExclusionZoneLeakTests.cs
// Exclusion zones must not hide secrets that are not really metadata:
// front matter only at offset 0, metadata keys only at a line start or after a space, tab or "(".
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
      '(path: ' + ADDR_A + ')',
      '  file: ' + ADDR_A,
      '\tpath: ' + ADDR_A,
      'see (attachment: ' + ADDR_A + ')',
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

  // ---- Fix A: a key is metadata only at a line start or after a space, a tab or "(" ----

  describe('key glued to any other character, does not hide line', () => {
    for (const [label, glue] of [
      ['combining acute accent (Mn)', 'e\u{301}'],
      ['ZERO WIDTH JOINER', '\u{200D}'],
      ['ZERO WIDTH NON-JOINER', '\u{200C}'],
      ['MATHEMATICAL BOLD CAPITAL A (non-BMP letter, a surrogate pair)', '\u{1D400}'],
      ['emoji (surrogate pair)', '\u{1F600}'],
      ['|', '|'],
      ['>', '>'],
      ['"', '"'],
      ['[', '['],
      ['*', '*'],
      ['`', '`'],
      ['<', '<'],
      ['.', '.'],
      ['NO-BREAK SPACE is not one of the allowed separators', '\u{A0}'],
    ] as const) {
      test(label, () => {
        for (const key of ['file:', 'FILE:', 'path:', 'source_file:', 'attachment:']) {
          const line = glue + key + ' ' + ADDR_A;
          assert.equal(
            detects('## Notes\n\n' + line + '\n', ADDR_A),
            true,
            `'${line}' is ordinary text: the key is not at a line start or after a space, tab or '('`,
          );
        }
      });
    }
  });

  describe('key after lone carriage return, is scanned', () => {
    // Multiline ^ matches only at the start of the text and after "\n", so with lone-CR line
    // endings a key after "\r" is not at a line start: the line is scanned.
    for (const text of ['x\rfile: ' + ADDR_A + '\r', '## Notes\rpath: ' + ADDR_A + '\r']) {
      test(JSON.stringify(text), () => {
        assert.equal(detects(text, ADDR_A), true, 'a key preceded by a lone CR is not a metadata key');
      });
    }
  });

  test('key at start of text, is still excluded', () => {
    assert.equal(detects('file: ' + ADDR_A + '\n', ADDR_A), false, 'offset 0 is a line start');
  });

  describe('metadata zone, ends at a lone carriage return', () => {
    for (const text of [
      'file: notes.md\rwallet ' + ADDR_A + '\r',
      'file: notes.md\rwallet ' + ADDR_A + '\r\n',
      '- path: notes.md\rsecond line\rthird ' + ADDR_A + '\n',
    ]) {
      test(JSON.stringify(text), () => {
        assert.equal(detects(text, ADDR_A), true,
          'a metadata line ends at the first CR or LF; later lone-CR lines are scanned');
      });
    }
  });

  describe('metadata value, before a carriage return, is still excluded', () => {
    for (const text of ['file: ' + ADDR_A + '\r\nnext line\r\n', 'file: ' + ADDR_A + '\rnext line\r']) {
      test(JSON.stringify(text), () => {
        assert.equal(detects(text, ADDR_A), false, "the value on the key's own line stays excluded");
      });
    }
  });
});
