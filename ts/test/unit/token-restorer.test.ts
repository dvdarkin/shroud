// Port of src/Shroud.Tests.Unit/TokenRestorerTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { restoreTokens } from '../../src/vault-builder.js';

describe('TokenRestorerTests', () => {
  test('restore, replaces every occurrence of known tokens', () => {
    const tokens = new Map([
      ['ADDR:11111111', '0xabc'],
      ['AMT:22222222', '$5'],
    ]);

    const { text, unresolved } = restoreTokens('[ADDR:11111111] paid [AMT:22222222] to [ADDR:11111111]', tokens);

    assert.equal(text, '0xabc paid $5 to 0xabc');
    assert.equal(unresolved, 0);
  });

  test('restore, value containing another tokens marker, is restored verbatim', () => {
    // The sequential replace this replaces expanded the inner marker a second time.
    const tokens = new Map([
      ['PASSWD:11111111', 'password=[AMT:22222222]'],
      ['AMT:22222222', '$5'],
    ]);

    assert.equal(
      restoreTokens('[PASSWD:11111111] and [AMT:22222222]', tokens).text,
      'password=[AMT:22222222] and $5',
    );
  });

  test('restore, value with dollar sequences, is inserted literally', () => {
    // JS-only hazard: "$&" and "$1" are replacement patterns in String.prototype.replace.
    const tokens = new Map([['AMT:22222222', "$& $1 $$ $'"]]);

    assert.equal(restoreTokens('a [AMT:22222222] b', tokens).text, "a $& $1 $$ $' b");
  });

  test('restore, unknown tokens, are left in place and counted', () => {
    const tokens = new Map([['ADDR:11111111', '0xabc']]);

    const { text, unresolved } = restoreTokens('[ADDR:11111111] [ADDR:99999999] [KEY:0000aaaa]', tokens);

    assert.equal(text, '0xabc [ADDR:99999999] [KEY:0000aaaa]');
    assert.equal(unresolved, 2);
  });

  test('restore, ordinary brackets, are not counted as tokens', () => {
    const tokens = new Map([['ADDR:11111111', '0xabc']]);

    const { text, unresolved } = restoreTokens(
      '[link](url) [x] [TODO: later] [[ADDR:11111111]] [ADDR:1111111',
      tokens,
    );

    assert.equal(text, '[link](url) [x] [TODO: later] [0xabc] [ADDR:1111111');
    assert.equal(unresolved, 0);
  });

  test('restore, null value, restores as empty', () => {
    const tokens = new Map<string, string | null>([['ADDR:11111111', null]]);

    assert.equal(restoreTokens('a[ADDR:11111111]b', tokens).text, 'ab');
  });
});
