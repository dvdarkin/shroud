// Port of src/Shroud.Tests.Unit/VaultEncryptionTests.cs
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { decrypt, decryptString, encrypt, encryptString } from '../../src/vault-encryption.js';

const PASSWORD = 'test-password-123';
const ALT_PASSWORD = 'different-password-456';

const utf8 = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));

describe('VaultEncryptionTests', () => {
  test('round trip bytes, returns original', () => {
    const plaintext = utf8('Hello, Shroud!');
    const encrypted = encrypt(plaintext, PASSWORD);
    const decrypted = decrypt(encrypted, PASSWORD);

    assert.notEqual(decrypted, null);
    assert.deepEqual([...decrypted!], [...plaintext]);
  });

  test('round trip string, returns original', () => {
    const text = 'Sensitive data: 0x1234567890abcdef';
    const encrypted = encryptString(text, PASSWORD);
    const decrypted = decryptString(encrypted, PASSWORD);

    assert.equal(decrypted, text);
  });

  test('wrong password, returns null', () => {
    const plaintext = utf8('secret');
    const encrypted = encrypt(plaintext, PASSWORD);
    const decrypted = decrypt(encrypted, ALT_PASSWORD);

    assert.equal(decrypted, null);
  });

  test('wrong password string, returns null', () => {
    const encrypted = encryptString('secret', PASSWORD);
    const decrypted = decryptString(encrypted, ALT_PASSWORD);

    assert.equal(decrypted, null);
  });

  test('truncated data, returns null', () => {
    const plaintext = utf8('secret');
    const encrypted = encrypt(plaintext, PASSWORD);

    // Truncate to less than salt(16) + nonce(12) + tag(16) = 44 bytes
    const truncated = encrypted.slice(0, 30);
    const decrypted = decrypt(truncated, PASSWORD);

    assert.equal(decrypted, null);
  });

  test('corrupted ciphertext, returns null', () => {
    const plaintext = utf8('secret');
    const encrypted = encrypt(plaintext, PASSWORD);

    // Corrupt a byte in the ciphertext region (after salt+nonce+tag = 44 bytes)
    if (encrypted.length > 45) encrypted[45]! ^= 0xff;

    const decrypted = decrypt(encrypted, PASSWORD);
    assert.equal(decrypted, null);
  });

  test('empty plaintext, round trips', () => {
    const plaintext = new Uint8Array(0);
    const encrypted = encrypt(plaintext, PASSWORD);
    const decrypted = decrypt(encrypted, PASSWORD);

    assert.notEqual(decrypted, null);
    assert.equal(decrypted!.length, 0);
  });

  test('different passwords, produce different ciphertext', () => {
    const plaintext = utf8('same data');
    const encrypted1 = encrypt(plaintext, PASSWORD);
    const encrypted2 = encrypt(plaintext, ALT_PASSWORD);

    assert.notDeepEqual([...encrypted1], [...encrypted2]);
  });

  test('same password same plaintext, produces different ciphertext', () => {
    const plaintext = utf8('same data');
    const encrypted1 = encrypt(plaintext, PASSWORD);
    const encrypted2 = encrypt(plaintext, PASSWORD);

    assert.notDeepEqual([...encrypted1], [...encrypted2], 'random salt and nonce should produce different ciphertext');
  });

  test('encrypted output, has expected minimum size', () => {
    const plaintext = utf8('test');
    const encrypted = encrypt(plaintext, PASSWORD);

    assert.equal(encrypted.length, 16 + 12 + 16 + plaintext.length);
  });
});
