/**
 * Password-based encryption, byte-compatible with the C# VaultEncryption:
 *
 *   key  = PBKDF2-HMAC-SHA512(UTF-8(password), salt, 600000 iterations, 32 bytes)
 *   blob = salt(16) | nonce(12) | tag(16) | ciphertext(N)      AES-256-GCM, no AAD
 *
 * A wrong password (or any tampering) fails GCM tag verification and yields null; no
 * partial plaintext is ever returned. See docs/format.md for the full specification.
 */
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { decodeUtf8 } from './internal/text-io.js';

export const SALT_LENGTH = 16;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const KEY_LENGTH = 32;
export const PBKDF2_ITERATIONS = 600_000;
export const PBKDF2_DIGEST = 'sha512';
const HEADER_LENGTH = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH;

export function deriveKey(password: string, salt: Uint8Array): Buffer {
  return pbkdf2Sync(Buffer.from(password, 'utf8'), salt, PBKDF2_ITERATIONS, KEY_LENGTH, PBKDF2_DIGEST);
}

/** Encrypts with a fresh random salt and nonce. */
export function encrypt(plaintext: Uint8Array, password: string): Uint8Array {
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKey(password, salt);
  const nonce = randomBytes(NONCE_LENGTH);
  return encryptWith(plaintext, key, salt, nonce);
}

/** Deterministic core of `encrypt`, exposed for format tests and test vectors. */
export function encryptWith(plaintext: Uint8Array, key: Uint8Array, salt: Uint8Array, nonce: Uint8Array): Uint8Array {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LENGTH });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(Buffer.concat([salt, nonce, tag, ciphertext]));
}

/** Decrypts a blob produced by `encrypt` (either build). Returns null on a wrong password. */
export function decrypt(packed: Uint8Array, password: string): Uint8Array | null {
  if (packed.length < HEADER_LENGTH) return null;

  const salt = packed.subarray(0, SALT_LENGTH);
  const nonce = packed.subarray(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH);
  const tag = packed.subarray(SALT_LENGTH + NONCE_LENGTH, HEADER_LENGTH);
  const ciphertext = packed.subarray(HEADER_LENGTH);

  const key = deriveKey(password, salt);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    return null; // Wrong password or tampered data
  }
}

export function encryptString(text: string, password: string): Uint8Array {
  return encrypt(Buffer.from(text, 'utf8'), password);
}

/** UTF-8 decodes the plaintext without stripping a BOM (Encoding.UTF8.GetString). */
export function decryptString(packed: Uint8Array, password: string): string | null {
  const bytes = decrypt(packed, password);
  return bytes === null ? null : decodeUtf8(bytes);
}
