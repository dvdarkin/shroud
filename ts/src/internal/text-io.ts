/**
 * File helpers with .NET File.ReadAllText / File.WriteAllText semantics.
 *
 * ReadAllText detects a byte order mark (UTF-8, UTF-16 LE/BE, UTF-32 LE/BE), strips
 * it, and otherwise decodes UTF-8, replacing invalid sequences with U+FFFD. Node's
 * `readFileSync(path, 'utf8')` would keep a UTF-8 BOM as U+FEFF, which then shifts
 * every span offset by one and changes masked output.
 *
 * WriteAllText writes UTF-8 without a BOM; lone surrogates become EF BF BD in both
 * runtimes.
 */
import { readFileSync, statSync, writeFileSync } from 'node:fs';

export function decodeText(bytes: Uint8Array): string {
  const b = bytes;
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) {
    return new TextDecoder('utf-16be', { ignoreBOM: true }).decode(b.subarray(2));
  }
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) {
    if (b.length >= 4 && b[2] === 0x00 && b[3] === 0x00) return decodeUtf32(b.subarray(4), true);
    return new TextDecoder('utf-16le', { ignoreBOM: true }).decode(b.subarray(2));
  }
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) {
    return decodeUtf8(b.subarray(3));
  }
  if (b.length >= 4 && b[0] === 0x00 && b[1] === 0x00 && b[2] === 0xfe && b[3] === 0xff) {
    return decodeUtf32(b.subarray(4), false);
  }
  return decodeUtf8(b);
}

/** UTF-8 decode without BOM stripping (Encoding.UTF8.GetString). */
export function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes);
}

const REPLACEMENT = String.fromCharCode(0xfffd);

function decodeUtf32(bytes: Uint8Array, littleEndian: boolean): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let out = '';
  let i = 0;
  for (; i + 4 <= bytes.length; i += 4) {
    const cp = view.getUint32(i, littleEndian);
    out += cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? REPLACEMENT : String.fromCodePoint(cp);
  }
  if (i < bytes.length) out += REPLACEMENT;
  return out;
}

export function readAllText(path: string): string {
  return decodeText(readFileSync(path));
}

export function writeAllText(path: string, text: string): void {
  writeFileSync(path, text, { encoding: 'utf8' });
}

/** File.Exists: true only for an existing regular file; never throws. */
export function fileExists(path: string): boolean {
  try {
    return path.length > 0 && statSync(path).isFile();
  } catch {
    return false;
  }
}

/** Directory.Exists: true only for an existing directory; never throws. */
export function directoryExists(path: string): boolean {
  try {
    return path.length > 0 && statSync(path).isDirectory();
  } catch {
    return false;
  }
}
