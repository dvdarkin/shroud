/**
 * Orchestrates the scan-mask-vault pipeline. Scans every .md file under a directory,
 * masks detected spans and produces:
 *
 *  - public/        masked copies, safe to share (Tier 0);
 *  - manifest.json  token metadata without secret values (Tier 0);
 *  - vault.shroud   encrypted JSON mapping token ids to original values (Tier 2).
 *
 * The output is format-compatible with the C# build in both directions; FORMAT.md
 * specifies every byte.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import type { ShroudConfig } from './config.js';
import { defaultConfig } from './config.js';
import { serializeIndented } from './internal/dotnet-json.js';
import {
  enumerateFiles,
  getDirectoryName,
  getFileName,
  getFullPath,
  getRelativePath,
  isRootPath,
  pathCombine,
} from './internal/dotnet-path.js';
import { readAllText, writeAllText } from './internal/text-io.js';
import { SpanMasker, type TokenMapping } from './masker.js';
import type { ScanResult } from './models.js';
import { SensitivityScanner } from './scanner.js';
import { encryptString } from './vault-encryption.js';

export interface MaskedFile {
  readonly relativePath: string;
  readonly maskedContent: string;
  readonly tokensApplied: number;
}

export interface TokenEntry {
  value: string;
  /** Entity type name, for example "CryptoAddr". */
  service: string;
  /** Pattern identifier, for example "evm_address". */
  serviceId: string;
  /** Lower-cased domain name, for example "onchain". */
  domain: string;
  /** Every file the token was applied in, one entry per occurrence. */
  files: string[];
  occurrences: number;
}

export interface VaultResult {
  readonly sourceDir: string;
  readonly maskedFiles: MaskedFile[];
  /** Token id -> entry, in first-seen order. */
  readonly tokens: Map<string, TokenEntry>;
}

/**
 * The decrypted vault.shroud payload. Fields are nullable only because a hand-edited
 * vault can set them to null; vaults written by either build never do.
 */
export interface VaultData {
  version: number;
  created: string | null;
  tokens: Map<string, string | null> | null;
  fileHashes: Map<string, string | null> | null;
}

export interface ManifestToken {
  service: string;
  domain: string;
  files: string[];
  occurrences: number;
}

export interface ManifestFile {
  created: string;
  source: string;
  fileCount: number;
  tokenCount: number;
  tokens: Map<string, ManifestToken>;
  summary: Map<string, number>;
}

/** Culture-sensitive string order, like LINQ OrderBy over strings in .NET (current culture). */
const cultureCompare = new Intl.Collator().compare;

export class VaultBuilder {
  private readonly scanner: SensitivityScanner;
  private readonly maskingKey: Uint8Array;

  /**
   * `maskingKey` is a test seam (an `internal` constructor in C#): a fixed key makes
   * token ids, and so collisions, reproducible. Omit it to use a random 32-byte key.
   */
  constructor(configOrScanner?: ShroudConfig | SensitivityScanner | null, maskingKey?: Uint8Array) {
    this.scanner =
      configOrScanner instanceof SensitivityScanner
        ? configOrScanner
        : new SensitivityScanner(configOrScanner ?? defaultConfig());
    this.maskingKey = maskingKey ?? randomBytes(32);
  }

  build(sourceDir: string): VaultResult {
    const mdFiles = enumerateFiles(sourceDir, '*.md', true).sort(cultureCompare);

    const masker = new SpanMasker(this.maskingKey);
    const tokens = new Map<string, TokenEntry>();
    const maskedFiles: MaskedFile[] = [];

    for (const filePath of mdFiles) {
      const relativePath = getRelativePath(sourceDir, filePath);
      const text = readAllText(filePath);
      const scanResult = this.scanner.scan(text);

      if (scanResult.aboveThreshold.length === 0) {
        // Clean file - copy as-is
        maskedFiles.push({ relativePath, maskedContent: text, tokensApplied: 0 });
        continue;
      }

      const maskResult = masker.mask(text, scanResult);

      for (const token of maskResult.tokens) {
        const existing = tokens.get(token.tokenId);
        if (existing) {
          // Same id, different value: the second value would be lost and reveal would
          // restore the wrong text. Fail before anything is written.
          if (existing.value !== token.originalValue) throw new TokenCollisionException(token.tokenId);

          existing.files.push(relativePath);
          existing.occurrences++;
        } else {
          tokens.set(token.tokenId, {
            value: token.originalValue,
            service: token.entityType,
            serviceId: serviceIdFor(scanResult, token),
            domain: token.domain.toLowerCase(),
            files: [relativePath],
            occurrences: 1,
          });
        }
      }

      maskedFiles.push({ relativePath, maskedContent: maskResult.maskedText, tokensApplied: maskResult.tokens.length });
    }

    return { sourceDir, maskedFiles, tokens };
  }

  writeOutput(result: VaultResult, outputDir: string, password: string): void {
    const publicDir = pathCombine(outputDir, 'public');
    mkdirSync(publicDir, { recursive: true });

    // Masked files, preserving directory structure
    for (const file of result.maskedFiles) {
      const outPath = pathCombine(publicDir, file.relativePath);
      const dir = getDirectoryName(outPath);
      if (dir) mkdirSync(dir, { recursive: true });
      writeAllText(outPath, file.maskedContent);
    }

    const manifest = buildManifest(result, dotnetUtcNowRoundTrip());
    writeAllText(pathCombine(outputDir, 'manifest.json'), serializeManifest(manifest));

    const vaultData: VaultData = {
      version: 1,
      created: manifest.created,
      tokens: new Map([...result.tokens].map(([id, entry]) => [id, entry.value])),
      fileHashes: mapFromUnique(result.maskedFiles.map((f) => [f.relativePath, computeHash(f.maskedContent)])),
    };

    const encrypted = encryptString(serializeVaultData(vaultData), password);
    writeFileSync(pathCombine(outputDir, 'vault.shroud'), encrypted);
  }
}

/**
 * Thrown by VaultBuilder.build when two different original values produce the same
 * token id (4-byte HMAC prefix). Continuing would map both values to one token and
 * reveal would restore the wrong text. The message names the token id only, never an
 * original value.
 */
export class TokenCollisionException extends Error {
  readonly tokenId: string;

  constructor(tokenId: string) {
    super(
      `Token id collision: two different values both map to [${tokenId}]. ` +
        'Nothing was written. Run the vault again (a new masking key is generated each run).',
    );
    this.name = 'TokenCollisionException';
    this.tokenId = tokenId;
  }
}

/**
 * The pattern id recorded for a new token: the service of the first above-threshold
 * span in the same file whose matched text and entity type equal the token's.
 */
function serviceIdFor(scanResult: ScanResult, token: TokenMapping): string {
  return (
    scanResult.aboveThreshold.find((s) => s.matchedText === token.originalValue && s.entityType === token.entityType)
      ?.service ?? ''
  );
}

/**
 * manifest.json is public, so it records only the final directory name of the source
 * ("." and relative paths are resolved first), never the absolute path. A filesystem
 * root has no name and is kept as is. (Path.GetFullPath, TrimEndingDirectorySeparator
 * and GetFileName in C#.)
 */
export function sourceDirectoryName(sourceDir: string): string {
  const full = getFullPath(sourceDir);
  const name = isRootPath(full) ? '' : getFileName(full);
  return name === '' ? full : name;
}

function computeHash(content: string): string {
  return `sha256:${createHash('sha256').update(Buffer.from(content, 'utf8')).digest('hex')}`;
}

/** Enumerable.ToDictionary: throws on a duplicate key. */
function mapFromUnique<V>(entries: [string, V][]): Map<string, V> {
  const map = new Map<string, V>();
  for (const [k, v] of entries) {
    if (map.has(k)) throw new Error(`An item with the same key has already been added. Key: ${k}`);
    map.set(k, v);
  }
  return map;
}

export function buildManifest(result: VaultResult, created: string): ManifestFile {
  const summary = new Map<string, number>();
  for (const entry of result.tokens.values()) {
    summary.set(entry.domain, (summary.get(entry.domain) ?? 0) + entry.occurrences);
  }
  return {
    created,
    source: sourceDirectoryName(result.sourceDir),
    fileCount: result.maskedFiles.length,
    tokenCount: result.tokens.size,
    tokens: new Map(
      [...result.tokens].map(([id, entry]) => [
        id,
        { service: entry.serviceId, domain: entry.domain, files: [...new Set(entry.files)], occurrences: entry.occurrences },
      ]),
    ),
    summary,
  };
}

/** manifest.json text; `newline` defaults to os.EOL like .NET Environment.NewLine. */
export function serializeManifest(manifest: ManifestFile, newline?: string): string {
  return serializeIndented({
    created: manifest.created,
    source: manifest.source,
    fileCount: manifest.fileCount,
    tokenCount: manifest.tokenCount,
    tokens: new Map(
      [...manifest.tokens].map(([id, t]) => [
        id,
        { service: t.service, domain: t.domain, files: t.files, occurrences: t.occurrences },
      ]),
    ),
    summary: manifest.summary,
  }, newline);
}

/** Reads manifest.json text (either build) into a ManifestFile, preserving token order. */
export function parseManifest(json: string): ManifestFile {
  const root = JSON.parse(json) as {
    created: string;
    source: string;
    fileCount: number;
    tokenCount: number;
    tokens: Record<string, ManifestToken>;
    summary: Record<string, number>;
  };
  return {
    created: root.created,
    source: root.source,
    fileCount: root.fileCount,
    tokenCount: root.tokenCount,
    tokens: new Map(Object.entries(root.tokens ?? {})),
    summary: new Map(Object.entries(root.summary ?? {})),
  };
}

/** Plaintext vault JSON; `newline` defaults to os.EOL like .NET Environment.NewLine. */
export function serializeVaultData(data: VaultData, newline?: string): string {
  return serializeIndented({
    version: data.version,
    created: data.created,
    tokens: data.tokens,
    fileHashes: data.fileHashes,
  }, newline);
}

export class VaultFormatError extends Error {
  constructor(detail: string) {
    super(`The JSON value could not be converted to VaultData: ${detail}`);
    this.name = 'VaultFormatError';
  }
}

/**
 * Parses decrypted vault JSON with the C# reader's rules (System.Text.Json, camelCase,
 * case-sensitive names, unknown properties ignored). Returns null for a JSON `null`
 * document, which the CLI reports as a corrupt vault.
 */
export function parseVaultData(json: string): VaultData | null {
  const root: unknown = JSON.parse(json);
  if (root === null) return null;
  if (typeof root !== 'object' || Array.isArray(root)) throw new VaultFormatError('expected an object');
  const data: VaultData = { version: 0, created: '', tokens: new Map(), fileHashes: new Map() };
  for (const [key, value] of Object.entries(root as Record<string, unknown>)) {
    switch (key) {
      case 'version':
        if (typeof value !== 'number' || !Number.isInteger(value)) throw new VaultFormatError('version');
        data.version = value;
        break;
      case 'created':
        if (typeof value !== 'string' && value !== null) throw new VaultFormatError('created');
        data.created = value;
        break;
      case 'tokens':
        data.tokens = readStringMap(value, 'tokens');
        break;
      case 'fileHashes':
        data.fileHashes = readStringMap(value, 'fileHashes');
        break;
    }
  }
  return data;
}

function readStringMap(value: unknown, name: string): Map<string, string | null> | null {
  if (value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) throw new VaultFormatError(name);
  const map = new Map<string, string | null>();
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v !== 'string' && v !== null) throw new VaultFormatError(`${name}.${k}`);
    map.set(k, v);
  }
  return map;
}

/**
 * DateTime.UtcNow.ToString("o"): yyyy-MM-ddTHH:mm:ss.fffffffZ. JS clocks have
 * millisecond resolution, so the last four of the seven fraction digits are zero.
 */
export function dotnetUtcNowRoundTrip(now: Date = new Date()): string {
  return now.toISOString().replace(/\.(\d{3})Z$/, (_match, ms: string) => `.${ms}0000Z`);
}
