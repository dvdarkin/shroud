/**
 * The `shroud` command line. Commands, flags, exit codes and output text match the
 * C# Shroud.Cli (public build, without Shroud.Private patterns) line for line,
 * including its line endings (os.EOL, CRLF on Windows) and number formatting.
 */
import { randomFillSync } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, readSync, writeFileSync } from 'node:fs';
import { EOL } from 'node:os';
import { sep } from 'node:path';
import {
  ConfigFormatError,
  PRESET_NAMES,
  type ShroudConfig,
  configForPreset,
  defaultConfig,
  loadConfig,
  saveConfig,
} from './config.js';
import {
  ASSET_NAME_BOOST,
  CONTEXT_WINDOW_CHARS,
  CURRENCY_SIGNAL_BOOST,
  type ScoringDetail,
} from './context-scorer.js';
import { align, formatBool, formatDouble, formatFixed } from './internal/dotnet-format.js';
import {
  enumerateFiles,
  getDirectoryName,
  getFileName,
  getFullPath,
  getRelativePath,
  isPathRooted,
  pathCombine,
} from './internal/dotnet-path.js';
import { decodeText, directoryExists, fileExists, readAllText, writeAllText } from './internal/text-io.js';
import { SpanMasker } from './masker.js';
import type { ScanResult } from './models.js';
import { getPatternsForConfig } from './pattern-library.js';
import { type ScanDiagnostics, SensitivityScanner } from './scanner.js';
import { decryptString } from './vault-encryption.js';
import {
  TokenCollisionException,
  VaultBuilder,
  VaultFormatError,
  type TokenEntry,
  type VaultResult,
  computeHash,
  parseVaultData,
  restoreTokens,
} from './vault-builder.js';

const CONFIG_FILE_NAME = 'shroud.json';

/** Where the CLI writes. Console.Out / Console.Error in C#; tests swap it to capture output. */
export interface CliIo {
  stdout(text: string): void;
  stderr(text: string): void;
}

const processIo: CliIo = {
  stdout: (text) => void process.stdout.write(text),
  stderr: (text) => void process.stderr.write(text),
};

let io: CliIo = processIo;

/** Redirects CLI output (Console.SetOut/SetError); null restores the process streams. */
export function setCliIo(next: CliIo | null): void {
  io = next ?? processIo;
}

/**
 * Test seam (Program.VaultMaskingKeyOverride in C#): when set, `vault` uses this masking
 * key instead of a random one.
 */
let vaultMaskingKeyOverride: Uint8Array | null = null;

export function setVaultMaskingKeyOverride(key: Uint8Array | null): void {
  vaultMaskingKeyOverride = key;
}

/**
 * Test seam (Program.OpenStdin in C#): where `scan -` and `reveal --text -` read all of
 * stdin from; null restores the process stream.
 */
const processStdin = (): Uint8Array => readFileSync(0);
let readStdinBytes: () => Uint8Array = processStdin;

export function setCliStdin(next: (() => Uint8Array) | null): void {
  readStdinBytes = next ?? processStdin;
}

const STDIN_ARG = '-';
const PASSWORD_VARIABLE = 'SHROUD_PASSWORD';

/** All of stdin as text, decoded like readAllText (UTF-8, a BOM is honoured and dropped). */
function readStdinText(): string {
  return decodeText(readStdinBytes());
}

/** The password from -p, else from the SHROUD_PASSWORD environment variable, else undefined. */
function givenPassword(passwordArg: string | undefined): string | undefined {
  if (passwordArg !== undefined) return passwordArg;
  const fromEnvironment = process.env[PASSWORD_VARIABLE];
  return fromEnvironment ? fromEnvironment : undefined;
}

const out = (line = '') => io.stdout(line + EOL);
const err = (line = '') => io.stderr(line + EOL);

/** An error that the C# CLI would surface as an unhandled .NET exception of this type. */
class DotnetException extends Error {
  constructor(
    readonly dotnetType: string,
    message: string,
  ) {
    super(message);
    this.name = dotnetType;
  }
}

export async function main(args: string[]): Promise<number> {
  if (args.length === 0) return printUsage();

  // A command name always means the command, even when a directory of that name exists
  // (write "./scan" to vault a directory called "scan").
  switch (args[0]) {
    case 'vault':
      return runVault(args.slice(1));
    case 'reveal':
      return runReveal(args.slice(1));
    case 'scan':
      return runScan(args.slice(1));
    case 'mask':
      return runMask(args.slice(1));
    case 'init':
      return runInit(args.slice(1));
    case 'help':
    case '--help':
    case '-h':
      return printUsage();
    default:
      // Any other first argument that is a directory: vault it (the default command).
      return directoryExists(args[0]!) ? runVault(args) : error(`Unknown command: ${args[0]}`);
  }
}

interface ParsedArgs {
  flags: Set<string>;
  values: Map<string, string>;
  positionals: string[];
}

/**
 * Splits arguments into flags, options that take a value, and positionals. Returns an
 * error message for an option that is not known or has no value. A lone "-" and anything
 * not starting with "-" is a positional.
 */
function parseArgs(args: string[], flagNames: string[], valueNames: string[]): ParsedArgs | string {
  const parsed: ParsedArgs = { flags: new Set(), values: new Map(), positionals: [] };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg.length < 2 || arg[0] !== '-') parsed.positionals.push(arg);
    else if (flagNames.includes(arg)) parsed.flags.add(arg);
    else if (valueNames.includes(arg)) {
      if (i + 1 >= args.length || args[i + 1]!.length === 0) return `Option ${arg} needs a value.`;
      parsed.values.set(arg, args[++i]!);
    } else return `Unknown option: ${arg}`;
  }
  return parsed;
}

function optionValue(values: Map<string, string>, shortName: string, longName: string): string | undefined {
  return values.get(longName) ?? values.get(shortName);
}

/**
 * The directory path without trailing separators. ".", ".." and roots have no name of
 * their own to append a suffix to, so they are resolved to a full path first.
 */
function namedDirectory(dir: string): string {
  const trimmed = dir.replace(/[/\\]+$/, '');
  const name = getFileName(trimmed);
  return name === '' || name === '.' || name === '..' ? getFullPath(dir) : trimmed;
}

/** True when `path` is `dir` or lies under it. */
function isSameOrInside(dir: string, path: string): boolean {
  const relative = getRelativePath(getFullPath(dir), getFullPath(path));
  return relative === '.' || (!isPathRooted(relative) && relative !== '..' && !relative.startsWith('..' + sep));
}

const VAULT_FILE_NAME = 'vault.shroud';
const MANIFEST_FILE_NAME = 'manifest.json';
const PUBLIC_DIR_NAME = 'public';

/**
 * True when `dir` can take vault output: it does not exist, holds nothing but hidden
 * entries (names starting with '.'), or holds an earlier vault (vault.shroud, with at most
 * manifest.json and public/ beside it). vault replaces public/, so any other directory
 * could lose files it never wrote.
 */
function canHoldVaultOutput(dir: string): boolean {
  if (fileExists(dir)) return false;
  if (!directoryExists(dir)) return true;
  const names = readdirSync(dir).filter((name) => !name.startsWith('.'));
  return (
    names.length === 0 ||
    (names.includes(VAULT_FILE_NAME) &&
      names.every((name) => name === VAULT_FILE_NAME || name === MANIFEST_FILE_NAME || name === PUBLIC_DIR_NAME))
  );
}

function runScan(args: string[]): number {
  const parsed = parseArgs(args, ['--verbose', '-v', '--debug', '--exit-code', '--no-values'], ['-c', '--config']);
  if (typeof parsed === 'string') return error(parsed);
  const { flags, positionals: files } = parsed;

  if (files.length === 0) {
    return error(
      'Usage: shroud scan <file|-> [file2 ...] [--verbose] [--debug] [--exit-code] [--no-values] [--config file]',
    );
  }
  if (files.filter((f) => f === STDIN_ARG).length > 1) return error('- (stdin) can be given only once.');

  const noValues = flags.has('--no-values');
  const debug = flags.has('--debug');
  const verbose = debug || flags.has('--verbose') || flags.has('-v');
  let missing = 0;
  let detected = false;

  const configPath = optionValue(parsed.values, '-c', '--config');
  const config = loadConfigOrDefault(configPath);
  if (config === null) return error(`Config file not found: ${configPath}`);
  const scanner = createScanner(config);

  for (const path of expandGlobs(files)) {
    const fromStdin = path === STDIN_ARG;
    if (!fromStdin && !fileExists(path)) {
      err(`  File not found: ${path}`);
      missing++;
      continue;
    }

    const text = fromStdin ? readStdinText() : readAllText(path);
    const label = fromStdin ? '<stdin>' : path;

    let result: ScanResult;
    if (verbose) {
      const scanned = scanner.scanWithDiagnostics(text);
      result = scanned.result;
      printScanResultVerbose(label, result, scanned.diagnostics, debug, noValues);
    } else {
      result = scanner.scan(text);
      printScanResult(label, result, noValues);
    }
    if (result.aboveThreshold.length > 0) detected = true;
  }

  // 1: a file was not found. 2 (only with --exit-code): something would be tokenized.
  if (missing > 0) return 1;
  return detected && flags.has('--exit-code') ? 2 : 0;
}

function runMask(args: string[]): number {
  const parsed = parseArgs(args, [], ['-o', '--output', '-c', '--config']);
  if (typeof parsed === 'string') return error(parsed);
  const files = parsed.positionals;
  const outputPath = optionValue(parsed.values, '-o', '--output');

  if (files.length === 0) return error('Usage: shroud mask <file.md> [-o output.md]');

  const inputs = [...expandGlobs(files)];
  if (outputPath !== undefined && inputs.length > 1) {
    return error(
      `-o ${outputPath} names one output file but ${inputs.length} input files were given; ` +
        'mask them one at a time, or omit -o to mask each file in place.',
    );
  }

  const configPath = optionValue(parsed.values, '-c', '--config');
  const config = loadConfigOrDefault(configPath);
  if (config === null) return error(`Config file not found: ${configPath}`);
  const scanner = createScanner(config);
  const key = loadOrCreateKey(config);
  const masker = new SpanMasker(key);
  let missing = 0;
  let maskedInPlace = false;

  for (const path of inputs) {
    if (!fileExists(path)) {
      err(`  File not found: ${path}`);
      missing++;
      continue;
    }

    const text = readAllText(path);
    const scanResult = scanner.scan(text);

    if (scanResult.aboveThreshold.length === 0) {
      out(`  ${path}: clean (no sensitive spans detected)`);
      continue;
    }

    const maskResult = masker.mask(text, scanResult);
    const target = outputPath ?? path;
    writeAllText(target, maskResult.maskedText);
    if (outputPath === undefined) maskedInPlace = true;

    out(`  ${path} -> ${target}`);
    out(`    Masked ${maskResult.tokens.length} spans:`);
    for (const token of maskResult.tokens) {
      out(`      [${token.tokenId}] ${token.domain}/${token.entityType}`);
    }
  }

  if (maskedInPlace) {
    err('  Note: files were masked in place. mask is one-way: the original values are not stored anywhere.');
    err("  Use 'shroud vault' when you need to reveal them later.");
  }

  return missing > 0 ? 1 : 0;
}

async function runVault(args: string[]): Promise<number> {
  const parsed = parseArgs(args, [], ['-o', '--output', '-p', '--password', '-c', '--config']);
  if (typeof parsed === 'string') return error(parsed);
  if (parsed.positionals.length !== 1) {
    return error('Usage: shroud vault <directory> [-o output] [-p password] [--config file]');
  }

  const sourceDir = parsed.positionals[0]!;
  if (!directoryExists(sourceDir)) return error(`Directory not found: ${sourceDir}`);

  const passwordArg = givenPassword(optionValue(parsed.values, '-p', '--password'));
  const outputDir = optionValue(parsed.values, '-o', '--output') ?? namedDirectory(sourceDir) + '.shroud';

  // An output inside the source would be scanned by the next run (masked copies of masked copies).
  if (isSameOrInside(sourceDir, outputDir)) {
    return error(`Output directory ${outputDir} is inside the source directory. Choose a location outside it with -o.`);
  }

  // A source inside the output would be overwritten by public/ or removed as a stale copy.
  if (isSameOrInside(outputDir, sourceDir)) {
    return error(
      `Source directory ${sourceDir} is inside the output directory ${outputDir}. Choose an output outside it with -o.`,
    );
  }

  // vault replaces public/ in its output, so the output must be new, empty or an earlier vault.
  if (!canHoldVaultOutput(outputDir)) {
    return error(`Output directory ${outputDir} is not empty and is not a Shroud vault. Choose a new or empty directory with -o.`);
  }

  const configPath = optionValue(parsed.values, '-c', '--config');
  const config = loadConfigOrDefault(configPath);
  if (config === null) return error(`Config file not found: ${configPath}`);
  const builder = new VaultBuilder(createScanner(config), vaultMaskingKeyOverride ?? undefined);

  out(`\n  Scanning ${sourceDir}...\n`);
  let result: VaultResult;
  try {
    result = builder.build(sourceDir);
  } catch (e) {
    if (e instanceof TokenCollisionException) return error(e.message);
    throw e;
  }

  if (result.tokens.size === 0) {
    out('  No sensitive data detected. Nothing to vault.');
    return 0;
  }

  // Print summary by domain (stable sort: ties keep first-seen order, like LINQ)
  const groups = new Map<string, TokenEntry[]>();
  for (const entry of result.tokens.values()) {
    const group = groups.get(entry.domain) ?? [];
    group.push(entry);
    groups.set(entry.domain, group);
  }
  const occurrences = (g: TokenEntry[]) => g.reduce((n, t) => n + t.occurrences, 0);
  const byDomain = [...groups].sort((a, b) => occurrences(b[1]) - occurrences(a[1]));
  for (const [domain, group] of byDomain) {
    const files = new Set(group.flatMap((t) => t.files)).size;
    out(`    ${align(domain, -14)} ${align(String(occurrences(group)), 3)} spans across ${files} files`);
  }
  out();

  // Get password
  const password = passwordArg ?? (await readPassword('  Vault password: '));
  if (!password) return error('Password required.');

  // A piped password is one line on stdin; there is nothing to confirm it against.
  if (passwordArg === undefined && process.stdin.isTTY) {
    const confirm = await readPassword('  Confirm: ');
    if (password !== confirm) return error("Passwords don't match.");
  }

  out();
  builder.writeOutput(result, outputDir, password);

  const maskedCount = result.maskedFiles.filter((f) => f.tokensApplied > 0).length;
  const cleanCount = result.maskedFiles.length - maskedCount;

  out(`  ${outputDir}/`);
  out(`    public/          ${result.maskedFiles.length} files (${maskedCount} masked, ${cleanCount} clean)`);
  out(`    vault.shroud     ${result.tokens.size} tokens (encrypted)`);
  out('    manifest.json    metadata for agents');
  out(`\n  Source untouched. To reveal: shroud reveal "${outputDir}"`);

  return 0;
}

async function runReveal(args: string[]): Promise<number> {
  const parsed = parseArgs(args, [], ['-o', '--output', '-p', '--password', '--text']);
  if (typeof parsed === 'string') return error(parsed);
  if (parsed.positionals.length !== 1) {
    return error('Usage: shroud reveal <vault-dir> [-o output] [-p password] [--text file|-]');
  }

  const vaultDir = parsed.positionals[0]!;
  const vaultFile = pathCombine(vaultDir, 'vault.shroud');
  const publicDir = pathCombine(vaultDir, 'public');

  if (!fileExists(vaultFile)) return error(`No vault.shroud found in ${vaultDir}`);

  const passwordArg = givenPassword(optionValue(parsed.values, '-p', '--password'));
  let outputDir = optionValue(parsed.values, '-o', '--output');

  const textPath = parsed.values.get('--text');
  if (textPath !== undefined) return revealText(vaultDir, vaultFile, textPath, outputDir, passwordArg);

  // Default: "<name>.shroud" reveals to "<name>.revealed", any other name to
  // "<name>.revealed" next to it. Never into the vault directory, whose public/ is shared.
  if (outputDir === undefined) {
    const named = namedDirectory(vaultDir);
    const suffix = '.shroud';
    const stem =
      named.endsWith(suffix) && getFileName(named).length > suffix.length ? named.slice(0, -suffix.length) : named;
    outputDir = stem + '.revealed';
  }
  if (isSameOrInside(vaultDir, outputDir)) {
    return error(
      `Output directory ${outputDir} is inside the vault directory, which holds the shareable copies. Choose a location outside it with -o.`,
    );
  }

  const password = passwordArg ?? (await readPassword('  Vault password: '));
  if (!password) return error('Password required.');

  out('  Decrypting...');
  const encrypted = readFileSync(vaultFile);
  const json = decryptString(encrypted, password);
  if (json === null) return error('Wrong password.');

  const vaultData = parseVaultData(json);
  if (vaultData === null || vaultData.tokens === null) return error('Corrupt vault file.');

  mkdirSync(outputDir, { recursive: true });
  const hashes = vaultData.fileHashes ?? new Map<string, string | null>();

  let filesRevealed = 0;
  if (directoryExists(publicDir)) {
    for (const file of enumerateFiles(publicDir, '*.md', true)) {
      const relative = getRelativePath(publicDir, file);
      const content = readAllText(file);

      // The vault records a hash of every masked copy it was built with (keys use the
      // writer's path separator). A vault without hashes is not checked.
      if (hashes.size > 0) {
        const key = [relative, relative.replaceAll('\\', '/'), relative.replaceAll('/', '\\')].find((k) =>
          hashes.has(k),
        );
        if (key === undefined) err(`  Warning: ${relative} is not part of this vault.`);
        else if (hashes.get(key) !== computeHash(content)) err(`  Warning: ${relative} was changed after it was vaulted.`);
      }

      const restored = restoreTokens(content, vaultData.tokens);
      if (restored.unresolved > 0) {
        err(`  Warning: ${relative}: ${restored.unresolved} token(s) are not in this vault and were left in place.`);
      }

      const outPath = pathCombine(outputDir, relative);
      const dir = getDirectoryName(outPath);
      if (dir) mkdirSync(dir, { recursive: true });
      writeAllText(outPath, restored.text);
      filesRevealed++;
    }
  }

  out(`\n  ${filesRevealed} files revealed to ${outputDir}/`);
  return 0;
}

/**
 * reveal --text: restores the tokens of this vault in one text (a file, or "-" for stdin),
 * for example a model's answer about the masked copies. The result goes to -o or to
 * stdout, as UTF-8; nothing else is written to stdout, so it can be piped.
 */
async function revealText(
  vaultDir: string,
  vaultFile: string,
  textPath: string,
  outputPath: string | undefined,
  passwordArg: string | undefined,
): Promise<number> {
  const fromStdin = textPath === STDIN_ARG;
  if (!fromStdin && !fileExists(textPath)) return error(`File not found: ${textPath}`);
  if (fromStdin && passwordArg === undefined) {
    return error(`--text - reads the text from stdin, so the password must come from -p or ${PASSWORD_VARIABLE}.`);
  }
  if (outputPath !== undefined && isSameOrInside(vaultDir, outputPath)) {
    return error(
      `Output file ${outputPath} is inside the vault directory, which holds the shareable copies. Choose a location outside it with -o.`,
    );
  }

  const password = passwordArg ?? (await readPassword('  Vault password: '));
  if (!password) return error('Password required.');

  const json = decryptString(readFileSync(vaultFile), password);
  if (json === null) return error('Wrong password.');

  const vaultData = parseVaultData(json);
  if (vaultData === null || vaultData.tokens === null) return error('Corrupt vault file.');

  const text = fromStdin ? readStdinText() : readAllText(textPath);
  const restored = restoreTokens(text, vaultData.tokens);
  if (restored.unresolved > 0) {
    err(`  Warning: ${restored.unresolved} token(s) are not in this vault and were left in place.`);
  }

  if (outputPath !== undefined) writeAllText(outputPath, restored.text);
  else io.stdout(restored.text);
  return 0;
}

/** Console.In.ReadLine on redirected input: the first line of stdin, without its line ending. */
function readStdinLine(): string {
  const chunks: Buffer[] = [];
  const buffer = Buffer.alloc(4096);
  for (;;) {
    let read: number;
    try {
      read = readSync(0, buffer, 0, buffer.length, null);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'EAGAIN') continue;
      if (code === 'EOF') break;
      throw e;
    }
    if (read === 0) break;
    const chunk = Buffer.from(buffer.subarray(0, read));
    chunks.push(chunk);
    if (chunk.includes(0x0a)) break;
  }
  const text = Buffer.concat(chunks).toString('utf8');
  const end = text.search(/\r\n|\n|\r/);
  return end < 0 ? text : text.slice(0, end);
}

/** Console.ReadKey-based masked password prompt (echoes '*', prompt on stderr). */
function readPassword(prompt: string): Promise<string> {
  io.stderr(prompt);
  const stdin = process.stdin;
  // Piped or redirected input: the password is the first line of stdin.
  if (!stdin.isTTY) {
    const line = readStdinLine();
    io.stderr(EOL);
    return Promise.resolve(line);
  }

  return new Promise((resolve) => {
    let password = '';
    let pending = '';
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.resume();

    const finish = () => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      io.stderr(EOL);
      resolve(password);
    };

    const onData = (chunk: string) => {
      const data = pending + chunk;
      pending = '';
      for (let i = 0; i < data.length; i++) {
        const c = data[i]!;
        const code = c.charCodeAt(0);
        if (c === '\r' || c === '\n') {
          finish();
          return;
        }
        if (code === 0x03) {
          // Ctrl+C terminates the process, as it does for Console.ReadKey.
          stdin.setRawMode(false);
          process.exit(process.platform === 'win32' ? -1073741510 : 130);
        }
        if (code === 0x1b) {
          // Escape sequence (arrows, function keys): ReadKey reports these as keys with
          // a '\0' KeyChar, which the C# loop ignores. Skip the whole sequence.
          const next = data[i + 1];
          if (next === '[' || next === 'O') {
            let j = i + 2;
            while (j < data.length && !/[@-~]/.test(data[j]!)) j++;
            i = j;
          }
          continue;
        }
        if ((code === 0x08 || code === 0x7f) && password.length > 0) {
          password = password.slice(0, -1);
          io.stderr('\b \b');
        } else if (!isControl(code)) {
          password += c;
          io.stderr('*');
        }
      }
    };

    stdin.on('data', onData);
  });
}

/** char.IsControl: Unicode category Cc. */
function isControl(code: number): boolean {
  return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
}

function runInit(args: string[]): number {
  const parsed = parseArgs(args, [], ['-p', '--preset']);
  if (typeof parsed === 'string') return error(parsed);
  if (parsed.positionals.length > 0) return error('Usage: shroud init [--preset paranoid|financial|dev]');

  // Same detection as running without a shroud.json at all.
  const preset = optionValue(parsed.values, '-p', '--preset') ?? 'paranoid';

  if (!PRESET_NAMES.includes(preset)) {
    return error(`Unknown preset: ${preset}. Valid presets: ${PRESET_NAMES.join(', ')}.`);
  }

  const config = configForPreset(preset);

  if (fileExists(CONFIG_FILE_NAME)) {
    err(`  ${CONFIG_FILE_NAME} already exists. Delete it first to reinitialize.`);
    return 1;
  }

  saveConfig(config, CONFIG_FILE_NAME);
  const d = config.domains!;
  out(`  Created ${CONFIG_FILE_NAME} with preset: ${preset}`);
  out(
    `  Domains: onchain=${formatBool(d.onChain!.enabled)}, ` +
      `financial=${formatBool(d.financial!.enabled)} (${d.financial!.layer ?? ''}), ` +
      `identity=${formatBool(d.identity!.enabled)}, ` +
      `credentials=${formatBool(d.credentials!.enabled)}, ` +
      `secrets=${formatBool(d.secrets!.enabled)}`,
  );
  out(`  Threshold: ${formatDouble(config.threshold)}`);
  return 0;
}

/** A matched value for the report: truncated, or only its length with --no-values. */
function display(text: string, max: number, noValues: boolean): string {
  if (noValues) return `<${text.length} chars>`;
  return text.length > max ? text.slice(0, max) + '...' : text;
}

function printHeaderAndAbove(result: ScanResult, noValues: boolean, onSpan?: (index: number) => void): void {
  if (result.aboveThreshold.length > 0) {
    out();
    out(`    ${align('Domain', -12)} ${align('Type', -18)} ${align('Service', -24)} ${align('Conf', 5)}  Value`);
    out(`    ${'-'.repeat(90)}`);
    result.aboveThreshold.forEach((span, index) => {
      const svc = span.service ? span.service : '-';
      out(
        `    ${align(span.domain, -12)} ${align(span.entityType, -18)} ${align(svc, -24)} ` +
          `${align(formatFixed(span.confidence, 2), 5)}  ${display(span.matchedText, 35, noValues)}`,
      );
      onSpan?.(index);
    });
  }
}

function printBelow(result: ScanResult, noValues: boolean, onSpan?: (index: number) => void): void {
  if (result.belowThreshold.length > 0) {
    out();
    out(`    Below threshold (${formatFixed(result.threshold, 2)}):`);
    result.belowThreshold.forEach((span, index) => {
      out(
        `      ${align(span.domain, -12)} ${align(span.entityType, -18)} ` +
          `${align(formatFixed(span.confidence, 2), 5)}  ${display(span.matchedText, 40, noValues)}`,
      );
      onSpan?.(index);
    });
  }
}

function printSummaryHeader(path: string, result: ScanResult): void {
  out(`\n  ${path}`);
  out(
    `  Detected: ${result.allDetected.length} ` +
      `(tokenize: ${result.aboveThreshold.length}, ` +
      `below threshold: ${result.belowThreshold.length})`,
  );
}

function printScanResult(path: string, result: ScanResult, noValues: boolean): void {
  printSummaryHeader(path, result);
  printHeaderAndAbove(result, noValues);
  printBelow(result, noValues);
}

function printScanResultVerbose(
  path: string,
  result: ScanResult,
  diagnostics: ScanDiagnostics,
  debug: boolean,
  noValues: boolean,
): void {
  printSummaryHeader(path, result);

  if (debug && diagnostics.exclusionZones.length > 0) {
    out('\n    Exclusion zones:');
    for (const zone of diagnostics.exclusionZones) out(`      chars ${zone.start}-${zone.end}`);
  }

  const detailFor = (span: ScanResult['allDetected'][number]) =>
    diagnostics.allSpans.find(
      (d) =>
        d.span.start === span.start &&
        d.span.end === span.end &&
        d.span.entityType === span.entityType &&
        d.span.service === span.service &&
        !d.wasExcluded &&
        !d.failedLuhn,
    );

  printHeaderAndAbove(result, noValues, (i) => {
    const diag = detailFor(result.aboveThreshold[i]!);
    if (diag) printScoringDetail(diag.scoring, debug);
  });
  printBelow(result, noValues, (i) => {
    const diag = detailFor(result.belowThreshold[i]!);
    if (diag) printScoringDetail(diag.scoring, debug);
  });

  if (debug && diagnostics.overlapResolutions.length > 0) {
    out();
    out('    Overlap resolutions:');
    for (const res of diagnostics.overlapResolutions) {
      const dropped = display(res.dropped.matchedText, 30, noValues);
      const winner = display(res.winner.matchedText, 30, noValues);
      out(`      dropped "${dropped}" (${res.reason}) -> winner "${winner}"`);
    }
  }

  if (debug) {
    const excluded = diagnostics.allSpans.filter((d) => d.wasExcluded).length;
    const luhnFailed = diagnostics.allSpans.filter((d) => d.failedLuhn).length;
    if (excluded > 0 || luhnFailed > 0) {
      out();
      if (excluded > 0) out(`    ${excluded} matches excluded (in exclusion zones)`);
      if (luhnFailed > 0) out(`    ${luhnFailed} matches rejected (failed Luhn validation)`);
    }
  }
}

function printScoringDetail(scoring: ScoringDetail, debug: boolean): void {
  if (!scoring.hasContextWords) {
    // No context words: the final confidence IS the base.
    out(`              structural match (base: ${formatFixed(scoring.baseConfidence, 2)})`);
    return;
  }
  // Context words can boost even a structural (base >= 0.80) pattern, so show the real
  // breakdown whenever the pattern has any.
  const kind = scoring.isStructural ? 'structural' : 'contextual';
  const boost = scoring.finalConfidence - scoring.baseConfidence;
  out(`              ${kind} match (base: ${formatFixed(scoring.baseConfidence, 2)} + context: +${formatFixed(boost, 2)})`);
  if (scoring.contextWordsFound.length > 0) {
    const words = scoring.contextWordsFound.map((w) => `"${w}"`).join(', ');
    out(`              context words: ${words} (within ${CONTEXT_WINDOW_CHARS} chars)`);
  }
  if (debug) {
    if (scoring.assetBoostApplied) out(`              + asset name boost (+${formatFixed(ASSET_NAME_BOOST, 2)})`);
    if (scoring.currencyBoostApplied) out(`              + currency signal boost (+${formatFixed(CURRENCY_SIGNAL_BOOST, 2)})`);
    out(`              context window: chars ${scoring.contextWindowStart}-${scoring.contextWindowEnd}`);
  }
}

/**
 * --config path when given (null when that file does not exist), else shroud.json in the
 * current directory, else the default (paranoid) configuration.
 */
function loadConfigOrDefault(configPath: string | undefined): ShroudConfig | null {
  if (configPath !== undefined) return fileExists(configPath) ? loadConfig(configPath) : null;
  return fileExists(CONFIG_FILE_NAME) ? loadConfig(CONFIG_FILE_NAME) : defaultConfig();
}

function createScanner(config: ShroudConfig): SensitivityScanner {
  return new SensitivityScanner(getPatternsForConfig(config), config.threshold);
}

function loadOrCreateKey(config: ShroudConfig): Uint8Array {
  const keyPath = config.keyFile ?? '.shroud/vault.key';
  const dir = getDirectoryName(keyPath);

  if (dir && !directoryExists(dir)) mkdirSync(dir, { recursive: true });

  if (fileExists(keyPath)) return readFileSync(keyPath);

  const key = new Uint8Array(32);
  randomFillSync(key);
  writeFileSync(keyPath, key);
  err(`  Generated new key: ${keyPath}`);
  err('  Keep it to get the same token for the same value in later runs. It cannot unmask anything.');
  return key;
}

function* expandGlobs(args: readonly string[]): Generator<string> {
  for (const arg of args) {
    if (arg.includes('*') || arg.includes('?')) {
      let dir = getDirectoryName(arg);
      const pattern = getFileName(arg);
      if (!dir) dir = '.';
      if (!directoryExists(dir)) {
        throw new DotnetException('System.IO.DirectoryNotFoundException', `Could not find a part of the path '${dir}'.`);
      }
      yield* enumerateFiles(dir, pattern, false);
    } else {
      yield arg;
    }
  }
}

const USAGE = [
  'shroud - Sensitive data detection and masking for text files',
  '',
  'Usage:',
  '  shroud <directory>                         Vault a directory (safe copy + encrypted registry)',
  '  shroud vault <directory> [-o output]        Same as above, explicit command',
  '  shroud reveal <vault-dir> [-o output]       Decrypt and restore original files',
  "  shroud reveal <vault-dir> --text <file|->   Restore this vault's tokens in one text, to stdout or -o",
  '  shroud scan <file|-> [--verbose] [--debug]       Detect sensitive spans, print report (- reads stdin)',
  '  shroud mask <file.md> [-o output.md]        Replace spans with tokens, one-way (-o: one input only)',
  '  shroud init [--preset paranoid|financial|dev]     Create shroud.json config (default: paranoid)',
  '',
  'Exit codes:',
  '  0 success, 1 error (including a file that was not found).',
  '  scan --exit-code exits 2 when a file has spans that would be tokenized.',
  '',
  'Options:',
  '  --config <file>  scan, mask, vault: use this config instead of ./shroud.json',
  '  --no-values      scan: print the length of each match instead of its text',
  '  scan and mask take any text file; vault processes .md files only.',
  '',
  'Passwords:',
  '  vault and reveal take the password from -p, else from the SHROUD_PASSWORD',
  '  environment variable, else from one line of piped stdin, else they prompt.',
  '',
  'Vault mode:',
  '  Point at a directory. Shroud scans all .md files, produces:',
  '    <dir>.shroud/public/       Masked copies (safe to share)',
  '    <dir>.shroud/vault.shroud  Encrypted token registry (password required)',
  '    <dir>.shroud/manifest.json Metadata for agents (no secret values)',
  "  Only vault output can be revealed; 'mask' keeps no record of the original values.",
  '',
  'Presets:',
  '  paranoid   All domains, lower threshold, directional financial (DEFAULT)',
  '  financial  All domains, markets-level financial detection',
  '  dev        On-chain + identity + credentials + secrets (no financial)',
  '',
  "Without shroud.json, paranoid mode is used. Run 'shroud init' to customize.",
  '',
  'Diagnostics:',
  '  --verbose  Show confidence scoring breakdown for each detection',
  '  --debug    Full diagnostics: exclusion zones, overlap resolutions, context windows',
  '',
  'Trust:',
  // Verbatim from the C# CLI, which the TS CLI reproduces byte for byte.
  '  Zero runtime dependencies. Source-auditable.',
  '  https://github.com/dvdarkin/shroud',
];

function printUsage(): number {
  out(USAGE.join(EOL));
  return 0;
}

function error(message: string): number {
  err(`  Error: ${message}`);
  return 1;
}

const NODE_ERRORS: Readonly<Record<string, string>> = {
  ENOENT: 'System.IO.FileNotFoundException',
  EACCES: 'System.UnauthorizedAccessException',
  EPERM: 'System.UnauthorizedAccessException',
  EISDIR: 'System.UnauthorizedAccessException',
};

const NULL_REFERENCE = 'System.NullReferenceException';

/**
 * Mirrors the .NET host for an unhandled exception: one "Unhandled exception. <Type>:
 * <message>" line on stderr (the TS port prints no .NET stack trace) and the host's
 * exit code: 0xE0434352 on Windows, or 0xC0000005 for a NullReferenceException (which
 * .NET raises from an access violation). On Unix the .NET host aborts (134).
 */
export function crash(e: unknown): never {
  let type = 'System.Exception';
  let message = e instanceof Error ? e.message : String(e);
  if (e instanceof DotnetException) {
    type = e.dotnetType;
  } else if (e instanceof TypeError && /Cannot read properties of (null|undefined)/.test(e.message)) {
    type = NULL_REFERENCE;
    message = 'Object reference not set to an instance of an object.';
  } else if (e instanceof SyntaxError || e instanceof ConfigFormatError || e instanceof VaultFormatError) {
    type = 'System.Text.Json.JsonException';
  } else if (e instanceof Error) {
    const code = (e as NodeJS.ErrnoException).code;
    type = (code && NODE_ERRORS[code]) || 'System.Exception';
  }
  process.stderr.write(`Unhandled exception. ${type}: ${message}${EOL}`);
  if (process.platform !== 'win32') process.exit(134);
  process.exit(type === NULL_REFERENCE ? -1073741819 : -532462766);
}

