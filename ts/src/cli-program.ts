/**
 * The `shroud` command line. Commands, flags, exit codes and output text match the
 * C# Shroud.Cli (public build, without Shroud.Private patterns) line for line,
 * including its line endings (os.EOL, CRLF on Windows) and number formatting.
 */
import { randomFillSync } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { EOL } from 'node:os';
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
  getRelativePath,
  pathCombine,
} from './internal/dotnet-path.js';
import { directoryExists, fileExists, readAllText, writeAllText } from './internal/text-io.js';
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
  parseVaultData,
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

  // If first arg is a directory path (no command prefix), treat as vault
  if (directoryExists(args[0]!)) return runVault(args);

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
      return error(`Unknown command: ${args[0]}`);
  }
}

function runScan(args: string[]): number {
  const files: string[] = [];
  let verbose = false;
  let debug = false;

  for (const arg of args) {
    if (arg === '--verbose' || arg === '-v') verbose = true;
    else if (arg === '--debug') debug = true;
    else files.push(arg);
  }

  if (files.length === 0) return error('Usage: shroud scan <file.md> [file2.md ...] [--verbose] [--debug]');

  if (debug) verbose = true;

  const config = loadConfigOrDefault();
  const scanner = createScanner(config);

  for (const path of expandGlobs(files)) {
    if (!fileExists(path)) {
      err(`  File not found: ${path}`);
      continue;
    }

    const text = readAllText(path);

    if (verbose) {
      const { result, diagnostics } = scanner.scanWithDiagnostics(text);
      printScanResultVerbose(path, result, diagnostics, debug);
    } else {
      printScanResult(path, scanner.scan(text));
    }
  }

  return 0;
}

function runMask(args: string[]): number {
  let outputPath: string | undefined;
  const files: string[] = [];

  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '-o' || args[i] === '--output') && i + 1 < args.length) {
      outputPath = args[++i];
    } else {
      files.push(args[i]!);
    }
  }

  if (files.length === 0) return error('Usage: shroud mask <file.md> [-o output.md]');

  const inputs = [...expandGlobs(files)];
  if (outputPath !== undefined && inputs.length > 1) {
    return error(
      `-o ${outputPath} names one output file but ${inputs.length} input files were given; ` +
        'mask them one at a time, or omit -o to mask each file in place.',
    );
  }

  const config = loadConfigOrDefault();
  const scanner = createScanner(config);
  const key = loadOrCreateKey(config);
  const masker = new SpanMasker(key);

  for (const path of inputs) {
    if (!fileExists(path)) {
      err(`  File not found: ${path}`);
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

    out(`  ${path} -> ${target}`);
    out(`    Masked ${maskResult.tokens.length} spans:`);
    for (const token of maskResult.tokens) {
      out(`      [${token.tokenId}] ${token.domain}/${token.entityType}`);
    }
  }

  return 0;
}

async function runVault(args: string[]): Promise<number> {
  if (args.length === 0) return error('Usage: shroud vault <directory>');

  const sourceDir = args[0]!;
  if (!directoryExists(sourceDir)) return error(`Directory not found: ${sourceDir}`);

  let outputDir: string | undefined;
  let passwordArg: string | undefined;
  for (let i = 1; i < args.length; i++) {
    if ((args[i] === '-o' || args[i] === '--output') && i + 1 < args.length) outputDir = args[++i];
    else if ((args[i] === '-p' || args[i] === '--password') && i + 1 < args.length) passwordArg = args[++i];
  }

  outputDir ??= sourceDir.replace(/[/\\]+$/, '') + '.shroud';

  const config = loadConfigOrDefault();
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

  if (passwordArg === undefined) {
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
  if (args.length === 0) return error('Usage: shroud reveal <vault-dir>');

  const vaultDir = args[0]!;
  const vaultFile = pathCombine(vaultDir, 'vault.shroud');
  const publicDir = pathCombine(vaultDir, 'public');

  if (!fileExists(vaultFile)) return error(`No vault.shroud found in ${vaultDir}`);

  let passwordArg: string | undefined;
  let outputDir: string | undefined;
  for (let i = 1; i < args.length; i++) {
    if ((args[i] === '-p' || args[i] === '--password') && i + 1 < args.length) passwordArg = args[++i];
    else if ((args[i] === '-o' || args[i] === '--output') && i + 1 < args.length) outputDir = args[++i];
  }

  const password = passwordArg ?? (await readPassword('  Vault password: '));
  if (!password) return error('Password required.');

  out('  Decrypting...');
  const encrypted = readFileSync(vaultFile);
  const json = decryptString(encrypted, password);
  if (json === null) return error('Wrong password.');

  const vaultData = parseVaultData(json);
  if (vaultData === null) return error('Corrupt vault file.');

  outputDir ??= vaultDir.split('.shroud').join('.revealed');
  mkdirSync(outputDir, { recursive: true });

  let filesRevealed = 0;
  if (directoryExists(publicDir)) {
    for (const file of enumerateFiles(publicDir, '*.md', true)) {
      const relative = getRelativePath(publicDir, file);
      let content = readAllText(file);

      // Replace all tokens with original values, in vault order (ordinal, all occurrences)
      if (vaultData.tokens === null) throw new DotnetException('System.NullReferenceException', 'Object reference not set to an instance of an object.');
      for (const [tokenId, value] of vaultData.tokens) {
        content = content.split(`[${tokenId}]`).join(value ?? '');
      }

      const outPath = pathCombine(outputDir, relative);
      const dir = getDirectoryName(outPath);
      if (dir) mkdirSync(dir, { recursive: true });
      writeAllText(outPath, content);
      filesRevealed++;
    }
  }

  out(`\n  ${filesRevealed} files revealed to ${outputDir}/`);
  return 0;
}

/** Console.ReadKey-based masked password prompt (echoes '*', prompt on stderr). */
function readPassword(prompt: string): Promise<string> {
  io.stderr(prompt);
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    throw new DotnetException(
      'System.InvalidOperationException',
      'Cannot read keys when either application does not have a console or when console input has been redirected. Try Console.Read.',
    );
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
  let preset = 'financial';
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '--preset' || args[i] === '-p') && i + 1 < args.length) preset = args[++i]!;
  }

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
      `identity=${formatBool(d.identity!.enabled)}`,
  );
  out(`  Threshold: ${formatDouble(config.threshold)}`);
  return 0;
}

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + '...' : text;
}

function printHeaderAndAbove(result: ScanResult, onSpan?: (index: number) => void): void {
  if (result.aboveThreshold.length > 0) {
    out();
    out(`    ${align('Domain', -12)} ${align('Type', -18)} ${align('Service', -24)} ${align('Conf', 5)}  Value`);
    out(`    ${'-'.repeat(90)}`);
    result.aboveThreshold.forEach((span, index) => {
      const svc = span.service ? span.service : '-';
      out(
        `    ${align(span.domain, -12)} ${align(span.entityType, -18)} ${align(svc, -24)} ` +
          `${align(formatFixed(span.confidence, 2), 5)}  ${truncate(span.matchedText, 35)}`,
      );
      onSpan?.(index);
    });
  }
}

function printBelow(result: ScanResult, onSpan?: (index: number) => void): void {
  if (result.belowThreshold.length > 0) {
    out();
    out(`    Below threshold (${formatFixed(result.threshold, 2)}):`);
    result.belowThreshold.forEach((span, index) => {
      out(
        `      ${align(span.domain, -12)} ${align(span.entityType, -18)} ` +
          `${align(formatFixed(span.confidence, 2), 5)}  ${truncate(span.matchedText, 40)}`,
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

function printScanResult(path: string, result: ScanResult): void {
  printSummaryHeader(path, result);
  printHeaderAndAbove(result);
  printBelow(result);
}

function printScanResultVerbose(path: string, result: ScanResult, diagnostics: ScanDiagnostics, debug: boolean): void {
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

  printHeaderAndAbove(result, (i) => {
    const diag = detailFor(result.aboveThreshold[i]!);
    if (diag) printScoringDetail(diag.scoring, debug);
  });
  printBelow(result, (i) => {
    const diag = detailFor(result.belowThreshold[i]!);
    if (diag) printScoringDetail(diag.scoring, debug);
  });

  if (debug && diagnostics.overlapResolutions.length > 0) {
    out();
    out('    Overlap resolutions:');
    for (const res of diagnostics.overlapResolutions) {
      const dropped = truncate(res.dropped.matchedText, 30);
      const winner = truncate(res.winner.matchedText, 30);
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

function loadConfigOrDefault(): ShroudConfig {
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
  err('  Back this up. Losing it means masked data cannot be unmasked.');
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
  '  shroud scan <file.md> [--verbose] [--debug]      Detect sensitive spans, print report',
  '  shroud mask <file.md> [-o output.md]        Replace sensitive spans with tokens (-o: one input only)',
  '  shroud init [--preset financial|dev|paranoid]     Create shroud.json config',
  '',
  'Vault mode:',
  '  Point at a directory. Shroud scans all .md files, produces:',
  '    <dir>.shroud/public/       Masked copies (safe to share)',
  '    <dir>.shroud/vault.shroud  Encrypted token registry (password required)',
  '    <dir>.shroud/manifest.json Metadata for agents (no secret values)',
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
  '  Zero dependencies beyond .NET 8 runtime. Source-auditable.',
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

