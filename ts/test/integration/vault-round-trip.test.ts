// Port of src/Shroud.Tests.Integration/VaultRoundTripTests.cs
// End-to-end vault round-trip: original files -> vault -> reveal -> compare SHA-256 hashes.
// Verifies that the full pipeline (scan, mask, encrypt, decrypt, unmask) preserves
// every byte of the original content.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { afterEach, beforeEach, describe, test, type TestContext } from 'node:test';
import {
  enumerateFiles,
  getDirectoryName,
  getRelativePath,
  pathCombine,
} from '../../src/internal/dotnet-path.js';
import { directoryExists, readAllText, writeAllText } from '../../src/internal/text-io.js';
import { VaultBuilder, parseVaultData } from '../../src/vault-builder.js';
import { decryptString } from '../../src/vault-encryption.js';

const PASSWORD = 'test-password-1234';

describe('VaultRoundTripTests', () => {
  let sourceDir = '';
  let vaultDir = '';
  let revealDir = '';

  beforeEach(() => {
    const testId = randomUUID().replace(/-/g, '').slice(0, 8);
    sourceDir = pathCombine(tmpdir(), `shroud-test-${testId}`);
    vaultDir = sourceDir + '.shroud';
    revealDir = sourceDir + '.revealed';
    mkdirSync(sourceDir, { recursive: true });
  });

  afterEach(() => {
    for (const dir of [sourceDir, vaultDir, revealDir]) {
      if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    }
  });

  function hashFile(path: string): string {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  }

  /**
   * Runs the full vault -> reveal pipeline and returns SHA-256 hashes
   * of each file's original and revealed content.
   */
  function vaultAndReveal(t: TestContext): Map<string, { original: string; revealed: string }> {
    // Capture original hashes
    const originalHashes = new Map<string, string>();
    for (const file of enumerateFiles(sourceDir, '*.md', true)) {
      originalHashes.set(getRelativePath(sourceDir, file), hashFile(file));
    }

    // Vault
    const builder = new VaultBuilder();
    const result = builder.build(sourceDir);
    builder.writeOutput(result, vaultDir, PASSWORD);

    t.diagnostic(`  Vaulted: ${result.maskedFiles.length} files, ${result.tokens.size} tokens`);

    // Verify masked files exist and contain tokens (if any detections)
    const publicDir = pathCombine(vaultDir, 'public');
    assert.ok(directoryExists(publicDir));

    // Reveal: decrypt vault, replace tokens in public files
    const encrypted = readFileSync(pathCombine(vaultDir, 'vault.shroud'));
    const json = decryptString(encrypted, PASSWORD);
    assert.notEqual(json, null, 'decryption with correct password should succeed');

    const vaultData = parseVaultData(json!);
    assert.notEqual(vaultData, null);

    mkdirSync(revealDir, { recursive: true });
    for (const file of enumerateFiles(publicDir, '*.md', true)) {
      const relative = getRelativePath(publicDir, file);
      let content = readAllText(file);

      for (const [tokenId, value] of vaultData!.tokens!) content = content.split(`[${tokenId}]`).join(value ?? '');

      const outPath = pathCombine(revealDir, relative);
      const dir = getDirectoryName(outPath);
      if (dir) mkdirSync(dir, { recursive: true });
      writeAllText(outPath, content);
    }

    // Collect revealed hashes
    const hashes = new Map<string, { original: string; revealed: string }>();
    for (const [relative, original] of originalHashes) {
      const revealedPath = pathCombine(revealDir, relative);
      assert.ok(existsSync(revealedPath), `revealed file ${relative} should exist`);
      hashes.set(relative, { original, revealed: hashFile(revealedPath) });
    }

    return hashes;
  }

  test('single file, round trip preserves content', (t) => {
    const original = 'Sent 0.5 ETH to 0x1111111111111111111111111111111111111111 at $1,234.';
    writeAllText(pathCombine(sourceDir, 'notes.md'), original);

    const hashes = vaultAndReveal(t);

    assert.ok(hashes.has('notes.md'));
    assert.equal(hashes.get('notes.md')!.revealed, hashes.get('notes.md')!.original, 'revealed file should be byte-identical to original');
  });

  test('three files, round trip all preserved', (t) => {
    const files: Record<string, string> = {
      'wallet.md': [
        '## Wallet Summary',
        'Main: 0x2222222222222222222222222222222222222222',
        'Cold: bc1qaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'Balance: $45,000 across both wallets.',
        'API key for alerts: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA',
      ].join('\n'),
      'trades.md': ['## 2026-04-01', 'bought 100 NVDA for $120 each. Total: $12,000.', 'SSN on file: 123-45-6789'].join('\n'),
      'subdir/defi.md': [
        '## DeFi Positions',
        'Staked 1,000 USDC in pool 0x3333333333333333333333333333333333333333',
        'Tx: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'Yield so far: $42.50',
      ].join('\n'),
    };

    for (const [name, content] of Object.entries(files)) {
      const path = pathCombine(sourceDir, name);
      const dir = getDirectoryName(path);
      if (dir) mkdirSync(dir, { recursive: true });
      writeAllText(path, content);
    }

    const hashes = vaultAndReveal(t);

    assert.equal(hashes.size, 3, 'all 3 files should be vaulted and revealed');

    for (const [name, { original, revealed }] of hashes) {
      t.diagnostic(`  ${name}: original=${original.slice(0, 16)}... revealed=${revealed.slice(0, 16)}...`);
      assert.equal(revealed, original, `${name} should be byte-identical after round-trip`);
    }
  });

  test('clean file, no detections, preserved verbatim', (t) => {
    const original = 'This file has no sensitive data whatsoever. Just plain text.';
    writeAllText(pathCombine(sourceDir, 'clean.md'), original);

    const hashes = vaultAndReveal(t);

    assert.equal(hashes.get('clean.md')!.revealed, hashes.get('clean.md')!.original, 'file with no detections should pass through unchanged');
  });

  test('wrong password, reveal fails', () => {
    writeAllText(pathCombine(sourceDir, 'secret.md'), 'Key: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA');

    const builder = new VaultBuilder();
    const result = builder.build(sourceDir);
    builder.writeOutput(result, vaultDir, PASSWORD);

    const encrypted = readFileSync(pathCombine(vaultDir, 'vault.shroud'));
    const json = decryptString(encrypted, 'wrong-password');

    assert.equal(json, null, 'wrong password should fail decryption');
  });
});
