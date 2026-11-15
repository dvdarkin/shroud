// Interop vectors produced by the C# build itself (tools/dotnet-probe, mode "vectors"):
// a real vault written by VaultBuilder.WriteOutput, blobs from VaultEncryption, token ids
// from SpanMasker, and shroud.json files from ShroudConfig.Save. This file has no C#
// counterpart; it pins the byte-level format documented in FORMAT.md.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ConfigFormatError, configForPreset, loadConfig, parseConfig, serializeConfig } from '../../src/config.js';
import { SpanMasker } from '../../src/masker.js';
import type { EntityType, SensitiveSpan } from '../../src/models.js';
import {
  VaultBuilder,
  buildManifest,
  parseManifest,
  parseVaultData,
  serializeManifest,
  serializeVaultData,
} from '../../src/vault-builder.js';
import { decrypt, decryptString, encryptWith, deriveKey } from '../../src/vault-encryption.js';

interface Vectors {
  runtime: string;
  password: string;
  vaultShroudBase64: string;
  vaultJson: string;
  manifestJson: string;
  publicFilesBase64: Record<string, string>;
  smallBlobs: Record<string, string>;
  maskKeyHex: string;
  tokens: [EntityType, string, string, string][];
  configs: Record<string, string>;
}

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../../test/fixtures/dotnet-vectors.json', import.meta.url)), 'utf8'),
) as Vectors;
const newline = vectors.vaultJson.includes('\r\n') ? '\r\n' : '\n';
const fromHex = (h: string) => String.fromCharCode(...(h.match(/.{4}/g) ?? []).map((x) => parseInt(x, 16)));

describe('DotnetInteropTests', () => {
  test(`decrypts a vault.shroud written by the C# build (${vectors.runtime})`, () => {
    const blob = Buffer.from(vectors.vaultShroudBase64, 'base64');
    assert.equal(decryptString(blob, vectors.password), vectors.vaultJson);
    assert.equal(decryptString(blob, vectors.password + 'x'), null);
  });

  test('re-serializes the C# vault payload byte for byte', () => {
    const data = parseVaultData(vectors.vaultJson);
    assert.ok(data);
    assert.equal(data.version, 1);
    assert.equal(serializeVaultData(data, newline), vectors.vaultJson);
  });

  test('re-serializes the C# manifest byte for byte', () => {
    assert.equal(serializeManifest(parseManifest(vectors.manifestJson), newline), vectors.manifestJson);
  });

  test('C# file hashes are sha256 of the public file bytes', () => {
    const data = parseVaultData(vectors.vaultJson)!;
    const hashes = new Map([...data.fileHashes!].map(([k, v]) => [k.replace(/\\/g, '/'), v]));
    assert.equal(hashes.size, Object.keys(vectors.publicFilesBase64).length);
    for (const [rel, b64] of Object.entries(vectors.publicFilesBase64)) {
      const digest = createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex');
      assert.equal(hashes.get(rel), `sha256:${digest}`, rel);
    }
  });

  test('reveals the C# public files with the C# token registry', () => {
    const data = parseVaultData(vectors.vaultJson)!;
    const revealed = Object.fromEntries(
      Object.entries(vectors.publicFilesBase64).map(([rel, b64]) => {
        let content = Buffer.from(b64, 'base64').toString('utf8');
        for (const [id, value] of data.tokens!) content = content.split(`[${id}]`).join(value ?? '');
        return [rel, content];
      }),
    );
    assert.equal(revealed['clean.md'], 'Nothing here.');
    assert.equal(
      revealed['sub/b.md'],
      'SSN 123-45-6789\r\nghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA\r\nSent 0.5 ETH again\r\n',
    );
    assert.equal(
      revealed['a.md'],
      'Sent 0.5 ETH to 0x1111111111111111111111111111111111111111 at $1,234.\n' +
        String.raw`password = "p<a>&'+` + '`' + String.raw`\\x" and \\192.168.10.2\share\f.md` + '\n' +
        'bought \u0661\u0662\u0663 ETH \u00e9t\u00e9 \uD83D\uDE00 nonce:\u0085123456 tx\n',
    );
  });

  test('decrypts small C# blobs, including empty and non-ASCII passwords', () => {
    for (const [password, entry] of Object.entries(vectors.smallBlobs)) {
      const sep = entry.indexOf('|');
      const blob = Buffer.from(entry.slice(0, sep), 'base64');
      assert.equal(decryptString(blob, password), entry.slice(sep + 1), JSON.stringify(password));
      assert.equal(blob.length, 44 + Buffer.byteLength(entry.slice(sep + 1), 'utf8'));
    }
  });

  test('container layout is salt | nonce | tag | ciphertext', () => {
    const [b64, plain] = vectors.smallBlobs['test-password-123']!.split('|') as [string, string];
    const blob = Buffer.from(b64, 'base64');
    const salt = blob.subarray(0, 16);
    const nonce = blob.subarray(16, 28);
    const key = deriveKey('test-password-123', salt);
    // Re-encrypting with the same salt, nonce and key must reproduce the C# bytes exactly.
    assert.deepEqual(Buffer.from(encryptWith(Buffer.from(plain, 'utf8'), key, salt, nonce)), blob);
    assert.ok(decrypt(blob, 'test-password-123'));
  });

  test('token ids match the C# SpanMasker for the same key', () => {
    const masker = new SpanMasker(Buffer.from(vectors.maskKeyHex, 'hex'));
    for (const [type, textHex, tokenId, maskedText] of vectors.tokens) {
      const text = fromHex(textHex);
      const span: SensitiveSpan = { start: 0, end: text.length, entityType: type, domain: 'OnChain', confidence: 1, matchedText: text, service: '' };
      const result = masker.mask(text, { allDetected: [span], aboveThreshold: [span], belowThreshold: [], threshold: 0.7 });
      assert.equal(result.tokens[0]!.tokenId, tokenId, `${type} ${JSON.stringify(text)}`);
      assert.equal(result.maskedText, maskedText);
    }
  });

  test('shroud.json from each preset matches ShroudConfig.Save byte for byte', () => {
    for (const preset of ['financial', 'dev', 'paranoid']) {
      assert.equal(serializeConfig(configForPreset(preset), newline), vectors.configs[preset], preset);
    }
  });

  test('a config with nulls and an exponent threshold serializes like ShroudConfig.Save', () => {
    // C#: new ShroudConfig { KeyFile = "keys/k.bin", Threshold = 1e-7 } with
    // Domains.Financial.Layer = null and Domains.Secrets = null (null properties are omitted).
    const config = configForPreset('unknown-falls-back');
    config.domains = {
      onChain: { enabled: true, layer: 'markets' },
      financial: { enabled: true, layer: null },
      identity: { enabled: true, layer: 'markets' },
      credentials: { enabled: true, layer: 'markets' },
      secrets: null,
    };
    config.threshold = 1e-7;
    config.keyFile = 'keys/k.bin';
    config.preset = null;
    const csharp = vectors.configs['custom']!;
    assert.equal(serializeConfig(config, newline), csharp);
    assert.match(csharp, /"threshold": 1E-07/);
  });

  test('parsing that config follows System.Text.Json defaults for missing properties', () => {
    const config = parseConfig(vectors.configs['custom']!);
    assert.equal(config.threshold, 1e-7);
    assert.equal(config.keyFile, 'keys/k.bin');
    assert.equal(config.preset, null);
    // "layer" is absent (omitted null), so the DomainToggle default applies.
    assert.equal(config.domains!.financial!.layer, 'markets');
    // "secrets" is absent, so the DomainConfig default toggle applies.
    assert.deepEqual(config.domains!.secrets, { enabled: true, layer: 'markets' });
  });

  // test/fixtures/dotnet-config-vectors.json: ShroudConfig.Load (PropertyNameCaseInsensitive)
  // on each document, from tools/dotnet-probe mode "configs" <inputs.json> <out.json>, where
  // inputs.json is the array of the "json" fields. Covers mixed case at every level,
  // duplicate names in the same and in different case, a replaced nested object, a wrong
  // type before a valid duplicate, and non-ASCII look-alike keys (KELVIN SIGN, long s, dotted I).
  test('shroud.json property names match like System.Text.Json PropertyNameCaseInsensitive', () => {
    const configVectors = JSON.parse(
      readFileSync(fileURLToPath(new URL('../../../test/fixtures/dotnet-config-vectors.json', import.meta.url)), 'utf8'),
    ) as ({ json: string; error: string } | { json: string; domains: unknown; threshold: number; keyFile: string | null; preset: string | null })[];
    assert.ok(configVectors.length >= 28);
    for (const v of configVectors) {
      if ('error' in v) {
        assert.equal(v.error, 'System.Text.Json.JsonException', v.json);
        assert.throws(() => parseConfig(v.json), ConfigFormatError, v.json);
        continue;
      }
      const c = parseConfig(v.json);
      assert.deepEqual(
        { domains: c.domains, threshold: c.threshold, keyFile: c.keyFile ?? null, preset: c.preset ?? null },
        { domains: v.domains, threshold: v.threshold, keyFile: v.keyFile, preset: v.preset },
        v.json,
      );
    }
  });

  // conformance/vaults: six vaults written by the C# VaultBuilder from <name>/input/. The
  // masking key is random, so token ids cannot be compared, but meta.json summarises the
  // manifest by (type abbreviation, service), and the manifest source is the directory name.
  test('VaultBuilder on the conformance vault inputs gives the C# manifest services and source', () => {
    const vaultsDir = fileURLToPath(new URL('../../../../conformance/vaults/', import.meta.url));
    const names = readdirSync(vaultsDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name);
    assert.ok(names.length >= 6);
    for (const name of names) {
      const dir = join(vaultsDir, name);
      const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as {
        config: string;
        tokenCount: number;
        manifestSource: string;
        manifestServices: { typeAbbreviation: string; service: string; tokens: number; occurrences: number }[];
      };
      const csharpManifest = JSON.parse(readFileSync(join(dir, 'vault', 'manifest.json'), 'utf8')) as { source: string };
      const config = loadConfig(join(vaultsDir, '..', meta.config));
      const result = new VaultBuilder(config).build(join(dir, 'input'));
      const manifest = buildManifest(result, 'created');

      assert.equal(manifest.source, meta.manifestSource, name);
      assert.equal(manifest.source, csharpManifest.source, name);
      assert.equal(manifest.tokenCount, meta.tokenCount, name);
      const summary = new Map<string, { typeAbbreviation: string; service: string; tokens: number; occurrences: number }>();
      for (const [id, t] of manifest.tokens) {
        const typeAbbreviation = id.slice(0, id.indexOf(':'));
        const key = `${typeAbbreviation}|${t.service}`;
        const s = summary.get(key) ?? { typeAbbreviation, service: t.service, tokens: 0, occurrences: 0 };
        s.tokens++;
        s.occurrences += t.occurrences;
        summary.set(key, s);
      }
      const order = (a: { typeAbbreviation: string; service: string }, b: { typeAbbreviation: string; service: string }) =>
        a.typeAbbreviation < b.typeAbbreviation ? -1 : a.typeAbbreviation > b.typeAbbreviation ? 1 : a.service < b.service ? -1 : a.service > b.service ? 1 : 0;
      assert.deepEqual([...summary.values()].sort(order), [...meta.manifestServices].sort(order), name);
    }
  });
});
