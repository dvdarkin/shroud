// Port of src/Shroud.Tests.Unit/ConfigCaseInsensitiveTests.cs
// shroud.json property names are matched case-insensitively at every level, so a user who
// writes "onchain" instead of "onChain" gets the configuration they wrote.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, test } from 'node:test';
import { type ShroudConfig, loadConfig } from '../../src/config.js';

describe('ConfigCaseInsensitiveTests', () => {
  const path = join(tmpdir(), `shroud-config-${randomUUID().replace(/-/g, '')}.json`);

  afterEach(() => {
    if (existsSync(path)) rmSync(path);
  });

  function loadJson(json: string): ShroudConfig {
    writeFileSync(path, json);
    return loadConfig(path);
  }

  test('lowercase nested key, is honoured', () => {
    const cfg = loadJson('{ "domains": { "onchain": { "enabled": false } } }');

    assert.equal(cfg.domains!.onChain!.enabled, false, '"onchain" must configure the onChain domain');
  });

  test('mixed case keys, at every level, are honoured', () => {
    const cfg = loadJson(`{
  "DOMAINS": {
    "OnChain": { "ENABLED": false },
    "FINANCIAL": { "Enabled": true, "LAYER": "magnitudes" },
    "identity": { "enabled": false },
    "Credentials": { "Enabled": false },
    "SECRETS": { "enabled": false }
  },
  "Threshold": 0.9,
  "KEYFILE": "k.key",
  "Preset": "custom"
}`);

    assert.equal(cfg.domains!.onChain!.enabled, false);
    assert.equal(cfg.domains!.financial!.enabled, true);
    assert.equal(cfg.domains!.financial!.layer, 'magnitudes');
    assert.equal(cfg.domains!.identity!.enabled, false);
    assert.equal(cfg.domains!.credentials!.enabled, false);
    assert.equal(cfg.domains!.secrets!.enabled, false);
    assert.equal(cfg.threshold, 0.9);
    assert.equal(cfg.keyFile, 'k.key');
    assert.equal(cfg.preset, 'custom');
  });

  test('empty object, keeps class defaults, not the paranoid preset', () => {
    // Unchanged behaviour: {} is not Default(); it keeps the property defaults.
    const cfg = loadJson('{}');

    assert.equal(cfg.threshold, 0.7);
    assert.equal(cfg.domains!.financial!.layer, 'markets');
    assert.equal(cfg.preset, null);
  });
});
