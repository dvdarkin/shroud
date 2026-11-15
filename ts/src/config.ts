/**
 * Detection configuration (`shroud.json`) with three presets:
 *
 *  - paranoid: all domains, directional financial, threshold 0.50 (the default);
 *  - financial: all domains, markets-level financial, threshold 0.70;
 *  - dev: no financial domain, threshold 0.70.
 *
 * Financial detection is layered: "magnitudes" detects amounts/prices/quantities,
 * "markets" adds market pairs, "directional" adds everything else in the domain.
 *
 * The JSON format and its (de)serialization rules mirror System.Text.Json with the
 * camelCase naming policy used by the C# build: property names are matched
 * case-sensitively, unknown properties are ignored, missing properties keep their
 * defaults, a null/wrong-typed value type throws, and null strings/objects are kept.
 */
import { readAllText, writeAllText } from './internal/text-io.js';
import { serializeIndented } from './internal/dotnet-json.js';

export interface DomainToggle {
  enabled: boolean;
  /**
   * Financial detection granularity: "magnitudes", "markets" or "directional".
   * Each level includes the previous ones. Only meaningful for the financial domain.
   * May be null when a config file sets it to null.
   */
  layer: string | null;
}

export interface DomainConfig {
  onChain: DomainToggle | null;
  financial: DomainToggle | null;
  identity: DomainToggle | null;
  credentials: DomainToggle | null;
  secrets: DomainToggle | null;
}

export interface ShroudConfig {
  domains: DomainConfig | null;
  threshold: number;
  keyFile?: string | null;
  preset?: string | null;
}

function toggle(enabled = true, layer: string | null = 'markets'): DomainToggle {
  return { enabled, layer };
}

function createDomainConfig(): DomainConfig {
  return {
    onChain: toggle(true),
    financial: toggle(true, 'markets'),
    identity: toggle(true),
    credentials: toggle(true),
    secrets: toggle(true),
  };
}

/** A config with the C# parameterless-constructor defaults (all domains, markets, 0.70). */
export function createConfig(): ShroudConfig {
  return { domains: createDomainConfig(), threshold: 0.7, keyFile: null, preset: null };
}

/** The built-in default: the paranoid preset. */
export function defaultConfig(): ShroudConfig {
  return configForPreset('paranoid');
}

/** Config for a named preset; unknown names fall back to the default (paranoid). */
export function configForPreset(preset: string): ShroudConfig {
  switch (preset) {
    case 'financial':
      return {
        domains: { ...createDomainConfig(), onChain: toggle(true), financial: toggle(true, 'markets'), identity: toggle(true) },
        threshold: 0.7,
        keyFile: null,
        preset: 'financial',
      };
    case 'dev':
      return {
        domains: { ...createDomainConfig(), onChain: toggle(true), financial: toggle(false), identity: toggle(true) },
        threshold: 0.7,
        keyFile: null,
        preset: 'dev',
      };
    case 'paranoid':
      return {
        domains: { ...createDomainConfig(), onChain: toggle(true), financial: toggle(true, 'directional'), identity: toggle(true) },
        threshold: 0.5,
        keyFile: null,
        preset: 'paranoid',
      };
    default:
      return defaultConfig();
  }
}

// ---------------------------------------------------------------------------
// System.Text.Json-compatible (de)serialization
// ---------------------------------------------------------------------------

export class ConfigFormatError extends Error {
  constructor(path: string, detail: string) {
    super(`The JSON value could not be converted at '${path}': ${detail}`);
    this.name = 'ConfigFormatError';
  }
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function isObject(v: Json): v is { [key: string]: Json } {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function readBool(v: Json, path: string): boolean {
  if (typeof v !== 'boolean') throw new ConfigFormatError(path, 'expected true or false');
  return v;
}

function readNumber(v: Json, path: string): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new ConfigFormatError(path, 'expected a number');
  return v;
}

function readNullableString(v: Json, path: string): string | null {
  if (v !== null && typeof v !== 'string') throw new ConfigFormatError(path, 'expected a string or null');
  return v;
}

function readToggle(v: Json, path: string): DomainToggle | null {
  if (v === null) return null;
  if (!isObject(v)) throw new ConfigFormatError(path, 'expected an object or null');
  const t = toggle();
  for (const [key, value] of Object.entries(v)) {
    if (key === 'enabled') t.enabled = readBool(value, `${path}.enabled`);
    else if (key === 'layer') t.layer = readNullableString(value, `${path}.layer`);
  }
  return t;
}

const DOMAIN_KEYS = ['onChain', 'financial', 'identity', 'credentials', 'secrets'] as const;

function readDomains(v: Json, path: string): DomainConfig | null {
  if (v === null) return null;
  if (!isObject(v)) throw new ConfigFormatError(path, 'expected an object or null');
  const d = createDomainConfig();
  for (const [key, value] of Object.entries(v)) {
    const k = DOMAIN_KEYS.find((name) => name === key);
    if (k) d[k] = readToggle(value, `${path}.${k}`);
  }
  return d;
}

/** Parses `shroud.json` text. `null` yields the parameterless defaults, like the C# Load. */
export function parseConfig(json: string): ShroudConfig {
  const root = JSON.parse(json) as Json;
  if (root === null) return createConfig();
  if (!isObject(root)) throw new ConfigFormatError('$', 'expected an object');
  const config = createConfig();
  for (const [key, value] of Object.entries(root)) {
    switch (key) {
      case 'domains':
        config.domains = readDomains(value, '$.domains');
        break;
      case 'threshold':
        config.threshold = readNumber(value, '$.threshold');
        break;
      case 'keyFile':
        config.keyFile = readNullableString(value, '$.keyFile');
        break;
      case 'preset':
        config.preset = readNullableString(value, '$.preset');
        break;
    }
  }
  return config;
}

export function loadConfig(path: string): ShroudConfig {
  return parseConfig(readAllText(path));
}

/** Serializes exactly like the C# `ShroudConfig.Save` (indented, camelCase, nulls omitted). */
export function serializeConfig(config: ShroudConfig, newline?: string): string {
  const t = (x: DomainToggle | null) => (x === null ? null : { enabled: x.enabled, layer: x.layer });
  const d = config.domains;
  return serializeIndented({
    domains:
      d === null
        ? null
        : {
            onChain: t(d.onChain),
            financial: t(d.financial),
            identity: t(d.identity),
            credentials: t(d.credentials),
            secrets: t(d.secrets),
          },
    threshold: config.threshold,
    keyFile: config.keyFile ?? null,
    preset: config.preset ?? null,
  }, newline);
}

export function saveConfig(config: ShroudConfig, path: string): void {
  writeAllText(path, serializeConfig(config));
}
