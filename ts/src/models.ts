/**
 * Core data model. Entity types and domains are string unions whose values are the
 * C# enum member names, so `String(entityType)` matches .NET `EntityType.ToString()`
 * in CLI output, manifests and vault metadata.
 */

export const ENTITY_TYPES = [
  // On-chain domain (atomic)
  'CryptoAddr',
  'TxHash',
  'ValidatorKey',
  'EnsName',
  'SeedPhrase',
  // Credentials domain (service-specific API keys and tokens)
  'ApiKey',
  'AccessToken',
  'WebhookSecret',
  // Secrets domain (structural secrets)
  'PrivateKey',
  'Jwt',
  'ConnectionString',
  'PasswordInContext',
  // Financial domain (compositional)
  'Quantity',
  'Amount',
  'Price',
  'MarketPair',
  'AssetName',
  'CreditCard',
  // Identity domain
  'Ssn',
  'Iban',
  'IpAddress',
  'MacAddress',
  'Email',
  'PhoneNumber',
] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];

/**
 * Sensitivity domains. OnChain is atomic (each match independently compromising);
 * Financial is compositional (sensitivity depends on combination).
 */
export const SENSITIVITY_DOMAINS = ['OnChain', 'Financial', 'Identity', 'Credentials', 'Secrets'] as const;

export type SensitivityDomain = (typeof SENSITIVITY_DOMAINS)[number];

/** A detected span. Offsets are UTF-16 code units, `end` exclusive. */
export interface SensitiveSpan {
  readonly start: number;
  readonly end: number;
  readonly entityType: EntityType;
  readonly domain: SensitivityDomain;
  readonly confidence: number;
  readonly matchedText: string;
  /** Pattern identifier (for example "evm_address"); empty when unknown. */
  readonly service: string;
}

export function spanLength(span: SensitiveSpan): number {
  return span.end - span.start;
}

const ABBREVIATIONS: Readonly<Record<EntityType, string>> = {
  // On-chain
  CryptoAddr: 'ADDR',
  TxHash: 'TX',
  ValidatorKey: 'VKEY',
  EnsName: 'ENS',
  SeedPhrase: 'SEED',
  // Credentials
  ApiKey: 'KEY',
  AccessToken: 'TOKEN',
  WebhookSecret: 'WHSEC',
  // Secrets
  PrivateKey: 'PRIVKEY',
  Jwt: 'JWT',
  ConnectionString: 'CONNSTR',
  PasswordInContext: 'PASSWD',
  // Financial
  Quantity: 'QTY',
  Amount: 'AMT',
  Price: 'PRICE',
  MarketPair: 'MKT',
  AssetName: 'ASSET',
  CreditCard: 'CC',
  // Identity
  Ssn: 'SSN',
  Iban: 'IBAN',
  IpAddress: 'IP',
  MacAddress: 'MAC',
  Email: 'EMAIL',
  PhoneNumber: 'PHONE',
};

/** The token prefix for an entity type, for example "ADDR" for CryptoAddr. */
export function typeAbbreviation(entityType: EntityType): string {
  return ABBREVIATIONS[entityType] ?? 'UNK';
}

export interface ScanResult {
  readonly allDetected: readonly SensitiveSpan[];
  readonly aboveThreshold: readonly SensitiveSpan[];
  readonly belowThreshold: readonly SensitiveSpan[];
  readonly threshold: number;
}

/**
 * A compiled detection rule. Structural patterns (base confidence >= 0.80 or no
 * context words) rely on format alone; contextual patterns start low and rely on
 * the context scorer finding keywords within 120 characters.
 */
export interface SensitivityPattern {
  readonly entityType: EntityType;
  readonly domain: SensitivityDomain;
  /**
   * The compiled matcher. Built-in patterns are .NET-syntax sources compiled with
   * `dotnetRegex`, which preserves .NET matching semantics. A plain JS RegExp is also
   * accepted (it is matched with a global copy of itself).
   */
  readonly regex: RegExp;
  readonly baseConfidence: number;
  readonly contextWords: readonly string[];
  readonly contextBoost: number;
  readonly service: string;
}

export function isStructural(pattern: SensitivityPattern): boolean {
  return pattern.contextWords.length === 0 || pattern.baseConfidence >= 0.8;
}
