/**
 * @logmark/shroud - sensitive data detection and tokenization for text files.
 *
 * TypeScript port of Shroud 0.3.1 (C#/.NET 8). Detection results, masked output,
 * manifests and encrypted vaults are interchangeable with the C# build; see docs/format.md.
 */
export {
  ENTITY_TYPES,
  SENSITIVITY_DOMAINS,
  type EntityType,
  type SensitivityDomain,
  type SensitiveSpan,
  type ScanResult,
  type SensitivityPattern,
  spanLength,
  typeAbbreviation,
  isStructural,
} from './models.js';

export {
  type ShroudConfig,
  type DomainConfig,
  type DomainToggle,
  ConfigFormatError,
  createConfig,
  defaultConfig,
  configForPreset,
  parseConfig,
  loadConfig,
  serializeConfig,
  saveConfig,
} from './config.js';

export {
  HIGH_CONFIDENCE,
  MEDIUM_CONFIDENCE,
  LOW_CONFIDENCE,
  KNOWN_ASSETS,
  TRADING_CONTEXT,
  PRICE_CONTEXT,
  AMOUNT_CONTEXT,
  isKnownAsset,
  getAllPatterns,
  getPatternsForConfig,
  getOnChainPatterns,
  getCredentialPatterns,
  getSecretPatterns,
  getFinancialPatterns,
  getIdentityPatterns,
} from './pattern-library.js';

export {
  CONTEXT_WINDOW_CHARS,
  ADDITIONAL_CONTEXT_WORD_BOOST,
  MAX_ADDITIONAL_CONTEXT_WORDS,
  ASSET_NAME_BOOST,
  CURRENCY_SIGNAL_BOOST,
  type ScoringDetail,
  score,
  scoreWithDetail,
} from './context-scorer.js';

export { isValidLuhn } from './luhn.js';

export {
  SensitivityScanner,
  type ScanDiagnostics,
  type SpanDiagnostic,
  type OverlapResolution,
  type ExclusionZone,
} from './scanner.js';

export { SpanMasker, generateTokenId, type MaskResult, type TokenMapping } from './masker.js';

export {
  SALT_LENGTH,
  NONCE_LENGTH,
  TAG_LENGTH,
  KEY_LENGTH,
  PBKDF2_ITERATIONS,
  deriveKey,
  encrypt,
  decrypt,
  encryptString,
  decryptString,
} from './vault-encryption.js';

export {
  VaultBuilder,
  VaultFormatError,
  TokenCollisionException,
  parseVaultData,
  serializeVaultData,
  serializeManifest,
  type VaultResult,
  type VaultData,
  type MaskedFile,
  type TokenEntry,
  type ManifestFile,
  type ManifestToken,
} from './vault-builder.js';

export { dotnetRegex, type DotnetRegexOptions, UnsupportedRegexError } from './internal/dotnet-regex.js';
