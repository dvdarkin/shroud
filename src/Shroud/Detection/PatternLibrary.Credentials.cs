// ============================================================================
// PatternLibrary.Credentials.cs -- Credentials Domain Patterns
// ============================================================================
//
// Covers: Service-specific API keys and access tokens -- AWS, GitHub, GitLab,
// Slack, Google, OpenAI, Anthropic, Stripe, SendGrid, Twilio, Telegram,
// Discord, Shopify, npm, PyPI, NuGet, Cloudflare, Heroku.  Also includes
// BIP32 extended keys (xprv/xpub/tprv/tpub) which are hierarchical
// deterministic wallet secrets.
//
// Confidence calibration:
//   High (>= 0.90) -- Tokens with unique structural prefixes (ghp_, sk-ant-,
//                       AKIA, AIza, etc.).  Nearly zero false positives.
//   Medium (0.70)   -- Patterns needing light context (Twilio SK*, NuGet oy2*).
//   Low   (<= 0.35) -- Generic shapes that only fire with strong context
//                       (Cloudflare 37-char alphanumeric, Heroku UUID).
//
// To add a new pattern:
//   1. Use EntityType.ApiKey for keys, EntityType.AccessToken for tokens,
//      EntityType.WebhookSecret for webhook secrets.
//   2. Domain is SensitivityDomain.Credentials (or OnChain for crypto keys).
//   3. Start with HighConfidence if the prefix is globally unique.
//   4. Give the pattern a unique Service string for diagnostics.
//   5. Add integration tests covering match and non-match cases.
// ============================================================================

using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

public static partial class PatternLibrary
{
    internal static IReadOnlyList<SensitivityPattern> GetCredentialPatterns() =>
    [
        // ================================================================
        // CREDENTIALS DOMAIN (service-specific keys and tokens)
        // Patterns sourced from Gitleaks (MIT), credited per-pattern.
        // ================================================================

        // --- AWS ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}", Opts),
            0.95, [], 0, "aws_access_key"),

        // --- GitHub (5 token types) ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bghp_[0-9a-zA-Z]{36}\b", Opts),
            0.95, [], 0, "github_pat"),
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bgho_[0-9a-zA-Z]{36}\b", Opts),
            0.95, [], 0, "github_oauth"),
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bghu_[0-9a-zA-Z]{36}\b", Opts),
            0.95, [], 0, "github_user"),
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bghs_[0-9a-zA-Z]{36}\b", Opts),
            0.95, [], 0, "github_app"),
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bgithub_pat_\w{82}\b", Opts),
            0.95, [], 0, "github_fine_grained"),

        // --- GitLab ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bglpat-[A-Za-z0-9\-_]{20}\b", Opts),
            0.95, [], 0, "gitlab_pat"),

        // --- Slack ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b", Opts),
            0.95, [], 0, "slack_bot"),
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b", Opts),
            0.95, [], 0, "slack_user"),
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bxoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b", Opts),
            0.95, [], 0, "slack_app"),

        // --- Google ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\bAIza[0-9A-Za-z\-_]{35}\b", Opts),
            0.95, [], 0, "google_api_key"),

        // --- OpenAI ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", Opts),
            0.95, [], 0, "openai_key"),

        // --- Anthropic ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\bsk-ant-api03-[a-zA-Z0-9_\-]{90,}\b", Opts),
            0.95, [], 0, "anthropic_key"),

        // --- Stripe ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\b[sr]k_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b", Opts),
            0.95, [], 0, "stripe_key"),
        new(EntityType.WebhookSecret, SensitivityDomain.Credentials,
            new Regex(@"\bwhsec_[A-Za-z0-9]{24,}\b", Opts),
            0.95, [], 0, "stripe_webhook"),

        // --- SendGrid ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b", Opts),
            0.95, [], 0, "sendgrid_key"),

        // --- Twilio ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\bSK[a-f0-9]{32}\b", Opts),
            0.90, ["twilio"], 0.05, "twilio_key"),

        // --- Telegram Bot ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b", Opts),
            0.90, [], 0, "telegram_bot"),

        // --- Discord Bot ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b", Opts),
            0.90, [], 0, "discord_bot"),

        // --- Shopify ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bshpat_[0-9a-fA-F]{32}\b", Opts),
            0.95, [], 0, "shopify_access"),

        // --- npm ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bnpm_[A-Za-z0-9]{36}\b", Opts),
            0.95, [], 0, "npm_token"),

        // --- PyPI ---
        new(EntityType.AccessToken, SensitivityDomain.Credentials,
            new Regex(@"\bpypi-[A-Za-z0-9]{36,}\b", Opts),
            0.95, [], 0, "pypi_token"),

        // --- NuGet ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\boy2[a-z0-9]{43}\b", Opts),
            0.90, ["nuget"], 0.05, "nuget_key"),

        // --- Cloudflare ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\b[A-Za-z0-9_-]{37}\b", Opts),
            0.20, ["cloudflare", "cf_api", "x-auth-key"], 0.70, "cloudflare_key"),

        // --- Heroku ---
        new(EntityType.ApiKey, SensitivityDomain.Credentials,
            new Regex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", Opts),
            0.20, ["heroku", "HEROKU_API_KEY"], 0.70, "heroku_key"),

        // --- xprv / xpub (extended keys -- moved from old ApiKey pattern) ---
        new(EntityType.ApiKey, SensitivityDomain.OnChain,
            new Regex(@"\b[xt](?:prv|pub)[a-zA-Z0-9]{100,}\b", Opts),
            0.95, [], 0, "bip32_extended_key")
    ];
}
