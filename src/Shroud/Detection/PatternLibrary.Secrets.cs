// ============================================================================
// PatternLibrary.Secrets.cs -- Secrets Domain Patterns
// ============================================================================
//
// Covers: Structural secrets that are not service-specific -- PEM private
// keys, JWT tokens, database connection strings (MongoDB, PostgreSQL, MySQL,
// Redis, SQL Server), and generic password/secret/login assignments in
// configuration or code.
//
// Confidence calibration:
//   High (>= 0.90) -- PEM headers, JWT three-part base64, database URIs with
//                       embedded credentials.  Virtually no false positives.
//   Medium (0.70)   -- Login assignments (username=...) which can appear in
//                       non-sensitive contexts.
//   Low   (<= 0.35) -- Not currently used in this domain.
//
// To add a new pattern:
//   1. Use the appropriate EntityType (PrivateKey, Jwt, ConnectionString,
//      PasswordInContext).
//   2. Domain is SensitivityDomain.Secrets.
//   3. Prefer structural patterns (unique headers/formats) over generic ones.
//   4. Give the pattern a unique Service string for diagnostics.
//   5. Add integration tests covering match and non-match cases.
// ============================================================================

using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

public static partial class PatternLibrary
{
    internal static IReadOnlyList<SensitivityPattern> GetSecretPatterns() =>
    [
        // ================================================================
        // SECRETS DOMAIN (structural secrets, not service-specific)
        // ================================================================

        // --- PEM private keys ---
        new(EntityType.PrivateKey, SensitivityDomain.Secrets,
            new Regex(@"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?:\sBLOCK)?-----", Opts),
            0.95, [], 0, "pem_private_key"),

        // --- JWT tokens (always start with eyJ because base64 of {"...) ---
        new(EntityType.Jwt, SensitivityDomain.Secrets,
            new Regex(@"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b", Opts),
            0.90, [], 0, "jwt"),

        // --- Connection strings with passwords ---
        new(EntityType.ConnectionString, SensitivityDomain.Secrets,
            new Regex(@"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:]+:[^@\s]+@[^\s]+", Opts),
            0.90, [], 0, "database_uri"),
        new(EntityType.ConnectionString, SensitivityDomain.Secrets,
            new Regex(@"(?i)(?:Server|Data\sSource)=[^;]+;.*?(?:Password|Pwd)=[^;\s]+", Opts),
            0.90, [], 0, "sql_connection_string"),

        // --- Generic password/secret in context ---
        new(EntityType.PasswordInContext, SensitivityDomain.Secrets,
            new Regex(@"(?i)(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[=:]\s*['""][^'""]{4,}['""]", Opts),
            0.85, [], 0, "password_assignment"),
        new(EntityType.PasswordInContext, SensitivityDomain.Secrets,
            new Regex(@"(?i)(?:login|username|user)\s*[=:]\s*['""][^'""]{2,}['""]", Opts),
            0.70, [], 0, "login_assignment")
    ];
}
