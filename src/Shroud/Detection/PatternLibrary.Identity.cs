// ============================================================================
// PatternLibrary.Identity.cs -- Identity Domain Patterns
// ============================================================================
//
// Covers: US Social Security numbers (SSN), International Bank Account
// Numbers (IBAN), IPv4 addresses (with homelab/server context), UNC network
// paths and file:// URIs with IPs, MAC addresses (colon and dash formats),
// and email addresses.
//
// Confidence calibration:
//   High (>= 0.90) -- UNC paths and file:// URIs with embedded IPs.
//                       Structurally unique, near-zero false positives.
//   Medium (0.70-0.85) -- SSN (with exclusion ranges), MAC addresses, email.
//   Low   (<= 0.35) -- Not currently used; all identity patterns have
//                       moderate-to-high structural uniqueness.
//
// To add a new pattern:
//   1. Use the appropriate EntityType (Ssn, Iban, IpAddress, MacAddress,
//      Email, or create a new one if needed).
//   2. Domain is SensitivityDomain.Identity.
//   3. For patterns that overlap with non-PII data, add context words.
//   4. Give the pattern a unique Service string for diagnostics.
//   5. Add integration tests covering match and non-match cases.
// ============================================================================

using System.Text.RegularExpressions;
using Shroud.Models;

namespace Shroud.Detection;

public static partial class PatternLibrary
{
    internal static IReadOnlyList<SensitivityPattern> GetIdentityPatterns() =>
    [
        // ================================================================
        // IDENTITY DOMAIN
        // ================================================================

        new(EntityType.Ssn, SensitivityDomain.Identity,
            new Regex(@"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", Opts),
            0.70, ["ssn", "social", "security"], 0.20, "us_ssn"),

        new(EntityType.Iban, SensitivityDomain.Identity,
            new Regex(@"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b", Opts),
            0.60, ["iban", "bank", "transfer", "wire", "account"], 0.25, "iban"),

        new(EntityType.IpAddress, SensitivityDomain.Identity,
            new Regex(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", Opts),
            0.50, ["server", "host", "node", "rpc", "endpoint", "ssh", "vpn",
                    "TCP", "UDP", "port", "api", "gateway", "router", "NAS",
                    "docker", "container", "network", "lan", "dhcp", "dns",
                    "ipfs", "mqtt", "proxy", "firewall", "homelab"], 0.30, "ipv4"),

        // --- UNC paths / network shares with IPs: \\192.168.10.2\share ---
        new(EntityType.IpAddress, SensitivityDomain.Identity,
            new Regex(@"\\\\(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\\[^\s\)\]]+", Opts),
            0.90, [], 0, "unc_network_path"),
        // file:// URIs with IPs
        new(EntityType.IpAddress, SensitivityDomain.Identity,
            new Regex(@"file:///\\\\(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\\[^\s\)\]]+", Opts),
            0.90, [], 0, "file_uri_network_path"),

        // --- MAC addresses: device hardware fingerprint ---
        new(EntityType.MacAddress, SensitivityDomain.Identity,
            new Regex(@"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", Opts),
            0.85, [], 0, "mac_colon"),
        new(EntityType.MacAddress, SensitivityDomain.Identity,
            new Regex(@"\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b", Opts),
            0.85, [], 0, "mac_dash"),

        new(EntityType.Email, SensitivityDomain.Identity,
            new Regex(@"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", Opts),
            0.70, ["email", "contact", "mailto", "send"], 0.15, "email")
    ];
}
