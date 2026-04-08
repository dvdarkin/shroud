namespace Shroud.Models;

/// <summary>
/// The two fundamentally different sensitivity domains.
/// OnChain: atomic (each match independently compromising).
/// Financial: compositional (sensitivity depends on combination).
/// </summary>
public enum SensitivityDomain
{
    OnChain,
    Financial,
    Identity,
    Credentials,
    Secrets
}
