using System.Security.Cryptography;
using System.Text;

namespace Shroud.Vault;

/// <summary>
/// Password-based encryption using PBKDF2-SHA512 (600k iterations, OWASP 2023+) for key derivation
/// and AES-256-GCM for authenticated encryption. Wire format: salt(16) | nonce(12) | tag(16) |
/// ciphertext(N). All primitives are from .NET 8 BCL — no native or external dependencies. Wrong
/// password is cleanly rejected via GCM tag verification (returns null, no partial decryption).
/// </summary>
public static class VaultEncryption
{
    private const int SaltLength = 16;
    private const int NonceLength = 12; // AES-GCM standard
    private const int TagLength = 16;   // AES-GCM standard
    private const int KeyLength = 32;   // AES-256

    /// <summary>
    /// Encrypt plaintext bytes with a password.
    /// Output format: salt(16) + nonce(12) + tag(16) + ciphertext(N)
    /// </summary>
    public static byte[] Encrypt(byte[] plaintext, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var key = DeriveKey(password, salt);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Pack: salt + nonce + tag + ciphertext
        var result = new byte[SaltLength + NonceLength + TagLength + ciphertext.Length];
        salt.CopyTo(result, 0);
        nonce.CopyTo(result, SaltLength);
        tag.CopyTo(result, SaltLength + NonceLength);
        ciphertext.CopyTo(result, SaltLength + NonceLength + TagLength);

        return result;
    }

    /// <summary>
    /// Decrypt a vault file produced by Encrypt. Returns null if password is wrong.
    /// </summary>
    public static byte[]? Decrypt(byte[] packed, string password)
    {
        if (packed.Length < SaltLength + NonceLength + TagLength)
            return null;

        var salt = packed[..SaltLength];
        var nonce = packed[SaltLength..(SaltLength + NonceLength)];
        var tag = packed[(SaltLength + NonceLength)..(SaltLength + NonceLength + TagLength)];
        var ciphertext = packed[(SaltLength + NonceLength + TagLength)..];

        var key = DeriveKey(password, salt);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
        catch (CryptographicException)
        {
            return null; // Wrong password
        }
    }

    public static byte[] EncryptString(string text, string password) =>
        Encrypt(Encoding.UTF8.GetBytes(text), password);

    public static string? DecryptString(byte[] packed, string password)
    {
        var bytes = Decrypt(packed, password);
        return bytes is null ? null : Encoding.UTF8.GetString(bytes);
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        // Use PBKDF2 with SHA-512 -- available cross-platform in .NET 8
        // Argon2id would be ideal but requires external deps.
        // 600,000 iterations of PBKDF2-SHA512 is OWASP-recommended (2023+).
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            600_000,
            HashAlgorithmName.SHA512,
            KeyLength);
    }
}
