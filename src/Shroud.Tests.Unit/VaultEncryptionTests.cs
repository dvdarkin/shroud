using FluentAssertions;
using Shroud.Vault;
using Xunit;

namespace Shroud.Tests.Unit;

public class VaultEncryptionTests
{
    private const string Password = "test-password-123";
    private const string AltPassword = "different-password-456";

    [Fact]
    public void RoundTrip_Bytes_ReturnsOriginal()
    {
        var plaintext = "Hello, Shroud!"u8.ToArray();
        var encrypted = VaultEncryption.Encrypt(plaintext, Password);
        var decrypted = VaultEncryption.Decrypt(encrypted, Password);

        decrypted.Should().NotBeNull();
        decrypted.Should().BeEquivalentTo(plaintext);
    }

    [Fact]
    public void RoundTrip_String_ReturnsOriginal()
    {
        var text = "Sensitive data: 0x1234567890abcdef";
        var encrypted = VaultEncryption.EncryptString(text, Password);
        var decrypted = VaultEncryption.DecryptString(encrypted, Password);

        decrypted.Should().Be(text);
    }

    [Fact]
    public void WrongPassword_ReturnsNull()
    {
        var plaintext = "secret"u8.ToArray();
        var encrypted = VaultEncryption.Encrypt(plaintext, Password);
        var decrypted = VaultEncryption.Decrypt(encrypted, AltPassword);

        decrypted.Should().BeNull();
    }

    [Fact]
    public void WrongPassword_String_ReturnsNull()
    {
        var encrypted = VaultEncryption.EncryptString("secret", Password);
        var decrypted = VaultEncryption.DecryptString(encrypted, AltPassword);

        decrypted.Should().BeNull();
    }

    [Fact]
    public void TruncatedData_ReturnsNull()
    {
        var plaintext = "secret"u8.ToArray();
        var encrypted = VaultEncryption.Encrypt(plaintext, Password);

        // Truncate to less than salt(16) + nonce(12) + tag(16) = 44 bytes
        var truncated = encrypted[..30];
        var decrypted = VaultEncryption.Decrypt(truncated, Password);

        decrypted.Should().BeNull();
    }

    [Fact]
    public void CorruptedCiphertext_ReturnsNull()
    {
        var plaintext = "secret"u8.ToArray();
        var encrypted = VaultEncryption.Encrypt(plaintext, Password);

        // Corrupt a byte in the ciphertext region (after salt+nonce+tag = 44 bytes)
        if (encrypted.Length > 45)
            encrypted[45] ^= 0xFF;

        var decrypted = VaultEncryption.Decrypt(encrypted, Password);
        decrypted.Should().BeNull();
    }

    [Fact]
    public void EmptyPlaintext_RoundTrips()
    {
        var plaintext = Array.Empty<byte>();
        var encrypted = VaultEncryption.Encrypt(plaintext, Password);
        var decrypted = VaultEncryption.Decrypt(encrypted, Password);

        decrypted.Should().NotBeNull();
        decrypted.Should().BeEmpty();
    }

    [Fact]
    public void DifferentPasswords_ProduceDifferentCiphertext()
    {
        var plaintext = "same data"u8.ToArray();
        var encrypted1 = VaultEncryption.Encrypt(plaintext, Password);
        var encrypted2 = VaultEncryption.Encrypt(plaintext, AltPassword);

        encrypted1.Should().NotBeEquivalentTo(encrypted2);
    }

    [Fact]
    public void SamePasswordSamePlaintext_ProducesDifferentCiphertext()
    {
        var plaintext = "same data"u8.ToArray();
        var encrypted1 = VaultEncryption.Encrypt(plaintext, Password);
        var encrypted2 = VaultEncryption.Encrypt(plaintext, Password);

        encrypted1.Should().NotBeEquivalentTo(encrypted2,
            "random salt and nonce should produce different ciphertext");
    }

    [Fact]
    public void EncryptedOutput_HasExpectedMinimumSize()
    {
        var plaintext = "test"u8.ToArray();
        var encrypted = VaultEncryption.Encrypt(plaintext, Password);

        encrypted.Length.Should().Be(16 + 12 + 16 + plaintext.Length);
    }
}
