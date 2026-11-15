namespace Shroud.Vault;

/// <summary>
/// Thrown by <see cref="VaultBuilder.Build"/> when two different original values produce the same
/// token id (4-byte HMAC prefix). Continuing would map both values to one token and reveal would
/// restore the wrong text. The message names the token id only, never an original value.
/// </summary>
public class TokenCollisionException : Exception
{
    public string TokenId { get; }

    public TokenCollisionException(string tokenId)
        : base($"Token id collision: two different values both map to [{tokenId}]. " +
               "Nothing was written. Run the vault again (a new masking key is generated each run).")
    {
        TokenId = tokenId;
    }
}
