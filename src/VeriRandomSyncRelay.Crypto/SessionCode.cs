using System.Security.Cryptography;
using System.Text;

namespace VeriRandomSyncRelay.Crypto;

/// <summary>
/// Human-transcribable lookup code. It is deliberately only a lookup key for
/// the relay; the payload key is protected by a separate password.
/// </summary>
public static class SessionCode
{
    public const int Length = 12;
    public const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    public static string Create()
    {
        Span<char> chars = stackalloc char[Length];
        for (var i = 0; i < chars.Length; i++)
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        return new string(chars);
    }

    public static string Normalize(string? code) =>
        new((code ?? string.Empty).Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    public static bool IsValid(string? code)
    {
        var normalized = Normalize(code);
        return normalized.Length == Length && normalized.All(Alphabet.Contains);
    }

    /// <summary>Groups the code as XXXX-XXXX-XXXX for display only.</summary>
    public static string Format(string code)
    {
        var normalized = Normalize(code);
        if (normalized.Length != Length)
            return normalized;
        return string.Join('-', normalized.Chunk(4).Select(chunk => new string(chunk)));
    }

    public static string HashHex(string code)
    {
        var normalized = Normalize(code);
        if (!IsValid(normalized))
            throw new CryptoException("Session code must be 12 characters from the unambiguous alphabet.");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
    }

    public static string GeneratePassword(int bytes = 24) =>
        Base64Url.Encode(RandomNumberGenerator.GetBytes(bytes));
}
