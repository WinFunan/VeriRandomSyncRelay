namespace VeriRandomSyncRelay.Crypto;

/// <summary>
/// Unpadded Base64Url helpers. The relay uses these everywhere so ids, keys,
/// nonces and ciphertexts never contain characters that need URL escaping.
/// </summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }

    public static bool TryDecode(string? value, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(value))
            return false;
        try
        {
            bytes = Decode(value);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static byte[] DecodeExact(string? value, int expectedLength, string name)
    {
        if (!TryDecode(value, out var bytes))
            throw new CryptoException($"{name} is not valid Base64Url.");
        if (bytes.Length != expectedLength)
            throw new CryptoException($"{name} must be {expectedLength} bytes.");
        return bytes;
    }
}
