using System.Security.Cryptography;

namespace VeriRandomSyncRelay.Crypto;

/// <summary>
/// AES-128 in counter mode. .NET has no built-in CTR mode, so this uses AES-ECB
/// to encrypt the counter blocks and XORs the keystream with the input.
/// The counter is a full 128-bit big-endian integer starting at the IV.
/// CTR provides confidentiality only; callers must authenticate the result
/// (this project uses HMAC-SHA256, encrypt-then-MAC).
/// </summary>
public static class AesCtr
{
    public const int BlockSize = 16;
    public const int KeySize = 16;
    public const int IvSize = 16;

    public static byte[] Transform(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != KeySize)
            throw new CryptoException("AES-128-CTR requires a 16-byte key.");
        if (iv.Length != IvSize)
            throw new CryptoException("AES-128-CTR requires a 16-byte IV.");

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        var output = new byte[input.Length];
        var counter = iv.ToArray();
        Span<byte> keystream = stackalloc byte[BlockSize];
        var offset = 0;
        while (offset < input.Length)
        {
            aes.EncryptEcb(counter, keystream, PaddingMode.None);
            var block = Math.Min(BlockSize, input.Length - offset);
            for (var i = 0; i < block; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
            offset += block;
            IncrementCounter(counter);
        }

        CryptographicOperations.ZeroMemory(keystream);
        CryptographicOperations.ZeroMemory(counter);
        return output;
    }

    private static void IncrementCounter(Span<byte> counter)
    {
        for (var i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }
}
