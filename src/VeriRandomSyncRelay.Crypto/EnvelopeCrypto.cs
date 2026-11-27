using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace VeriRandomSyncRelay.Crypto;

/// <summary>
/// End-to-end payload protection:
///   quick QR: 32 random bytes -> HKDF-SHA256 -> encKey (16) + macKey (32)
///   session:  Argon2id(password, salt) -> 32-byte payload key -> HKDF-SHA256
///   payload:  AES-128-CTR + HMAC-SHA256 (encrypt-then-MAC)
///
/// The relay server only stores the envelope and can never decrypt it.
/// </summary>
public static class EnvelopeCrypto
{
    public const int MasterKeySize = 32;
    public const int EncKeySize = 16;
    public const int MacKeySize = 32;
    public const int MacSize = 32;
    public const int MaxCiphertextBytes = 64 * 1024 * 1024;

    private static readonly byte[] EncInfo = Encoding.UTF8.GetBytes("verirandom-sync/v3/enc");
    private static readonly byte[] MacInfo = Encoding.UTF8.GetBytes("verirandom-sync/v3/mac");
    private static readonly byte[] RawKeyMode = Encoding.UTF8.GetBytes("raw");

    public static byte[] CreateMasterKey() => RandomNumberGenerator.GetBytes(MasterKeySize);

    /// <summary>Quick-QR path: the caller supplies the random payload key.</summary>
    public static Task<TransferEnvelope> EncryptAsync(
        byte[] plaintext,
        byte[] masterKey,
        string contentType,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(masterKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);
        if (masterKey.Length != MasterKeySize)
            throw new CryptoException($"Master key must be {MasterKeySize} bytes.");
        if (plaintext.Length > MaxCiphertextBytes)
            throw new CryptoException("Plaintext is too large.");
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(EncryptCore(plaintext, masterKey, contentType, null, null));
    }

    /// <summary>
    /// Session-code path: the payload key is derived directly from the user
    /// password. No wrapped key is uploaded; only the Argon2id salt and
    /// parameters travel with the envelope. <paramref name="context"/> should
    /// be the session-code hash so a malicious relay cannot swap envelopes
    /// between two transfers that reuse the same password.
    /// </summary>
    public static async Task<TransferEnvelope> EncryptWithPasswordAsync(
        byte[] plaintext,
        string password,
        string contentType,
        Argon2Parameters? parameters = null,
        byte[]? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);
        if (string.IsNullOrEmpty(password))
            throw new CryptoException("Password must not be empty.");
        if (plaintext.Length > MaxCiphertextBytes)
            throw new CryptoException("Plaintext is too large.");

        parameters ??= Argon2Parameters.Default;
        parameters.Validate();
        var kdf = new PasswordKdfEnvelope
        {
            Kdf = PasswordKdfEnvelope.CurrentKdf,
            Salt = Base64Url.Encode(RandomNumberGenerator.GetBytes(16)),
            MemoryKib = parameters.MemoryKib,
            Iterations = parameters.Iterations,
            Parallelism = parameters.Parallelism
        };
        var masterKey = await DeriveMasterKeyAsync(password, kdf, cancellationToken).ConfigureAwait(false);
        try
        {
            return EncryptCore(plaintext, masterKey, contentType, kdf, context);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    /// <summary>Decrypts a quick-QR envelope whose payload key arrived in the URL fragment.</summary>
    public static byte[] Decrypt(TransferEnvelope envelope, byte[] masterKey)
    {
        ValidateEnvelope(envelope);
        if (envelope.PasswordKdf is not null)
            throw new CryptoException("This envelope requires a password.");
        if (masterKey.Length != MasterKeySize)
            throw new CryptoException($"Master key must be {MasterKeySize} bytes.");
        return DecryptCore(envelope, masterKey, null);
    }

    /// <summary>Derives the payload key directly from the password, then decrypts.</summary>
    public static async Task<byte[]> DecryptWithPasswordAsync(
        TransferEnvelope envelope,
        string password,
        byte[]? context = null,
        CancellationToken cancellationToken = default)
    {
        ValidateEnvelope(envelope);
        if (envelope.PasswordKdf is null)
            throw new CryptoException("This envelope was not created with a password.");
        if (string.IsNullOrEmpty(password))
            throw new CryptoException("Password must not be empty.");

        var masterKey = await DeriveMasterKeyAsync(password, envelope.PasswordKdf, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return DecryptCore(envelope, masterKey, context);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    /// <summary>
    /// Relay-side validation. It never decrypts, but it rejects malformed envelopes
    /// and abusive Argon2 parameters before they can reach a receiving device.
    /// </summary>
    public static bool TryValidateWireEnvelope(
        TransferEnvelope envelope,
        string expectedContentType,
        bool requirePasswordKdf,
        out int ciphertextLength,
        out byte[] ciphertextSha256,
        out string error)
    {
        ciphertextLength = 0;
        ciphertextSha256 = [];
        error = string.Empty;
        try
        {
            ValidateEnvelope(envelope);
            if (!string.Equals(envelope.ContentType, expectedContentType, StringComparison.Ordinal))
                throw new CryptoException("Envelope content type does not match the transfer.");
            if (requirePasswordKdf != (envelope.PasswordKdf is not null))
                throw new CryptoException("Envelope password KDF presence does not match the transfer mode.");

            var ciphertext = Base64Url.Decode(envelope.Ciphertext);
            if (ciphertext.Length > MaxCiphertextBytes)
                throw new CryptoException("Ciphertext is too large.");
            if (envelope.PasswordKdf is not null)
                ValidateKdf(envelope.PasswordKdf);

            ciphertextLength = ciphertext.Length;
            ciphertextSha256 = SHA256.HashData(ciphertext);
            return true;
        }
        catch (CryptoException ex)
        {
            error = ex.Message;
            return false;
        }
        catch (FormatException)
        {
            error = "Envelope contains invalid Base64Url data.";
            return false;
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static void ValidateEnvelope(TransferEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (!string.Equals(envelope.Format, TransferEnvelope.CurrentFormat, StringComparison.Ordinal))
            throw new CryptoException("Unsupported envelope format.");
        if (!string.Equals(envelope.Cipher, TransferEnvelope.CurrentCipher, StringComparison.Ordinal))
            throw new CryptoException("Unsupported envelope cipher.");
        if (string.IsNullOrWhiteSpace(envelope.ContentType))
            throw new CryptoException("Envelope content type is required.");
        Base64Url.DecodeExact(envelope.Iv, AesCtr.IvSize, "IV");
        Base64Url.DecodeExact(envelope.Mac, MacSize, "MAC");
        if (envelope.Ciphertext.Length > 0)
            Base64Url.Decode(envelope.Ciphertext);
        if (envelope.PasswordKdf is not null)
            ValidateKdf(envelope.PasswordKdf);
    }

    public static void ValidateKdf(PasswordKdfEnvelope kdf)
    {
        ArgumentNullException.ThrowIfNull(kdf);
        if (!string.Equals(kdf.Kdf, PasswordKdfEnvelope.CurrentKdf, StringComparison.Ordinal))
            throw new CryptoException("Unsupported password KDF.");
        new Argon2Parameters(kdf.MemoryKib, kdf.Iterations, kdf.Parallelism).Validate();
        Base64Url.DecodeExact(kdf.Salt, 16, "Argon2id salt");
    }

    private static TransferEnvelope EncryptCore(
        byte[] plaintext,
        byte[] masterKey,
        string contentType,
        PasswordKdfEnvelope? kdf,
        byte[]? context)
    {
        if (kdf is not null)
            ValidateKdf(kdf);

        var (encKey, macKey) = DerivePayloadKeys(masterKey);
        try
        {
            var iv = RandomNumberGenerator.GetBytes(AesCtr.IvSize);
            var ciphertext = AesCtr.Transform(plaintext, encKey, iv);
            var mac = ComputeMac(macKey, contentType, iv, ciphertext, kdf, context);
            return new TransferEnvelope
            {
                Format = TransferEnvelope.CurrentFormat,
                Cipher = TransferEnvelope.CurrentCipher,
                ContentType = contentType,
                Iv = Base64Url.Encode(iv),
                Mac = Base64Url.Encode(mac),
                Ciphertext = Base64Url.Encode(ciphertext),
                PasswordKdf = kdf
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    private static byte[] DecryptCore(TransferEnvelope envelope, byte[] masterKey, byte[]? context)
    {
        var iv = Base64Url.DecodeExact(envelope.Iv, AesCtr.IvSize, "IV");
        var mac = Base64Url.DecodeExact(envelope.Mac, MacSize, "MAC");
        var ciphertext = envelope.Ciphertext.Length == 0 ? [] : Base64Url.Decode(envelope.Ciphertext);
        if (ciphertext.Length > MaxCiphertextBytes)
            throw new CryptoException("Ciphertext is too large.");

        var (encKey, macKey) = DerivePayloadKeys(masterKey);
        try
        {
            var expectedMac = ComputeMac(macKey, envelope.ContentType, iv, ciphertext, envelope.PasswordKdf,
                context);
            if (!CryptographicOperations.FixedTimeEquals(expectedMac, mac))
                throw new CryptoException("Envelope authentication failed. Wrong password or corrupted payload.");
            return AesCtr.Transform(ciphertext, encKey, iv);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    private static (byte[] EncKey, byte[] MacKey) DerivePayloadKeys(byte[] masterKey)
    {
        var encKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, EncKeySize, null, EncInfo);
        var macKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, MacKeySize, null, MacInfo);
        return (encKey, macKey);
    }

    private static async Task<byte[]> DeriveMasterKeyAsync(
        string password,
        PasswordKdfEnvelope kdf,
        CancellationToken cancellationToken)
    {
        ValidateKdf(kdf);
        var salt = Base64Url.DecodeExact(kdf.Salt, 16, "Argon2id salt");
        var parameters = new Argon2Parameters(kdf.MemoryKib, kdf.Iterations, kdf.Parallelism);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = parameters.MemoryKib,
                Iterations = parameters.Iterations,
                DegreeOfParallelism = parameters.Parallelism
            };
            var key = await argon2.GetBytesAsync(MasterKeySize).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] ComputeMac(
        byte[] macKey,
        string contentType,
        byte[] iv,
        byte[] ciphertext,
        PasswordKdfEnvelope? kdf,
        byte[]? context)
    {
        using var buffer = new MemoryStream();
        WriteString(buffer, TransferEnvelope.CurrentFormat);
        WriteString(buffer, TransferEnvelope.CurrentCipher);
        WriteString(buffer, contentType);

        if (kdf is null)
        {
            WriteBytes(buffer, RawKeyMode);
        }
        else
        {
            WriteString(buffer, kdf.Kdf);
            WriteBytes(buffer, Base64Url.DecodeExact(kdf.Salt, 16, "Argon2id salt"));
            WriteInt32(buffer, kdf.MemoryKib);
            WriteInt32(buffer, kdf.Iterations);
            WriteInt32(buffer, kdf.Parallelism);
        }

        WriteBytes(buffer, iv);
        WriteBytes(buffer, context ?? []);
        WriteInt32(buffer, ciphertext.Length);
        buffer.Write(ciphertext);
        return HMACSHA256.HashData(macKey, buffer.ToArray());
    }

    private static void WriteString(Stream stream, string value) =>
        WriteBytes(stream, Encoding.UTF8.GetBytes(value));

    private static void WriteBytes(Stream stream, byte[] value)
    {
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }
}
