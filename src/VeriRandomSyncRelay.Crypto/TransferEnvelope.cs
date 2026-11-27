using System.Text.Json.Serialization;

namespace VeriRandomSyncRelay.Crypto;

/// <summary>
/// The wire envelope. The relay stores this document verbatim; it never sees
/// a payload key or a password.
/// </summary>
public sealed class TransferEnvelope
{
    public const string CurrentFormat = "verirandom-sync-envelope/v3";
    public const string CurrentCipher = "aes-128-ctr-hmac-sha256";

    [JsonPropertyName("format")]
    public string Format { get; init; } = CurrentFormat;

    [JsonPropertyName("cipher")]
    public string Cipher { get; init; } = CurrentCipher;

    [JsonPropertyName("content_type")]
    public string ContentType { get; init; } = string.Empty;

    [JsonPropertyName("iv")]
    public string Iv { get; init; } = string.Empty;

    [JsonPropertyName("mac")]
    public string Mac { get; init; } = string.Empty;

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; init; } = string.Empty;

    /// <summary>
    /// Null for quick-QR transfers, where the key travels in the QR fragment.
    /// Present for session-code transfers, where the payload key is derived
    /// directly from the user password and this Argon2id salt.
    /// </summary>
    [JsonPropertyName("password_kdf")]
    public PasswordKdfEnvelope? PasswordKdf { get; init; }
}

/// <summary>
/// Argon2id parameters used to derive the payload key directly from the user
/// password. The salt is random per transfer and is not secret; the password
/// never leaves the sending or receiving device.
/// </summary>
public sealed class PasswordKdfEnvelope
{
    public const string CurrentKdf = "argon2id";

    [JsonPropertyName("kdf")]
    public string Kdf { get; init; } = CurrentKdf;

    [JsonPropertyName("salt")]
    public string Salt { get; init; } = string.Empty;

    [JsonPropertyName("memory_kib")]
    public int MemoryKib { get; init; }

    [JsonPropertyName("iterations")]
    public int Iterations { get; init; }

    [JsonPropertyName("parallelism")]
    public int Parallelism { get; init; }
}
