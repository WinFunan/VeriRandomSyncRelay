namespace VeriRandomSyncRelay.Crypto;

/// <summary>
/// Argon2id parameters for password-based key derivation. The relay only stores
/// and validates these values; the KDF itself runs on the clients.
/// </summary>
public sealed record Argon2Parameters(int MemoryKib, int Iterations, int Parallelism)
{
    public const int MinMemoryKib = 8 * 1024;
    public const int MaxMemoryKib = 256 * 1024;
    public const int MinIterations = 1;
    public const int MaxIterations = 10;
    public const int MinParallelism = 1;
    public const int MaxParallelism = 8;

    /// <summary>64 MiB, 3 passes, 4 lanes. Tune down on low-end mobile devices.</summary>
    public static Argon2Parameters Default { get; } = new(64 * 1024, 3, 4);

    public void Validate()
    {
        if (MemoryKib is < MinMemoryKib or > MaxMemoryKib)
            throw new CryptoException($"Argon2id memory must be between {MinMemoryKib} and {MaxMemoryKib} KiB.");
        if (Iterations is < MinIterations or > MaxIterations)
            throw new CryptoException($"Argon2id iterations must be between {MinIterations} and {MaxIterations}.");
        if (Parallelism is < MinParallelism or > MaxParallelism)
            throw new CryptoException($"Argon2id parallelism must be between {MinParallelism} and {MaxParallelism}.");
    }
}
