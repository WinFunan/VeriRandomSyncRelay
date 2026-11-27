namespace VeriRandomSyncRelay.Server;

public sealed class RelayOptions
{
    public const string SectionName = "Relay";

    /// <summary>Maximum ciphertext bytes accepted for one transfer. Default 1 MiB.</summary>
    public long MaxPayloadBytes { get; set; } = 1L * 1024 * 1024;

    /// <summary>Maximum JSON envelope bytes on the wire (Base64 overhead included).</summary>
    public long MaxEnvelopeBytes { get; set; } = 2L * 1024 * 1024;

    public int DefaultTtlSeconds { get; set; } = 600;
    public int MinTtlSeconds { get; set; } = 30;
    public int MaxTtlSeconds { get; set; } = 3600;
    public int DefaultMaxDownloads { get; set; } = 10;
    public int MaxDownloads { get; set; } = 100;

    /// <summary>Hard cap for all stored envelopes, so the in-memory relay cannot be exhausted.</summary>
    public long MaxTotalBytes { get; set; } = 256L * 1024 * 1024;

    public int MaxTransfers { get; set; } = 10_000;
    public int CleanupIntervalSeconds { get; set; } = 30;

    /// <summary>Set true behind TLS. Keep false for local HTTP development.</summary>
    public bool RequireHttps { get; set; }
}
