namespace VeriRandomSyncRelay.Server;

public sealed class TransferRecord
{
    public required string Id { get; init; }
    public required byte[] UploadTokenHash { get; init; }
    public required string Mode { get; init; }
    public required string ContentType { get; init; }
    public required long PayloadLength { get; init; }
    public required byte[] PayloadSha256 { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required int MaxDownloads { get; init; }
    public string? SessionCodeHash { get; init; }

    public int Downloads { get; set; }
    public byte[]? EnvelopeBytes { get; set; }

    /// <summary>All mutations of one record are serialized by this gate.</summary>
    public object Gate { get; } = new();
}
