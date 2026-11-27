using System.Text.Json;

namespace VeriRandomSyncRelay.Protocol;

public static class TransferModes
{
    public const string Quick = "quick";
    public const string Session = "session";

    public static bool IsValid(string? mode) => mode is Quick or Session;
}

public static class TransferContentTypes
{
    public const string Roster = "roster";
    public const string Settings = "settings";
    public const string AllData = "all-data";
    public const string TextLibrary = "text-library";

    public static bool IsValid(string? contentType) =>
        contentType is Roster or Settings or AllData or TextLibrary;
}

public sealed class CreateTransferRequest
{
    public string Mode { get; init; } = string.Empty;
    public string ContentType { get; init; } = string.Empty;
    public long PayloadLength { get; init; }
    public string PayloadSha256 { get; init; } = string.Empty;
    public string? SessionCodeHash { get; init; }
    public int? MaxDownloads { get; init; }
    public int? ExpiresInSeconds { get; init; }
}

public sealed class CreateTransferResponse
{
    public string Id { get; init; } = string.Empty;
    public string UploadToken { get; init; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; init; }
    public int MaxDownloads { get; init; }
}

public sealed class ResolveSessionRequest
{
    public string SessionCodeHash { get; init; } = string.Empty;
}

public sealed class ErrorResponse
{
    public string Error { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public static class ProtocolJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };
}
