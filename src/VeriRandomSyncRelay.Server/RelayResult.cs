namespace VeriRandomSyncRelay.Server;

public enum RelayStatus
{
    Ok,
    NotFound,
    Forbidden,
    Conflict,
    Expired,
    NotReady,
    Capacity,
    TooMany,
    Invalid
}

public readonly record struct RelayResult<T>(RelayStatus Status, T? Value, string? Error)
{
    public bool IsOk => Status == RelayStatus.Ok;

    public static RelayResult<T> Ok(T value) => new(RelayStatus.Ok, value, null);
    public static RelayResult<T> Fail(RelayStatus status, string error) => new(status, default, error);
}

public sealed record CreatedTransfer(TransferRecord Record, string UploadToken);
