using VeriRandomSyncRelay.Protocol;

namespace VeriRandomSyncRelay.Server;

public static class ApiErrors
{
    public static IResult From(RelayStatus status, string? message) => status switch
    {
        RelayStatus.Invalid => Write(StatusCodes.Status400BadRequest, "invalid_request", message),
        RelayStatus.NotFound => Write(StatusCodes.Status404NotFound, "not_found", message),
        RelayStatus.Forbidden => Write(StatusCodes.Status403Forbidden, "forbidden", message),
        RelayStatus.Conflict => Write(StatusCodes.Status409Conflict, "conflict", message),
        RelayStatus.NotReady => Write(StatusCodes.Status409Conflict, "not_ready", message),
        RelayStatus.Expired => Write(StatusCodes.Status410Gone, "expired", message),
        RelayStatus.Capacity => Write(StatusCodes.Status503ServiceUnavailable, "capacity", message),
        RelayStatus.TooMany => Write(StatusCodes.Status429TooManyRequests, "too_many_transfers", message),
        _ => Write(StatusCodes.Status500InternalServerError, "server_error", message ?? "Unexpected relay error.")
    };

    public static IResult Bad(string code, string message) =>
        Write(StatusCodes.Status400BadRequest, code, message);

    public static IResult TooLarge(string message) =>
        Write(StatusCodes.Status413PayloadTooLarge, "payload_too_large", message);

    private static IResult Write(int statusCode, string code, string? message) =>
        Results.Json(new ErrorResponse { Error = code, Message = message ?? code },
            ProtocolJson.Options, statusCode: statusCode);
}
