using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Options;
using VeriRandomSyncRelay.Crypto;
using VeriRandomSyncRelay.Protocol;
using VeriRandomSyncRelay.Server;

var builder = WebApplication.CreateBuilder(args);
var relayDefaults = builder.Configuration.GetSection(RelayOptions.SectionName).Get<RelayOptions>()
                    ?? new RelayOptions();

builder.WebHost.ConfigureKestrel(options =>
    options.Limits.MaxRequestBodySize = relayDefaults.MaxEnvelopeBytes + 64 * 1024);

builder.Services.Configure<RelayOptions>(builder.Configuration.GetSection(RelayOptions.SectionName));
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<RelayStore>();
builder.Services.AddHostedService<RelayCleanupService>();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("create", http => RateLimitPartition.GetFixedWindowLimiter(
        ClientKey(http), _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 30,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("resolve", http => RateLimitPartition.GetFixedWindowLimiter(
        ClientKey(http), _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.AddPolicy("upload", http => RateLimitPartition.GetFixedWindowLimiter(
        ClientKey(http), _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 120,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
            AutoReplenishment = true
        }));
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.ContentType = "application/json; charset=utf-8";
        await context.HttpContext.Response.WriteAsJsonAsync(
            new ErrorResponse { Error = "too_many_requests", Message = "Rate limit exceeded. Try again later." },
            ProtocolJson.Options, cancellationToken);
    };
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    if (context.Request.Path.StartsWithSegments("/v1"))
        context.Response.Headers.CacheControl = "no-store";
    await next();
});

app.UseRateLimiter();
if (relayDefaults.RequireHttps)
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.MapGet("/health", (RelayStore store, IOptions<RelayOptions> options) =>
    Results.Json(new
    {
        status = "ok",
        transfers = store.Count,
        storedBytes = store.TotalBytes,
        maxPayloadBytes = options.Value.MaxPayloadBytes
    }, ProtocolJson.Options));

app.MapPost("/v1/transfers",
        (CreateTransferRequest request, RelayStore store, IOptions<RelayOptions> options, TimeProvider time) =>
        {
            var settings = options.Value;
            if (!TransferModes.IsValid(request.Mode))
                return ApiErrors.Bad("invalid_mode", "Mode must be 'quick' or 'session'.");
            if (!TransferContentTypes.IsValid(request.ContentType))
                return ApiErrors.Bad("invalid_content_type", "Unknown content type.");
            if (request.PayloadLength is <= 0 || request.PayloadLength > settings.MaxPayloadBytes)
                return ApiErrors.Bad("invalid_payload_length",
                    $"Payload length must be between 1 and {settings.MaxPayloadBytes} bytes.");
            if (!TryParseHex(request.PayloadSha256, 32, out var payloadSha256))
                return ApiErrors.Bad("invalid_payload_hash", "payload_sha256 must be 32 bytes of hex.");

            var sessionMode = request.Mode == TransferModes.Session;
            string? sessionHash = null;
            if (sessionMode)
            {
                if (!TryParseHex(request.SessionCodeHash, 32, out var sessionHashBytes))
                    return ApiErrors.Bad("invalid_session_hash", "session_code_hash must be 32 bytes of hex.");
                sessionHash = Convert.ToHexString(sessionHashBytes).ToLowerInvariant();
            }
            else if (request.SessionCodeHash is not null)
            {
                return ApiErrors.Bad("invalid_session_hash", "Quick transfers cannot carry a session code hash.");
            }

            var maxDownloads = Math.Clamp(request.MaxDownloads ?? settings.DefaultMaxDownloads,
                1, settings.MaxDownloads);
            var ttl = Math.Clamp(request.ExpiresInSeconds ?? settings.DefaultTtlSeconds,
                settings.MinTtlSeconds, settings.MaxTtlSeconds);
            var expiresAt = time.GetUtcNow().AddSeconds(ttl);

            var result = store.Create(request.Mode, request.ContentType, request.PayloadLength,
                payloadSha256, sessionHash, maxDownloads, expiresAt);
            if (!result.IsOk)
                return ApiErrors.From(result.Status, result.Error);

            var created = result.Value!;
            return Results.Json(new CreateTransferResponse
            {
                Id = created.Record.Id,
                UploadToken = created.UploadToken,
                ExpiresAt = created.Record.ExpiresAt,
                MaxDownloads = created.Record.MaxDownloads
            }, ProtocolJson.Options, statusCode: StatusCodes.Status201Created);
        })
    .RequireRateLimiting("create");

app.MapPut("/v1/transfers/{id}/payload",
        async (string id, HttpRequest request, RelayStore store, IOptions<RelayOptions> options,
            CancellationToken cancellationToken) =>
        {
            if (!request.Headers.TryGetValue("X-VeriRandom-Upload-Token", out var tokenValues) ||
                string.IsNullOrWhiteSpace(tokenValues.ToString()))
                return ApiErrors.Bad("missing_upload_token", "The X-VeriRandom-Upload-Token header is required.");
            if (request.ContentLength is { } contentLength && contentLength > options.Value.MaxEnvelopeBytes)
                return ApiErrors.TooLarge("Envelope exceeds the allowed size.");

            var body = await ReadBodyAsync(request.Body, options.Value.MaxEnvelopeBytes, cancellationToken);
            if (body is null)
                return ApiErrors.TooLarge("Envelope exceeds the allowed size.");

            TransferEnvelope? envelope;
            try
            {
                envelope = JsonSerializer.Deserialize<TransferEnvelope>(body, ProtocolJson.Options);
            }
            catch (JsonException)
            {
                return ApiErrors.Bad("invalid_envelope", "The request body is not a valid envelope.");
            }
            if (envelope is null)
                return ApiErrors.Bad("invalid_envelope", "The request body is not a valid envelope.");

            var result = store.Upload(id, tokenValues.ToString(), body, envelope);
            return result.IsOk ? Results.NoContent() : ApiErrors.From(result.Status, result.Error);
        })
    .RequireRateLimiting("upload");

app.MapGet("/v1/transfers/{id}", (HttpContext context, string id, RelayStore store) =>
{
    var result = store.Get(id);
    if (!result.IsOk)
        return ApiErrors.From(result.Status, result.Error);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Bytes(result.Value!, "application/json; charset=utf-8");
});

app.MapPost("/v1/sessions/resolve",
        (ResolveSessionRequest request, HttpContext context, RelayStore store) =>
        {
            if (!TryParseHex(request.SessionCodeHash, 32, out var sessionHashBytes))
                return ApiErrors.Bad("invalid_session_hash", "session_code_hash must be 32 bytes of hex.");
            var result = store.Resolve(Convert.ToHexString(sessionHashBytes).ToLowerInvariant());
            if (!result.IsOk)
                return ApiErrors.From(result.Status, result.Error);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Bytes(result.Value!, "application/json; charset=utf-8");
        })
    .RequireRateLimiting("resolve");

app.MapDelete("/v1/transfers/{id}", (string id, HttpRequest request, RelayStore store) =>
{
    if (!request.Headers.TryGetValue("X-VeriRandom-Upload-Token", out var tokenValues) ||
        string.IsNullOrWhiteSpace(tokenValues.ToString()))
        return ApiErrors.Bad("missing_upload_token", "The X-VeriRandom-Upload-Token header is required.");
    var result = store.Delete(id, tokenValues.ToString());
    return result.IsOk ? Results.NoContent() : ApiErrors.From(result.Status, result.Error);
});

app.Run();

static string ClientKey(HttpContext context) =>
    context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

static bool TryParseHex(string? value, int byteLength, out byte[] bytes)
{
    bytes = [];
    if (value is null || value.Length != byteLength * 2)
        return false;
    try
    {
        bytes = Convert.FromHexString(value);
        return bytes.Length == byteLength;
    }
    catch (FormatException)
    {
        return false;
    }
}

static async Task<byte[]?> ReadBodyAsync(Stream body, long limit, CancellationToken cancellationToken)
{
    using var output = new MemoryStream();
    var buffer = new byte[81920];
    int read;
    while ((read = await body.ReadAsync(buffer, cancellationToken)) > 0)
    {
        if (output.Length + read > limit)
            return null;
        output.Write(buffer, 0, read);
    }
    return output.ToArray();
}

public partial class Program;
