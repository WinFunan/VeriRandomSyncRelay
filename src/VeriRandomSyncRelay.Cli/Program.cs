using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VeriRandomSyncRelay.Crypto;
using VeriRandomSyncRelay.Protocol;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    PrintUsage();
    return 0;
}

var command = args[0];
var options = ParseOptions(args.Skip(1).ToArray());
try
{
    return command switch
    {
        "send" => await SendAsync(options),
        "receive" => await ReceiveAsync(options),
        _ => UnknownCommand(command)
    };
}
catch (Exception exception)
{
    Console.Error.WriteLine($"error: {exception.Message}");
    return 1;
}

static int UnknownCommand(string command)
{
    Console.Error.WriteLine($"error: unknown command '{command}'");
    PrintUsage();
    return 2;
}

static async Task<int> SendAsync(Dictionary<string, string?> options)
{
    var server = Optional(options, "server") ?? "http://localhost:5227";
    var mode = Optional(options, "mode") ?? TransferModes.Quick;
    if (mode is not (TransferModes.Quick or TransferModes.Session))
        throw new ArgumentException("--mode must be 'quick' or 'session'.");
    var file = Require(options, "file");
    var contentType = Optional(options, "content-type") ?? TransferContentTypes.Roster;
    if (!TransferContentTypes.IsValid(contentType))
        throw new ArgumentException("--content-type must be roster, settings, all-data or text-library.");

    var plaintext = await File.ReadAllBytesAsync(file);
    var sessionCode = mode == TransferModes.Session ? SessionCode.Create() : null;
    var suppliedPassword = Optional(options, "password");
    var password = mode == TransferModes.Session
        ? suppliedPassword ?? SessionCode.GeneratePassword()
        : null;
    if (password is { Length: < 8 })
        Console.Error.WriteLine("warning: the password is shorter than 8 characters; Argon2id slows guessing but cannot rescue a weak password.");

    var argon2 = ReadArgon2(options);
    byte[]? masterKey = null;
    try
    {
        TransferEnvelope envelope;
        if (mode == TransferModes.Quick)
        {
            masterKey = EnvelopeCrypto.CreateMasterKey();
            envelope = await EnvelopeCrypto.EncryptAsync(plaintext, masterKey, contentType);
        }
        else
        {
            var context = Convert.FromHexString(SessionCode.HashHex(sessionCode!));
            envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(plaintext, password!, contentType, argon2,
                context);
        }

        var ciphertext = Base64Url.Decode(envelope.Ciphertext);
        var request = new CreateTransferRequest
        {
            Mode = mode,
            ContentType = contentType,
            PayloadLength = ciphertext.LongLength,
            PayloadSha256 = Convert.ToHexString(SHA256.HashData(ciphertext)).ToLowerInvariant(),
            SessionCodeHash = sessionCode is null ? null : SessionCode.HashHex(sessionCode),
            MaxDownloads = OptionalInt(options, "max-downloads"),
            ExpiresInSeconds = OptionalInt(options, "expires")
        };

        using var client = CreateClient(server);
        using var createResponse = await client.PostAsJsonAsync("v1/transfers", request, ProtocolJson.Options);
        await EnsureSuccessAsync(createResponse);
        var created = await createResponse.Content.ReadFromJsonAsync<CreateTransferResponse>(ProtocolJson.Options)
                      ?? throw new InvalidOperationException("The relay returned an empty create response.");

        try
        {
            await UploadAsync(client, created, envelope);
        }
        catch
        {
            await TryDeleteAsync(client, created);
            throw;
        }

        Console.WriteLine($"Transfer id : {created.Id}");
        Console.WriteLine($"Mode        : {mode}");
        Console.WriteLine($"Content type: {contentType}");
        Console.WriteLine($"Ciphertext  : {ciphertext.LongLength:N0} bytes");
        Console.WriteLine($"Expires at  : {created.ExpiresAt:u}");
        Console.WriteLine($"Downloads   : {created.MaxDownloads}");

        if (mode == TransferModes.Quick)
        {
            var pairingUrl = $"{server.TrimEnd('/')}/#t={Uri.EscapeDataString(created.Id)}&k={Base64Url.Encode(masterKey!)}";
            Console.WriteLine();
            Console.WriteLine($"Pairing URL : {pairingUrl}");
            Console.WriteLine("The key is in the URL fragment, so it is never sent to the relay. Do not put this URL");
            Console.WriteLine("into a server-side QR generator that uploads the URL to a third party.");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine($"Session code: {SessionCode.Format(sessionCode!)}");
            if (suppliedPassword is null)
                Console.WriteLine($"Password    : {password}");
            else
                Console.WriteLine("Password    : (as supplied)");
            Console.WriteLine("The receiver needs both the session code and this password.");
        }

        return 0;
    }
    finally
    {
        if (masterKey is not null)
            CryptographicOperations.ZeroMemory(masterKey);
    }
}

static async Task<int> ReceiveAsync(Dictionary<string, string?> options)
{
    var server = Optional(options, "server") ?? "http://localhost:5227";
    var output = Optional(options, "output") ?? "received.bin";
    var expectedContentType = Optional(options, "expect-content-type");
    if (expectedContentType is not null && !TransferContentTypes.IsValid(expectedContentType))
        throw new ArgumentException("--expect-content-type must be roster, settings, all-data or text-library.");

    using var client = CreateClient(server);
    TransferEnvelope envelope;
    byte[] plaintext;

    var pairingUrl = Optional(options, "url");
    var code = Optional(options, "code");
    if (pairingUrl is not null)
    {
        var (id, key) = ParsePairingUrl(pairingUrl);
        try
        {
            using var response = await client.GetAsync($"v1/transfers/{Uri.EscapeDataString(id)}");
            await EnsureSuccessAsync(response);
            envelope = await response.Content.ReadFromJsonAsync<TransferEnvelope>(ProtocolJson.Options)
                       ?? throw new InvalidOperationException("The relay returned an empty envelope.");
            plaintext = EnvelopeCrypto.Decrypt(envelope, key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
    else if (code is not null)
    {
        if (!SessionCode.IsValid(code))
            throw new ArgumentException("The session code must be 12 characters from the unambiguous alphabet.");
        var password = Optional(options, "password") ?? ReadPassword("Password: ");
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("A password is required for session-code transfers.");

        using var response = await client.PostAsJsonAsync("v1/sessions/resolve",
            new ResolveSessionRequest { SessionCodeHash = SessionCode.HashHex(code) }, ProtocolJson.Options);
        await EnsureSuccessAsync(response);
        envelope = await response.Content.ReadFromJsonAsync<TransferEnvelope>(ProtocolJson.Options)
                   ?? throw new InvalidOperationException("The relay returned an empty envelope.");
        plaintext = await EnvelopeCrypto.DecryptWithPasswordAsync(envelope, password,
            Convert.FromHexString(SessionCode.HashHex(code)));
    }
    else
    {
        throw new ArgumentException("Specify either --url (quick QR) or --code (session code).");
    }

    if (expectedContentType is not null && !string.Equals(envelope.ContentType, expectedContentType, StringComparison.Ordinal))
        throw new InvalidOperationException($"Envelope content type is '{envelope.ContentType}', not '{expectedContentType}'.");

    await File.WriteAllBytesAsync(output, plaintext);
    Console.WriteLine($"Content type: {envelope.ContentType}");
    Console.WriteLine($"Decrypted   : {plaintext.LongLength:N0} bytes");
    Console.WriteLine($"Output      : {Path.GetFullPath(output)}");
    return 0;
}

static HttpClient CreateClient(string server)
{
    var baseUri = new Uri(server.TrimEnd('/') + "/", UriKind.Absolute);
    return new HttpClient
    {
        BaseAddress = baseUri,
        Timeout = TimeSpan.FromSeconds(60)
    };
}

static async Task UploadAsync(HttpClient client, CreateTransferResponse created, TransferEnvelope envelope)
{
    var body = JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJson.Options);
    using var content = new ByteArrayContent(body);
    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
    using var request = new HttpRequestMessage(HttpMethod.Put,
        $"v1/transfers/{Uri.EscapeDataString(created.Id)}/payload")
    {
        Content = content
    };
    request.Headers.Add("X-VeriRandom-Upload-Token", created.UploadToken);
    using var response = await client.SendAsync(request);
    await EnsureSuccessAsync(response);
}

static async Task TryDeleteAsync(HttpClient client, CreateTransferResponse created)
{
    try
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete,
            $"v1/transfers/{Uri.EscapeDataString(created.Id)}");
        request.Headers.Add("X-VeriRandom-Upload-Token", created.UploadToken);
        using var response = await client.SendAsync(request);
    }
    catch
    {
        // Expiry remains the fallback cleanup path.
    }
}

static async Task EnsureSuccessAsync(HttpResponseMessage response)
{
    if (response.IsSuccessStatusCode)
        return;
    var body = await response.Content.ReadAsStringAsync();
    throw new InvalidOperationException($"relay returned {(int)response.StatusCode}: {body}");
}

static (string Id, byte[] Key) ParsePairingUrl(string value)
{
    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        throw new ArgumentException("--url must be an absolute pairing URL.");

    var fragment = uri.Fragment.TrimStart('#');
    var values = new Dictionary<string, string>(StringComparer.Ordinal);
    foreach (var part in fragment.Split('&', StringSplitOptions.RemoveEmptyEntries))
    {
        var separator = part.IndexOf('=');
        if (separator <= 0)
            continue;
        values[part[..separator]] = Uri.UnescapeDataString(part[(separator + 1)..]);
    }

    if (!values.TryGetValue("t", out var id) || string.IsNullOrWhiteSpace(id))
        throw new ArgumentException("The pairing URL has no transfer id.");
    if (!values.TryGetValue("k", out var keyText))
        throw new ArgumentException("The pairing URL has no key.");
    var key = Base64Url.Decode(keyText);
    if (key.Length != EnvelopeCrypto.MasterKeySize)
        throw new ArgumentException("The pairing URL key has the wrong size.");
    return (id, key);
}

static Argon2Parameters ReadArgon2(Dictionary<string, string?> options)
{
    var parameters = new Argon2Parameters(
        OptionalInt(options, "argon2-memory") ?? Argon2Parameters.Default.MemoryKib,
        OptionalInt(options, "argon2-iterations") ?? Argon2Parameters.Default.Iterations,
        OptionalInt(options, "argon2-parallelism") ?? Argon2Parameters.Default.Parallelism);
    parameters.Validate();
    return parameters;
}

static Dictionary<string, string?> ParseOptions(string[] args)
{
    var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length; i++)
    {
        var argument = args[i];
        if (!argument.StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException($"Unexpected argument '{argument}'.");
        var equals = argument.IndexOf('=');
        if (equals > 0)
        {
            result[argument[2..equals]] = argument[(equals + 1)..];
            continue;
        }

        var key = argument[2..];
        if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            result[key] = args[++i];
        else
            result[key] = null;
    }
    return result;
}

static string Require(Dictionary<string, string?> options, string key) =>
    Optional(options, key) ?? throw new ArgumentException($"--{key} is required.");

static string? Optional(Dictionary<string, string?> options, string key) =>
    options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

static int? OptionalInt(Dictionary<string, string?> options, string key)
{
    var value = Optional(options, key);
    if (value is null)
        return null;
    if (!int.TryParse(value, out var parsed))
        throw new ArgumentException($"--{key} must be an integer.");
    return parsed;
}

static string ReadPassword(string prompt)
{
    Console.Write(prompt);
    if (Console.IsInputRedirected)
        return Console.ReadLine() ?? string.Empty;

    var builder = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
            break;
        if (key.Key == ConsoleKey.Backspace)
        {
            if (builder.Length > 0)
                builder.Length--;
            continue;
        }
        if (!char.IsControl(key.KeyChar))
            builder.Append(key.KeyChar);
    }
    Console.WriteLine();
    return builder.ToString();
}

static void PrintUsage()
{
    Console.WriteLine("""
        VeriRandom Sync relay client

        Send:
          relay-cli send --file <path> [--mode quick|session] [--server URL]
                         [--content-type roster|settings|all-data|text-library]
                         [--password <password>] [--expires <seconds>]
                         [--max-downloads <n>]
                         [--argon2-memory <KiB>] [--argon2-iterations <n>]
                         [--argon2-parallelism <n>]

        Receive:
          relay-cli receive --url <pairing URL> [--server URL] [--output <path>]
          relay-cli receive --code <session code> [--password <password>]
                            [--server URL] [--output <path>]
                            [--expect-content-type <type>]

        Quick mode prints a pairing URL whose #fragment carries the key.
        Session mode prints a 12-character lookup code and a separate password.
        """);
}
