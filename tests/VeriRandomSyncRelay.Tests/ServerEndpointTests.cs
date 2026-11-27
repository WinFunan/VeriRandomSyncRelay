using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using VeriRandomSyncRelay.Crypto;
using VeriRandomSyncRelay.Protocol;

namespace VeriRandomSyncRelay.Tests;

public sealed class ServerEndpointTests(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly Argon2Parameters FastArgon2 = new(8 * 1024, 1, 1);

    [Fact]
    public async Task Quick_transfer_round_trips_over_http()
    {
        using var client = factory.CreateClient();
        var key = EnvelopeCrypto.CreateMasterKey();
        var plaintext = Encoding.UTF8.GetBytes("class roster");
        var envelope = await EnvelopeCrypto.EncryptAsync(plaintext, key, TransferContentTypes.Roster);
        var ciphertext = Base64Url.Decode(envelope.Ciphertext);

        var created = await CreateAsync(client, new CreateTransferRequest
        {
            Mode = TransferModes.Quick,
            ContentType = TransferContentTypes.Roster,
            PayloadLength = ciphertext.LongLength,
            PayloadSha256 = Convert.ToHexString(SHA256.HashData(ciphertext))
        });

        Assert.Null(envelope.PasswordKdf);
        await UploadAsync(client, created, envelope);

        using var getResponse = await client.GetAsync($"/v1/transfers/{created.Id}");
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        var downloaded = await getResponse.Content.ReadFromJsonAsync<TransferEnvelope>(ProtocolJson.Options);
        Assert.NotNull(downloaded);
        Assert.Equal(plaintext, EnvelopeCrypto.Decrypt(downloaded!, key));

        await DeleteAsync(client, created);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/v1/transfers/{created.Id}")).StatusCode);
    }

    [Fact]
    public async Task Session_transfer_resolves_by_code()
    {
        using var client = factory.CreateClient();
        const string password = "correct horse battery staple";
        var code = SessionCode.Create();
        var context = Convert.FromHexString(SessionCode.HashHex(code));
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(Encoding.UTF8.GetBytes("prize pool"),
            password, TransferContentTypes.Roster, FastArgon2, context);
        var ciphertext = Base64Url.Decode(envelope.Ciphertext);

        var created = await CreateAsync(client, new CreateTransferRequest
        {
            Mode = TransferModes.Session,
            ContentType = TransferContentTypes.Roster,
            PayloadLength = ciphertext.LongLength,
            PayloadSha256 = Convert.ToHexString(SHA256.HashData(ciphertext)),
            SessionCodeHash = SessionCode.HashHex(code)
        });
        await UploadAsync(client, created, envelope);

        using var resolveResponse = await client.PostAsJsonAsync("/v1/sessions/resolve",
            new ResolveSessionRequest { SessionCodeHash = SessionCode.HashHex(code) }, ProtocolJson.Options);
        Assert.Equal(HttpStatusCode.OK, resolveResponse.StatusCode);
        var resolved = await resolveResponse.Content.ReadFromJsonAsync<TransferEnvelope>(ProtocolJson.Options);
        Assert.NotNull(resolved);
        Assert.Equal("prize pool", Encoding.UTF8.GetString(
            await EnvelopeCrypto.DecryptWithPasswordAsync(resolved!, password,
                Convert.FromHexString(SessionCode.HashHex(code)))));
    }

    [Fact]
    public async Task Get_before_upload_returns_not_ready()
    {
        using var client = factory.CreateClient();
        var ciphertext = new byte[32];
        var created = await CreateAsync(client, new CreateTransferRequest
        {
            Mode = TransferModes.Quick,
            ContentType = TransferContentTypes.Settings,
            PayloadLength = ciphertext.LongLength,
            PayloadSha256 = Convert.ToHexString(SHA256.HashData(ciphertext))
        });

        var response = await client.GetAsync($"/v1/transfers/{created.Id}");
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Payload_over_one_mib_is_rejected_at_create()
    {
        using var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/v1/transfers", new CreateTransferRequest
        {
            Mode = TransferModes.Quick,
            ContentType = TransferContentTypes.Roster,
            PayloadLength = 1024 * 1024 + 1,
            PayloadSha256 = new string('a', 64)
        }, ProtocolJson.Options);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_requires_the_upload_token()
    {
        using var client = factory.CreateClient();
        var key = EnvelopeCrypto.CreateMasterKey();
        var envelope = await EnvelopeCrypto.EncryptAsync(Encoding.UTF8.GetBytes("x"), key,
            TransferContentTypes.Roster);
        var ciphertext = Base64Url.Decode(envelope.Ciphertext);
        var created = await CreateAsync(client, new CreateTransferRequest
        {
            Mode = TransferModes.Quick,
            ContentType = TransferContentTypes.Roster,
            PayloadLength = ciphertext.LongLength,
            PayloadSha256 = Convert.ToHexString(SHA256.HashData(ciphertext))
        });

        using var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJson.Options));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/v1/transfers/{created.Id}/payload")
        {
            Content = content
        };
        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static async Task<CreateTransferResponse> CreateAsync(HttpClient client, CreateTransferRequest request)
    {
        using var response = await client.PostAsJsonAsync("/v1/transfers", request, ProtocolJson.Options);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<CreateTransferResponse>(ProtocolJson.Options)
               ?? throw new InvalidOperationException("Empty create response.");
    }

    private static async Task UploadAsync(HttpClient client, CreateTransferResponse created,
        TransferEnvelope envelope)
    {
        using var content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJson.Options));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/v1/transfers/{created.Id}/payload")
        {
            Content = content
        };
        request.Headers.Add("X-VeriRandom-Upload-Token", created.UploadToken);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private static async Task DeleteAsync(HttpClient client, CreateTransferResponse created)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, $"/v1/transfers/{created.Id}");
        request.Headers.Add("X-VeriRandom-Upload-Token", created.UploadToken);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }
}
