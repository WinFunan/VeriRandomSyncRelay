using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using VeriRandomSyncRelay.Crypto;
using VeriRandomSyncRelay.Protocol;
using VeriRandomSyncRelay.Server;

namespace VeriRandomSyncRelay.Tests;

public sealed class RelayStoreTests
{
    private static readonly Argon2Parameters FastArgon2 = new(8 * 1024, 1, 1);

    [Fact]
    public async Task Quick_transfer_round_trips_through_the_store()
    {
        var (store, time) = CreateStore();
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, length, ciphertextHash,
            null, 5, time.GetUtcNow().AddMinutes(10));
        Assert.True(created.IsOk);

        var record = created.Value!.Record;
        var upload = store.Upload(record.Id, created.Value.UploadToken, bytes, envelope);
        Assert.True(upload.IsOk);

        var get = store.Get(record.Id);
        Assert.True(get.IsOk);
        Assert.Equal(bytes, get.Value);
        Assert.Equal(bytes.LongLength, store.TotalBytes);
    }

    [Fact]
    public async Task Session_transfer_resolves_by_code_and_decrypts_with_password()
    {
        var (store, time) = CreateStore();
        const string password = "correct horse battery staple";
        var code = SessionCode.Create();
        var context = Convert.FromHexString(SessionCode.HashHex(code));
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(Encoding.UTF8.GetBytes("secret roster"),
            password, TransferContentTypes.Roster, FastArgon2, context);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJson.Options);
        var ciphertext = Base64Url.Decode(envelope.Ciphertext);
        var created = store.Create(TransferModes.Session, TransferContentTypes.Roster, ciphertext.LongLength,
            SHA256.HashData(ciphertext), SessionCode.HashHex(code), 5, time.GetUtcNow().AddMinutes(10));
        Assert.True(created.IsOk);
        Assert.True(store.Upload(created.Value!.Record.Id, created.Value.UploadToken, bytes, envelope).IsOk);

        var resolved = store.Resolve(SessionCode.HashHex(code));
        Assert.True(resolved.IsOk);
        var plaintext = await EnvelopeCrypto.DecryptWithPasswordAsync(
            JsonSerializer.Deserialize<TransferEnvelope>(resolved.Value!, ProtocolJson.Options)!, password, context);
        Assert.Equal("secret roster", Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public async Task Wrong_upload_token_is_rejected()
    {
        var (store, time) = CreateStore();
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, length, ciphertextHash,
            null, 5, time.GetUtcNow().AddMinutes(10));

        var upload = store.Upload(created.Value!.Record.Id, "not-the-token", bytes, envelope);
        Assert.Equal(RelayStatus.Forbidden, upload.Status);
        Assert.Equal(RelayStatus.Forbidden, store.Delete(created.Value.Record.Id, "not-the-token").Status);
    }

    [Fact]
    public async Task Second_upload_is_rejected_so_payload_cannot_be_replaced()
    {
        var (store, time) = CreateStore();
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, length, ciphertextHash,
            null, 5, time.GetUtcNow().AddMinutes(10));
        var record = created.Value!.Record;
        Assert.True(store.Upload(record.Id, created.Value.UploadToken, bytes, envelope).IsOk);
        var second = store.Upload(record.Id, created.Value.UploadToken, bytes, envelope);
        Assert.Equal(RelayStatus.Conflict, second.Status);
    }

    [Fact]
    public async Task Download_limit_removes_the_transfer()
    {
        var (store, time) = CreateStore();
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, length, ciphertextHash,
            null, 1, time.GetUtcNow().AddMinutes(10));
        var record = created.Value!.Record;
        Assert.True(store.Upload(record.Id, created.Value.UploadToken, bytes, envelope).IsOk);

        Assert.True(store.Get(record.Id).IsOk);
        Assert.Equal(RelayStatus.Expired, store.Get(record.Id).Status);
        Assert.Equal(0, store.Count);
        Assert.Equal(0, store.TotalBytes);
    }

    [Fact]
    public async Task Expiry_is_enforced_and_cleanup_removes_the_record()
    {
        var (store, time) = CreateStore();
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, length, ciphertextHash,
            null, 5, time.GetUtcNow().AddMinutes(1));
        var record = created.Value!.Record;
        Assert.True(store.Upload(record.Id, created.Value.UploadToken, bytes, envelope).IsOk);

        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(RelayStatus.Expired, store.Get(record.Id).Status);
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void RemoveExpired_reports_removed_transfers()
    {
        var (store, time) = CreateStore();
        var hash = SHA256.HashData([1, 2, 3]);
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, 3, hash,
            null, 5, time.GetUtcNow().AddMinutes(1));
        Assert.True(created.IsOk);

        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(1, store.RemoveExpired());
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task Session_index_is_removed_with_the_transfer()
    {
        var (store, time) = CreateStore();
        var code = SessionCode.Create();
        var hash = SessionCode.HashHex(code);
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        // A quick envelope is not valid for a session transfer, so only create and delete here.
        var created = store.Create(TransferModes.Session, TransferContentTypes.Roster, length, ciphertextHash,
            hash, 5, time.GetUtcNow().AddMinutes(10));
        Assert.True(created.IsOk);

        Assert.True(store.Delete(created.Value!.Record.Id, created.Value.UploadToken).IsOk);
        Assert.Equal(RelayStatus.NotFound, store.Resolve(hash).Status);
    }

    [Fact]
    public async Task Session_upload_requires_a_password_kdf()
    {
        var (store, time) = CreateStore();
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Session, TransferContentTypes.Roster, length, ciphertextHash,
            SessionCode.HashHex(SessionCode.Create()), 5, time.GetUtcNow().AddMinutes(10));
        var upload = store.Upload(created.Value!.Record.Id, created.Value.UploadToken, bytes, envelope);
        Assert.Equal(RelayStatus.Invalid, upload.Status);
    }

    [Fact]
    public async Task Storage_capacity_is_enforced()
    {
        var (store, time) = CreateStore(new RelayOptions { MaxTotalBytes = 10 });
        var (envelope, bytes, _, ciphertextHash, length, _) = await MakeQuickEnvelopeAsync();
        var created = store.Create(TransferModes.Quick, TransferContentTypes.Roster, length, ciphertextHash,
            null, 5, time.GetUtcNow().AddMinutes(10));
        var upload = store.Upload(created.Value!.Record.Id, created.Value.UploadToken, bytes, envelope);
        Assert.Equal(RelayStatus.Capacity, upload.Status);
    }

    private static (RelayStore Store, MutableTimeProvider Time) CreateStore(RelayOptions? options = null)
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero));
        var store = new RelayStore(
            Microsoft.Extensions.Options.Options.Create(options ?? new RelayOptions()),
            time,
            NullLogger<RelayStore>.Instance);
        return (store, time);
    }

    private static async Task<(TransferEnvelope Envelope, byte[] Bytes, byte[] Key, byte[] CiphertextHash,
        int Length, byte[] Plaintext)> MakeQuickEnvelopeAsync(int requestedLength = 0)
    {
        var key = EnvelopeCrypto.CreateMasterKey();
        var plaintext = requestedLength > 0
            ? new byte[requestedLength]
            : Encoding.UTF8.GetBytes("hello relay");
        if (requestedLength > 0)
            Random.Shared.NextBytes(plaintext);
        var envelope = await EnvelopeCrypto.EncryptAsync(plaintext, key, TransferContentTypes.Roster);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, ProtocolJson.Options);
        var ciphertext = Base64Url.Decode(envelope.Ciphertext);
        return (envelope, bytes, key, SHA256.HashData(ciphertext), ciphertext.Length, plaintext);
    }
}

internal sealed class MutableTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan delta) => _now += delta;
}
