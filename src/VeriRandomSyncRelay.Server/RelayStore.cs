using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using VeriRandomSyncRelay.Crypto;
using VeriRandomSyncRelay.Protocol;

namespace VeriRandomSyncRelay.Server;

/// <summary>
/// In-memory, short-lived transfer store. The relay is deliberately stateless
/// across restarts: a transfer either completes inside its TTL or expires.
/// </summary>
public sealed class RelayStore(
    IOptions<RelayOptions> options,
    TimeProvider timeProvider,
    ILogger<RelayStore> logger)
{
    private readonly RelayOptions _options = options.Value;
    private readonly ConcurrentDictionary<string, TransferRecord> _byId = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _bySessionHash = new(StringComparer.Ordinal);
    private long _totalBytes;

    public int Count => _byId.Count;
    public long TotalBytes => Interlocked.Read(ref _totalBytes);

    public RelayResult<CreatedTransfer> Create(
        string mode,
        string contentType,
        long payloadLength,
        byte[] payloadSha256,
        string? sessionCodeHash,
        int maxDownloads,
        DateTimeOffset expiresAt)
    {
        if (!TransferModes.IsValid(mode))
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Unknown transfer mode.");
        if (!TransferContentTypes.IsValid(contentType))
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Unknown content type.");
        if (payloadLength is <= 0 || payloadLength > _options.MaxPayloadBytes)
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Payload length is outside the allowed range.");
        if (payloadSha256.Length != 32)
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Payload hash must be SHA-256.");
        if (mode == TransferModes.Session && !IsHex64(sessionCodeHash))
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Session transfers require a session code hash.");
        if (mode == TransferModes.Quick && sessionCodeHash is not null)
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Quick transfers cannot carry a session code hash.");

        if (_byId.Count >= _options.MaxTransfers)
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.TooMany, "The relay is at its transfer limit.");
        if (expiresAt <= timeProvider.GetUtcNow())
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Invalid, "Expiry must be in the future.");

        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var uploadToken = Base64Url.Encode(tokenBytes);
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(uploadToken));
        CryptographicOperations.ZeroMemory(tokenBytes);

        TransferRecord? record = null;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var candidate = new TransferRecord
            {
                Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant(),
                UploadTokenHash = tokenHash,
                Mode = mode,
                ContentType = contentType,
                PayloadLength = payloadLength,
                PayloadSha256 = payloadSha256,
                SessionCodeHash = sessionCodeHash,
                ExpiresAt = expiresAt,
                MaxDownloads = maxDownloads
            };
            if (_byId.TryAdd(candidate.Id, candidate))
            {
                record = candidate;
                break;
            }
        }

        if (record is null)
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Capacity, "Could not allocate a transfer id.");

        if (sessionCodeHash is not null && !_bySessionHash.TryAdd(sessionCodeHash, record.Id))
        {
            Remove(record);
            return RelayResult<CreatedTransfer>.Fail(RelayStatus.Conflict, "That session code is already in use.");
        }

        logger.LogInformation("Created {Mode} transfer {TransferId} ({Bytes} bytes, expires {ExpiresAt})",
            mode, record.Id, payloadLength, expiresAt);
        return RelayResult<CreatedTransfer>.Ok(new CreatedTransfer(record, uploadToken));
    }

    public RelayResult<bool> Upload(string id, string uploadToken, byte[] envelopeBytes, TransferEnvelope envelope)
    {
        if (!_byId.TryGetValue(id, out var record))
            return RelayResult<bool>.Fail(RelayStatus.NotFound, "Transfer not found.");
        if (envelopeBytes.Length == 0 || envelopeBytes.Length > _options.MaxEnvelopeBytes)
            return RelayResult<bool>.Fail(RelayStatus.Invalid, "Envelope size is outside the allowed range.");

        lock (record.Gate)
        {
            if (record.ExpiresAt <= timeProvider.GetUtcNow())
            {
                Remove(record);
                return RelayResult<bool>.Fail(RelayStatus.Expired, "Transfer has expired.");
            }

            var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(uploadToken));
            if (!CryptographicOperations.FixedTimeEquals(tokenHash, record.UploadTokenHash))
                return RelayResult<bool>.Fail(RelayStatus.Forbidden, "Upload token is invalid.");

            if (record.EnvelopeBytes is not null)
                return RelayResult<bool>.Fail(RelayStatus.Conflict, "Transfer already has a payload.");

            var requirePasswordKdf = record.Mode == TransferModes.Session;
            if (!EnvelopeCrypto.TryValidateWireEnvelope(envelope, record.ContentType, requirePasswordKdf,
                    out var ciphertextLength, out var ciphertextSha256, out var error))
                return RelayResult<bool>.Fail(RelayStatus.Invalid, error);

            if (ciphertextLength != record.PayloadLength)
                return RelayResult<bool>.Fail(RelayStatus.Invalid, "Ciphertext length does not match the transfer.");
            if (!CryptographicOperations.FixedTimeEquals(ciphertextSha256, record.PayloadSha256))
                return RelayResult<bool>.Fail(RelayStatus.Invalid, "Ciphertext hash does not match the transfer.");

            if (Interlocked.Read(ref _totalBytes) + envelopeBytes.Length > _options.MaxTotalBytes)
                return RelayResult<bool>.Fail(RelayStatus.Capacity, "The relay is at its storage limit.");

            record.EnvelopeBytes = envelopeBytes.ToArray();
            Interlocked.Add(ref _totalBytes, record.EnvelopeBytes.Length);
            logger.LogInformation("Uploaded payload for transfer {TransferId}", record.Id);
            return RelayResult<bool>.Ok(true);
        }
    }

    public RelayResult<byte[]> Get(string id) => Download(id);

    public RelayResult<byte[]> Resolve(string sessionCodeHash)
    {
        if (!IsHex64(sessionCodeHash))
            return RelayResult<byte[]>.Fail(RelayStatus.Invalid, "Session code hash must be SHA-256 hex.");
        if (!_bySessionHash.TryGetValue(sessionCodeHash.ToLowerInvariant(), out var id))
            return RelayResult<byte[]>.Fail(RelayStatus.NotFound, "Session not found.");
        return Download(id);
    }

    public RelayResult<bool> Delete(string id, string uploadToken)
    {
        if (!_byId.TryGetValue(id, out var record))
            return RelayResult<bool>.Fail(RelayStatus.NotFound, "Transfer not found.");

        lock (record.Gate)
        {
            var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(uploadToken));
            if (!CryptographicOperations.FixedTimeEquals(tokenHash, record.UploadTokenHash))
                return RelayResult<bool>.Fail(RelayStatus.Forbidden, "Upload token is invalid.");
            if (record.ExpiresAt <= timeProvider.GetUtcNow())
            {
                Remove(record);
                return RelayResult<bool>.Fail(RelayStatus.Expired, "Transfer has expired.");
            }

            Remove(record);
            logger.LogInformation("Revoked transfer {TransferId}", record.Id);
            return RelayResult<bool>.Ok(true);
        }
    }

    public int RemoveExpired()
    {
        var now = timeProvider.GetUtcNow();
        var removed = 0;
        foreach (var record in _byId.Values)
        {
            if (record.ExpiresAt <= now && Remove(record))
                removed++;
        }
        return removed;
    }

    private RelayResult<byte[]> Download(string id)
    {
        if (!_byId.TryGetValue(id, out var record))
            return RelayResult<byte[]>.Fail(RelayStatus.NotFound, "Transfer not found.");

        lock (record.Gate)
        {
            if (record.ExpiresAt <= timeProvider.GetUtcNow())
            {
                Remove(record);
                return RelayResult<byte[]>.Fail(RelayStatus.Expired, "Transfer has expired.");
            }
            if (record.EnvelopeBytes is null)
                return RelayResult<byte[]>.Fail(RelayStatus.NotReady, "Transfer has no payload yet.");
            if (record.Downloads >= record.MaxDownloads)
            {
                Remove(record);
                return RelayResult<byte[]>.Fail(RelayStatus.Expired, "Transfer download limit reached.");
            }

            record.Downloads++;
            return RelayResult<byte[]>.Ok(record.EnvelopeBytes);
        }
    }

    private bool Remove(TransferRecord record)
    {
        if (!((ICollection<KeyValuePair<string, TransferRecord>>)_byId)
            .Remove(new KeyValuePair<string, TransferRecord>(record.Id, record)))
            return false;

        if (record.SessionCodeHash is { } hash)
            ((ICollection<KeyValuePair<string, string>>)_bySessionHash)
                .Remove(new KeyValuePair<string, string>(hash, record.Id));

        if (record.EnvelopeBytes is { } bytes)
            Interlocked.Add(ref _totalBytes, -bytes.Length);
        return true;
    }

    private static bool IsHex64(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);
}
