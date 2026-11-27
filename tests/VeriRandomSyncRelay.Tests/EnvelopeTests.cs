using System.Text;
using VeriRandomSyncRelay.Crypto;

namespace VeriRandomSyncRelay.Tests;

public sealed class EnvelopeTests
{
    private static readonly Argon2Parameters FastArgon2 = new(8 * 1024, 1, 1);
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("session-code-hash-test-context");

    [Fact]
    public async Task Quick_envelope_round_trips_with_master_key()
    {
        var key = EnvelopeCrypto.CreateMasterKey();
        var plaintext = Encoding.UTF8.GetBytes("名单内容 / roster content");
        var envelope = await EnvelopeCrypto.EncryptAsync(plaintext, key, "roster");

        Assert.Null(envelope.PasswordKdf);
        Assert.Equal(plaintext, EnvelopeCrypto.Decrypt(envelope, key));
    }

    [Fact]
    public async Task Session_envelope_derives_key_from_password()
    {
        var plaintext = Encoding.UTF8.GetBytes("session payload");
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(plaintext, "correct horse battery staple",
            "settings", FastArgon2, Context);

        Assert.NotNull(envelope.PasswordKdf);
        Assert.Equal(plaintext, await EnvelopeCrypto.DecryptWithPasswordAsync(envelope,
            "correct horse battery staple", Context));
        await Assert.ThrowsAsync<CryptoException>(() =>
            EnvelopeCrypto.DecryptWithPasswordAsync(envelope, "wrong password", Context));
        await Assert.ThrowsAsync<CryptoException>(() =>
            EnvelopeCrypto.DecryptWithPasswordAsync(envelope, "correct horse battery staple",
                Encoding.UTF8.GetBytes("another session code")));
    }

    [Fact]
    public async Task Password_envelope_is_rejected_on_the_quick_path()
    {
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(Encoding.UTF8.GetBytes("hello"),
            "correct horse battery staple", "roster", FastArgon2);
        var key = EnvelopeCrypto.CreateMasterKey();

        var exception = Assert.Throws<CryptoException>(() => EnvelopeCrypto.Decrypt(envelope, key));
        Assert.Contains("password", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Quick_envelope_is_rejected_on_the_password_path()
    {
        var key = EnvelopeCrypto.CreateMasterKey();
        var envelope = await EnvelopeCrypto.EncryptAsync(Encoding.UTF8.GetBytes("hello"), key, "roster");

        var exception = await Assert.ThrowsAsync<CryptoException>(() =>
            EnvelopeCrypto.DecryptWithPasswordAsync(envelope, "correct horse battery staple", Context));
        Assert.Contains("password", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Tampered_ciphertext_fails_authentication()
    {
        var key = EnvelopeCrypto.CreateMasterKey();
        var envelope = await EnvelopeCrypto.EncryptAsync(Encoding.UTF8.GetBytes("hello"), key, "roster");
        var ciphertext = Base64Url.Decode(envelope.Ciphertext);
        ciphertext[0] ^= 0x01;
        var tampered = Copy(envelope, ciphertext: Base64Url.Encode(ciphertext));

        var exception = Assert.Throws<CryptoException>(() => EnvelopeCrypto.Decrypt(tampered, key));
        Assert.Contains("authentication", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Tampered_mac_fails_authentication()
    {
        var key = EnvelopeCrypto.CreateMasterKey();
        var envelope = await EnvelopeCrypto.EncryptAsync(Encoding.UTF8.GetBytes("hello"), key, "roster");
        var mac = Base64Url.Decode(envelope.Mac);
        mac[0] ^= 0x01;
        var tampered = Copy(envelope, mac: Base64Url.Encode(mac));

        Assert.Throws<CryptoException>(() => EnvelopeCrypto.Decrypt(tampered, key));
    }

    [Fact]
    public async Task Content_type_is_bound_to_the_mac()
    {
        var key = EnvelopeCrypto.CreateMasterKey();
        var envelope = await EnvelopeCrypto.EncryptAsync(Encoding.UTF8.GetBytes("hello"), key, "roster");
        var tampered = Copy(envelope, contentType: "settings");

        Assert.Throws<CryptoException>(() => EnvelopeCrypto.Decrypt(tampered, key));
    }

    [Fact]
    public async Task Tampered_argon2_salt_fails_authentication()
    {
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(Encoding.UTF8.GetBytes("hello"),
            "correct horse battery staple", "roster", FastArgon2, Context);
        var salt = Base64Url.Decode(envelope.PasswordKdf!.Salt);
        salt[0] ^= 0x01;
        var tamperedKdf = new PasswordKdfEnvelope
        {
            Kdf = envelope.PasswordKdf.Kdf,
            Salt = Base64Url.Encode(salt),
            MemoryKib = envelope.PasswordKdf.MemoryKib,
            Iterations = envelope.PasswordKdf.Iterations,
            Parallelism = envelope.PasswordKdf.Parallelism
        };
        var tampered = Copy(envelope, passwordKdf: tamperedKdf);

        await Assert.ThrowsAsync<CryptoException>(() =>
            EnvelopeCrypto.DecryptWithPasswordAsync(tampered, "correct horse battery staple", Context));
    }

    [Fact]
    public async Task Tampered_argon2_parameters_fail_authentication()
    {
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(Encoding.UTF8.GetBytes("hello"),
            "correct horse battery staple", "roster", FastArgon2, Context);
        var tamperedKdf = new PasswordKdfEnvelope
        {
            Kdf = envelope.PasswordKdf!.Kdf,
            Salt = envelope.PasswordKdf.Salt,
            MemoryKib = envelope.PasswordKdf.MemoryKib,
            Iterations = envelope.PasswordKdf.Iterations + 1,
            Parallelism = envelope.PasswordKdf.Parallelism
        };
        var tampered = Copy(envelope, passwordKdf: tamperedKdf);

        await Assert.ThrowsAsync<CryptoException>(() =>
            EnvelopeCrypto.DecryptWithPasswordAsync(tampered, "correct horse battery staple", Context));
    }

    [Fact]
    public async Task Wire_validator_rejects_abusive_argon2_parameters()
    {
        var envelope = await EnvelopeCrypto.EncryptWithPasswordAsync(Encoding.UTF8.GetBytes("hello"),
            "correct horse battery staple", "roster", FastArgon2);
        var abusiveKdf = new PasswordKdfEnvelope
        {
            Kdf = envelope.PasswordKdf!.Kdf,
            Salt = envelope.PasswordKdf.Salt,
            MemoryKib = 10 * 1024 * 1024,
            Iterations = envelope.PasswordKdf.Iterations,
            Parallelism = envelope.PasswordKdf.Parallelism
        };
        var abusive = Copy(envelope, passwordKdf: abusiveKdf);

        Assert.False(EnvelopeCrypto.TryValidateWireEnvelope(abusive, "roster", true,
            out _, out _, out var error));
        Assert.Contains("memory", error, StringComparison.OrdinalIgnoreCase);
    }

    private static TransferEnvelope Copy(
        TransferEnvelope source,
        string? contentType = null,
        string? ciphertext = null,
        string? mac = null,
        PasswordKdfEnvelope? passwordKdf = null) =>
        new()
        {
            Format = source.Format,
            Cipher = source.Cipher,
            ContentType = contentType ?? source.ContentType,
            Iv = source.Iv,
            Mac = mac ?? source.Mac,
            Ciphertext = ciphertext ?? source.Ciphertext,
            PasswordKdf = passwordKdf ?? source.PasswordKdf
        };
}
