using VeriRandomSyncRelay.Crypto;

namespace VeriRandomSyncRelay.Tests;

public sealed class SessionCodeTests
{
    [Fact]
    public void Created_codes_are_valid_and_use_the_unambiguous_alphabet()
    {
        for (var i = 0; i < 100; i++)
        {
            var code = SessionCode.Create();
            Assert.True(SessionCode.IsValid(code));
            Assert.Equal(SessionCode.Length, code.Length);
            Assert.All(code, character => Assert.Contains(character, SessionCode.Alphabet));
        }
    }

    [Fact]
    public void Normalization_accepts_display_formatting()
    {
        const string expected = "ABCDEFGHJKLM";
        Assert.Equal(expected, SessionCode.Normalize("abcd-efgh jklm"));
        Assert.Equal(expected, SessionCode.Normalize("ABCD EFGH JKLM"));
        Assert.True(SessionCode.IsValid("abcd-efgh jklm"));
        Assert.Equal("ABCD-EFGH-JKLM", SessionCode.Format("abcd-efgh jklm"));
    }

    [Fact]
    public void Hashes_are_stable_and_case_insensitive()
    {
        const string code = "ABCD2345EFGH";
        var hashA = SessionCode.HashHex(code);
        var hashB = SessionCode.HashHex("abcd-2345 efgh");
        Assert.Equal(64, hashA.Length);
        Assert.Equal(hashA, hashB);
    }

    [Theory]
    [InlineData("")]
    [InlineData("TOO-SHORT")]
    [InlineData("IIIIIIIIIIII")]
    [InlineData("OOOOOOOOOOOO")]
    [InlineData("000000000000")]
    [InlineData("111111111111")]
    public void Rejects_invalid_codes(string code)
    {
        Assert.False(SessionCode.IsValid(code));
        Assert.Throws<CryptoException>(() => SessionCode.HashHex(code));
    }

    [Fact]
    public void Generated_passwords_are_strong()
    {
        var password = SessionCode.GeneratePassword();
        Assert.True(password.Length >= 32);
        Assert.NotEqual(password, SessionCode.GeneratePassword());
    }
}
