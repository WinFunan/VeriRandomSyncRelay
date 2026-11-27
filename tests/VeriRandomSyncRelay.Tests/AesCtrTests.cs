using VeriRandomSyncRelay.Crypto;

namespace VeriRandomSyncRelay.Tests;

public sealed class AesCtrTests
{
    [Fact]
    public void Matches_Nist_Sp800_38a_F5_1_vector()
    {
        var key = Hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = Hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = Hex("6bc1bee22e409f96e93d7e117393172a" +
                            "ae2d8a571e03ac9c9eb76fac45af8e51" +
                            "30c81c46a35ce411e5fbc1191a0a52ef" +
                            "f69f2445df4f9b17ad2b417be66c3710");
        var expected = Hex("874d6191b620e3261bef6864990db6ce" +
                           "9806f66b7970fdff8617187bb9fffdff" +
                           "5ae4df3edbd5d35e5b4f09020db03eab" +
                           "1e031dda2fbe03d1792170a0f3009cee");

        var ciphertext = AesCtr.Transform(plaintext, key, iv);
        Assert.Equal(expected, ciphertext);
        Assert.Equal(plaintext, AesCtr.Transform(ciphertext, key, iv));
    }

    [Fact]
    public void Handles_Partial_Blocks()
    {
        var key = EnvelopeCrypto.CreateMasterKey()[..16];
        var iv = EnvelopeCrypto.CreateMasterKey()[..16];
        var plaintext = new byte[37];
        Random.Shared.NextBytes(plaintext);
        var ciphertext = AesCtr.Transform(plaintext, key, iv);
        Assert.Equal(plaintext, AesCtr.Transform(ciphertext, key, iv));
    }

    private static byte[] Hex(string value) => Convert.FromHexString(value);
}
