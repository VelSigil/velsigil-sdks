using System;
using System.Linq;
using System.Text;
using Velsigil.Client.Internal;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

public class Base64UrlTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("Zg", "f")]
    [InlineData("Zg==", "f")]
    [InlineData("Zm8", "fo")]
    [InlineData("Zm8=", "fo")]
    [InlineData("Zm9v", "foo")]
    [InlineData("Zm9vYg", "foob")]
    public void Decodes_with_or_without_padding(string input, string expected)
    {
        Assert.True(Base64Url.TryDecode(input, out var bytes));
        Assert.Equal(expected, Encoding.ASCII.GetString(bytes!));
    }

    [Fact]
    public void Decodes_url_safe_alphabet()
    {
        var data = new byte[] { 0xfb, 0xff, 0xbf };
        Assert.Equal("-_-_", Base64Url.Encode(data));
        Assert.True(Base64Url.TryDecode("-_-_", out var bytes));
        Assert.Equal(data, bytes);
    }

    [Theory]
    [InlineData("Z")]           // impossible length
    [InlineData("Zm9vY")]       // impossible length
    [InlineData("Zg=")]         // wrong padding amount
    [InlineData("Zg===")]       // too much padding
    [InlineData("Zm8+")]        // standard alphabet
    [InlineData("Zm8/")]
    [InlineData("Zm 8")]        // whitespace
    [InlineData("Zm8\n")]
    [InlineData("Zm=8")]        // padding in the middle
    [InlineData(null)]
    public void Rejects_invalid_input(string? input)
    {
        Assert.False(Base64Url.TryDecode(input, out var bytes));
        Assert.Null(bytes);
    }

    [Fact]
    public void Encode_never_pads()
    {
        for (var length = 0; length < 10; length++)
        {
            var encoded = Base64Url.Encode(new byte[length]);
            Assert.DoesNotContain('=', encoded);
            Assert.True(Base64Url.TryDecode(encoded, out var decoded));
            Assert.Equal(length, decoded!.Length);
        }
    }

    [Fact]
    public void Nonce_format_is_43_char_base64url()
    {
        var nonce = Base64Url.Encode(Crypto.RandomBytes(32));
        Assert.Equal(43, nonce.Length);
        Assert.True(Base64Url.IsUnpaddedAlphabet(nonce));
    }
}

public class Ed25519VerifierTests
{
    [Fact]
    public void Accepts_the_vector_public_key()
    {
        var key = Ed25519Verifier.FromBase64(Vectors.PublicKey);
        Assert.Equal(Vectors.KeyId, key.KeyId);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not base64!")]
    [InlineData("AAAA")] // 3 bytes
    [InlineData("I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToIA")] // 33 bytes
    public void Rejects_invalid_public_keys(string key)
    {
        Assert.Throws<ArgumentException>(() => Ed25519Verifier.FromBase64(key));
    }

    [Fact]
    public void Rejects_signatures_of_wrong_length_without_throwing()
    {
        var key = Ed25519Verifier.FromBase64(Vectors.PublicKey);
        Assert.False(key.Verify(new byte[] { 1, 2, 3 }, new byte[63]));
        Assert.False(key.Verify(new byte[] { 1, 2, 3 }, new byte[65]));
        Assert.False(key.Verify(new byte[] { 1, 2, 3 }, new byte[64]));
    }

    [Fact]
    public void Verifies_signatures_from_the_matching_seed_only()
    {
        var key = Ed25519Verifier.FromBase64(Vectors.PublicKey);
        var message = Encoding.ASCII.GetBytes("hello-velsigil");
        Assert.True(Base64Url.TryDecode(TestSigner.Primary.SignAscii("hello-velsigil"), out var good));
        Assert.True(Base64Url.TryDecode(TestSigner.Wrong.SignAscii("hello-velsigil"), out var bad));
        Assert.True(key.Verify(message, good!));
        Assert.False(key.Verify(message, bad!));
        var tampered = good!.ToArray();
        tampered[10] ^= 0x01;
        Assert.False(key.Verify(message, tampered));
    }
}

public class HardwareIdTests
{
    [Fact]
    public void Normalizes_by_trimming_and_lowercasing()
    {
        Assert.Equal("abc-def", HardwareId.NormalizeMachineId("  ABC-Def\r\n\t"));
    }

    [Fact]
    public void Rejects_empty_machine_id()
    {
        Assert.Throws<ArgumentException>(() => HardwareId.FromMachineId("   \n"));
    }

    [Fact]
    public void Hwid_is_lowercase_sha256_hex()
    {
        var hwid = HardwareId.FromMachineId("4C4C4544-0042-3510-8051-B4C04F4E4B32");
        Assert.Equal(64, hwid.Length);
        Assert.True(hwid.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }

    [Fact]
    public void Machine_hwid_is_stable_when_available()
    {
        if (!HardwareId.TryGet(out var first))
        {
            // Platforms without a machine id must report it rather than invent a value.
            Assert.Throws<PlatformNotSupportedException>(() => HardwareId.Get());
            return;
        }
        Assert.Equal(first, HardwareId.Get());
        Assert.Equal(first, VelsigilClient.GetHardwareId());
        Assert.Equal(HardwareId.FromMachineId(HardwareId.ReadMachineId()!), first);
    }

    [Fact]
    public void Parses_ioreg_output()
    {
        const string output = "+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000213>\n" +
            "    {\n" +
            "      \"IOPlatformSerialNumber\" = \"C02XXXXXXX\"\n" +
            "      \"IOPlatformUUID\" = \"F3E2D1C0-B9A8-7766-5544-332211009988\"\n" +
            "    }\n";
        Assert.Equal("F3E2D1C0-B9A8-7766-5544-332211009988", HardwareId.ParseIoregPlatformUuid(output));
        Assert.Null(HardwareId.ParseIoregPlatformUuid("nothing here"));
    }

    [Fact]
    public void Linux_machine_id_skips_empty_files_and_the_systemd_placeholder()
    {
        var directory = TestClients.TempDirectory();
        var etc = System.IO.Path.Combine(directory, "machine-id");
        var dbus = System.IO.Path.Combine(directory, "dbus-machine-id");
        System.IO.File.WriteAllText(etc, "uninitialized\n");
        System.IO.File.WriteAllText(dbus, "4C4C4544004235108051B4C04F4E4B32\n");
        Assert.Equal("4C4C4544004235108051B4C04F4E4B32", HardwareId.ReadLinuxMachineId(new[] { etc, dbus })?.Trim());

        System.IO.File.WriteAllText(etc, " UNINITIALIZED \n");
        Assert.Null(HardwareId.ReadLinuxMachineId(new[] { etc }));
        System.IO.File.WriteAllText(etc, " \n");
        Assert.Null(HardwareId.ReadLinuxMachineId(new[] { etc }));
    }
}
