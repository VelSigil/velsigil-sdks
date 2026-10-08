using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Velsigil.Client.Internal;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

/// <summary>
/// The private keys of the two test-vector key pairs are published (sdks/test-vectors.json), so the client refuses their
/// public keys unless the API URL is loopback (the hosts plain http is allowed for), and the public LeaseVerifier.Verify
/// helper (no URL) refuses them always. The SDK's own vector tests use the internal overload that takes a decoded key.
/// </summary>
public class PublishedTestKeyTests
{
    // Same text in every Velsigil SDK.
    private const string RefusalMessage =
        "This is the public test key from the Velsigil SDK test vectors, whose private key is published: anyone could forge " +
        "license answers for it. Use your product's public key (panel: Products > your product > Integration).";

    public static IEnumerable<object[]> TestKeyEncodings()
    {
        foreach (var key in new[] { Vectors.PublicKey, Vectors.WrongPublicKey })
        {
            var raw = Convert.FromBase64String(key);
            yield return new object[] { key }; // as published (standard base64)
            yield return new object[] { Base64Url.Encode(raw) }; // base64url, unpadded
            yield return new object[] { Base64Url.Encode(raw) + "=" }; // base64url, padded
            yield return new object[] { " \t" + key + "\r\n" }; // surrounding whitespace
            yield return new object[] { WithNonZeroTrailingBits(key) }; // non-canonical: same 32 bytes
        }
    }

    public static IEnumerable<object[]> TestKeysWithRemoteUrls()
    {
        var remoteUrls = new[]
        {
            TestClients.RemoteApiUrl,
            "https://licenses.example.com/api/client/v1",
            "https://localhost.example.com", // look-alikes of the loopback names are not loopback
            "https://127.0.0.1.nip.io",
            "https://10.0.0.5:3000",
            "https://[::2]",
            "https://[::ffff:127.0.0.1]", // IPv4-mapped loopback is not in the loopback set (localhost, 127.0.0.1, ::1)
            "https://[::]",
            "https://localhost.", // trailing dot: another host name
        };
        foreach (var key in new[] { Vectors.PublicKey, Vectors.WrongPublicKey })
        {
            foreach (var url in remoteUrls) yield return new object[] { key, url };
        }
    }

    [Theory]
    [MemberData(nameof(TestKeysWithRemoteUrls))]
    public void Test_keys_are_refused_with_a_non_loopback_https_url(string key, string url)
    {
        var error = Assert.Throws<ArgumentException>(() => new VelsigilClient(url, Vectors.ProductId, key, Options()));

        Assert.Equal("publicKeyBase64", error.ParamName);
        Assert.StartsWith(RefusalMessage, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(TestKeyEncodings))]
    public void Every_encoding_of_a_test_key_is_refused(string key)
    {
        var error = Assert.Throws<ArgumentException>(() => new VelsigilClient(TestClients.RemoteApiUrl, Vectors.ProductId, key, Options()));

        Assert.Equal("publicKeyBase64", error.ParamName);
        Assert.StartsWith(RefusalMessage, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("publicKey")]
    [InlineData("wrongPublicKey")]
    public void Test_keys_are_refused_over_opted_in_plain_http_to_a_remote_host(string vectorKey)
    {
        // AllowInsecureHttp widens the transport rule only; the key rule stays loopback-only.
        var key = Vectors.Keys.GetProperty(vectorKey).GetString()!;
        var options = Options();
        options.AllowInsecureHttp = true;

        var error = Assert.Throws<ArgumentException>(() => new VelsigilClient("http://licenses.example.com", Vectors.ProductId, key, options));

        Assert.Equal("publicKeyBase64", error.ParamName);
        Assert.StartsWith(RefusalMessage, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refusal_takes_the_same_error_path_as_an_invalid_public_key()
    {
        var invalid = Assert.Throws<ArgumentException>(() => new VelsigilClient(TestClients.RemoteApiUrl, Vectors.ProductId, "AAAA", Options()));
        var refused = Assert.Throws<ArgumentException>(() => new VelsigilClient(TestClients.RemoteApiUrl, Vectors.ProductId, Vectors.PublicKey, Options()));

        Assert.Equal(invalid.GetType(), refused.GetType());
        Assert.Equal(invalid.ParamName, refused.ParamName);
        Assert.Equal(RefusalMessage, PublishedTestKeys.RefusalMessage);
    }

    [Theory]
    [InlineData("http://localhost:3000")]
    [InlineData("http://LOCALHOST:3000/licensing/")]
    [InlineData("http://127.0.0.1:3000")]
    [InlineData("http://[::1]:3000")]
    [InlineData("https://localhost")]
    [InlineData("https://127.0.0.1:8443/api/client/v1")]
    [InlineData("https://[::1]")]
    [InlineData("http://[0:0:0:0:0:0:0:1]:3000")] // ::1 spelled out (.NET Framework's Uri.Host form below)
    [InlineData("https://[0000:0000:0000:0000:0000:0000:0000:0001]")]
    public void Test_keys_are_accepted_with_a_loopback_url(string url)
    {
        foreach (var key in new[] { Vectors.PublicKey, Vectors.WrongPublicKey })
        {
            using var client = new VelsigilClient(url, Vectors.ProductId, key, Options());
            Assert.Equal(Crypto.ToHex(Crypto.Sha256(Convert.FromBase64String(key))).Substring(0, 16), client.KeyId);
        }
    }

    [Theory]
    [MemberData(nameof(TestKeyEncodings))]
    public void Every_encoding_of_a_test_key_is_accepted_with_a_loopback_url(string key)
    {
        using var client = new VelsigilClient("http://127.0.0.1:3000", Vectors.ProductId, key, Options());
        Assert.NotEmpty(client.KeyId);
    }

    [Theory]
    [InlineData("https://licenses.example.com")]
    [InlineData("https://example.com/licensing/")]
    [InlineData("https://10.0.0.5:3000")]
    public void A_real_key_is_accepted_with_a_non_loopback_url(string url)
    {
        var signer = TestSigner.Random();

        using var client = new VelsigilClient(url, Vectors.ProductId, signer.PublicKeyBase64, Options());

        Assert.Equal(Crypto.ToHex(Crypto.Sha256(Convert.FromBase64String(signer.PublicKeyBase64))).Substring(0, 16), client.KeyId);
    }

    [Fact]
    public void A_key_one_bit_away_from_a_test_key_is_not_refused()
    {
        foreach (var testKey in new[] { Vectors.PublicKey, Vectors.WrongPublicKey })
        {
            // Flip bits until the result is a valid Ed25519 public key (not every 32-byte string is a curve point).
            var raw = Convert.FromBase64String(testKey);
            Ed25519Verifier? neighbour = null;
            for (var bit = 0; bit < 8 * raw.Length && neighbour is null; bit++)
            {
                var candidate = (byte[])raw.Clone();
                candidate[bit / 8] ^= (byte)(1 << (bit % 8));
                try
                {
                    neighbour = Ed25519Verifier.FromBase64(Convert.ToBase64String(candidate));
                }
                catch (ArgumentException)
                {
                    // Not a valid point: try the next bit.
                }
            }

            Assert.NotNull(neighbour);
            Assert.False(neighbour!.IsPublishedTestKey);
        }
    }

    [Fact]
    public void Verifier_flags_exactly_the_two_vector_keys()
    {
        Assert.True(Ed25519Verifier.FromBase64(Vectors.PublicKey).IsPublishedTestKey);
        Assert.True(Ed25519Verifier.FromBase64(Vectors.WrongPublicKey).IsPublishedTestKey);
        Assert.False(Ed25519Verifier.FromBase64(TestSigner.Random().PublicKeyBase64).IsPublishedTestKey);
        Assert.False(PublishedTestKeys.Contains(new byte[32]));
        Assert.False(PublishedTestKeys.Contains(Convert.FromBase64String(Vectors.PublicKey).Take(31).ToArray()));
    }

    // ---- The public low-level helper LeaseVerifier.Verify(token, publicKeyBase64, ...) has no API URL, so there is no
    // loopback exception: it refuses the test keys for every caller.

    [Theory]
    [MemberData(nameof(TestKeyEncodings))]
    public void Public_lease_verifier_refuses_every_encoding_of_a_test_key(string key)
    {
        var error = Assert.Throws<ArgumentException>(() => LeaseVerifier.Verify(Vectors.ValidLeaseToken, key, Vectors.ProductId,
            Vectors.TestHwid, DateTimeOffset.FromUnixTimeSeconds(Vectors.LeaseIssuedAt + 60)));

        Assert.Equal("publicKeyBase64", error.ParamName);
        Assert.StartsWith(RefusalMessage, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("lease_ok", "publicKey")]
    [InlineData("lease_wrong_key", "wrongPublicKey")]
    public void Public_lease_verifier_refuses_both_test_keys_even_for_leases_they_signed(string leaseName, string vectorKey)
    {
        var vector = Vectors.Lease(leaseName);
        var key = Vectors.Keys.GetProperty(vectorKey).GetString()!;
        var now = DateTimeOffset.FromUnixTimeSeconds(vector.GetProperty("now").GetInt64());

        var error = Assert.Throws<ArgumentException>(() =>
            LeaseVerifier.Verify(vector.GetProperty("token").GetString(), key, Vectors.ProductId, Vectors.TestHwid, now));
        Assert.Equal("publicKeyBase64", error.ParamName);
        Assert.StartsWith(RefusalMessage, error.Message, StringComparison.Ordinal);

        // The key is checked before the token is looked at: no token, no lease, still refused.
        Assert.Throws<ArgumentException>(() => LeaseVerifier.Verify(null, key, Vectors.ProductId, Vectors.TestHwid, now));
    }

    [Fact]
    public void Public_lease_verifier_refusal_takes_the_same_error_path_as_an_invalid_public_key()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(Vectors.LeaseIssuedAt + 60);
        var invalid = Assert.Throws<ArgumentException>(() => LeaseVerifier.Verify(Vectors.ValidLeaseToken, "AAAA", Vectors.ProductId, Vectors.TestHwid, now));
        var refused = Assert.Throws<ArgumentException>(() => LeaseVerifier.Verify(Vectors.ValidLeaseToken, Vectors.PublicKey, Vectors.ProductId, Vectors.TestHwid, now));
        var client = Assert.Throws<ArgumentException>(() => new VelsigilClient(TestClients.RemoteApiUrl, Vectors.ProductId, Vectors.PublicKey, Options()));

        Assert.Equal(invalid.GetType(), refused.GetType());
        Assert.Equal(invalid.ParamName, refused.ParamName);
        Assert.Equal(client.Message, refused.Message); // same text as the constructor guard
    }

    [Fact]
    public void Public_lease_verifier_accepts_a_real_key()
    {
        // The vector lease body re-signed with a freshly generated key: valid through the public helper.
        var signer = TestSigner.Random();
        var body = Vectors.ValidLeaseToken.Substring(0, Vectors.ValidLeaseToken.IndexOf('.'));
        var token = body + "." + signer.SignAscii(body);

        var result = LeaseVerifier.Verify(token, signer.PublicKeyBase64, Vectors.ProductId, Vectors.TestHwid,
            DateTimeOffset.FromUnixTimeSeconds(Vectors.LeaseIssuedAt + 60));

        Assert.Equal(LeaseStatus.Valid, result.Status);
        Assert.Equal(LeaseStatus.InvalidSignature, LeaseVerifier.Verify(Vectors.ValidLeaseToken, signer.PublicKeyBase64, Vectors.ProductId,
            Vectors.TestHwid, DateTimeOffset.FromUnixTimeSeconds(Vectors.LeaseIssuedAt + 60)).Status);
    }

    [Fact]
    public void Internal_lease_verifier_still_verifies_the_vectors_with_the_test_keys()
    {
        var ok = LeaseVerifier.Verify(Vectors.ValidLeaseToken, Ed25519Verifier.FromBase64(Vectors.PublicKey), Vectors.ProductId,
            Vectors.TestHwid, DateTimeOffset.FromUnixTimeSeconds(Vectors.LeaseIssuedAt + 60));
        Assert.Equal(LeaseStatus.Valid, ok.Status);

        var wrongKeyLease = Vectors.Lease("lease_wrong_key");
        var underWrongKey = LeaseVerifier.Verify(wrongKeyLease.GetProperty("token").GetString(), Ed25519Verifier.FromBase64(Vectors.WrongPublicKey),
            Vectors.ProductId, Vectors.TestHwid, DateTimeOffset.FromUnixTimeSeconds(wrongKeyLease.GetProperty("now").GetInt64()));
        Assert.Equal(LeaseStatus.Valid, underWrongKey.Status);
    }

    [Fact]
    public void The_unguarded_path_is_not_public()
    {
        // No public opt-out: the only public Verify takes the key as base64 (guarded), and the decoded-key type is internal.
        var publicVerify = typeof(LeaseVerifier).GetMethods(BindingFlags.Public | BindingFlags.Static).Where(m => m.Name == "Verify").ToArray();
        Assert.Single(publicVerify);
        Assert.Equal(typeof(string), publicVerify[0].GetParameters()[1].ParameterType);
        Assert.False(typeof(Ed25519Verifier).IsVisible);
        Assert.False(typeof(PublishedTestKeys).IsVisible);
    }

    private static VelsigilClientOptions Options() =>
        new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid };

    // Standard base64 of 32 bytes ends in one character carrying 4 data bits and 2 unused bits ("X=" with the unused
    // bits zero). Setting the lowest unused bit gives another string that decodes to the same 32 bytes.
    private static string WithNonZeroTrailingBits(string key)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var last = key.Length - 2; // key ends in "X="
        var value = Alphabet.IndexOf(key[last]);
        var variant = key.Substring(0, last) + Alphabet[value | 1] + key.Substring(last + 1);
        if (variant == key || !Convert.FromBase64String(variant).SequenceEqual(Convert.FromBase64String(key)))
        {
            throw new InvalidOperationException("Test setup: the variant must be a different encoding of the same bytes.");
        }
        return variant;
    }
}
