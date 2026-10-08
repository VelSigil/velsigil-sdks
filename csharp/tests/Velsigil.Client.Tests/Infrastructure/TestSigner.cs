using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Velsigil.Client.Tests.Infrastructure;

/// <summary>Signs envelopes and leases exactly like the server (Ed25519 over the ASCII bytes of the data string).</summary>
internal sealed class TestSigner
{
    public static TestSigner Primary { get; } = new TestSigner(Vectors.PrivateSeed);

    public static TestSigner Wrong { get; } = new TestSigner(Vectors.WrongPrivateSeed);

    private readonly Ed25519PrivateKeyParameters _key;

    public TestSigner(string seedBase64)
    {
        _key = new Ed25519PrivateKeyParameters(Convert.FromBase64String(seedBase64), 0);
    }

    /// <summary>A signer with a freshly generated key: unlike the vector keys, usable with any API URL.</summary>
    public static TestSigner Random() => new TestSigner(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

    public string PublicKeyBase64 => Convert.ToBase64String(_key.GeneratePublicKey().GetEncoded());

    public static string B64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string SignAscii(string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        var signer = new Ed25519Signer();
        signer.Init(true, _key);
        signer.BlockUpdate(bytes, 0, bytes.Length);
        return B64Url(signer.GenerateSignature());
    }

    public static string EncodePayload(JsonObject payload) => B64Url(Encoding.UTF8.GetBytes(payload.ToJsonString()));

    /// <summary>A complete <c>{ data, sig, kid }</c> envelope as JSON text.</summary>
    public string Envelope(JsonObject payload, string kid = "c1e9dc98b077ab8b")
    {
        var data = EncodePayload(payload);
        return new JsonObject { ["data"] = data, ["sig"] = SignAscii(data), ["kid"] = kid }.ToJsonString();
    }

    /// <summary>An offline lease token (<c>base64url(payload).base64url(sig)</c>).</summary>
    public string LeaseToken(JsonObject payload)
    {
        var body = EncodePayload(payload);
        return body + "." + SignAscii(body);
    }
}
