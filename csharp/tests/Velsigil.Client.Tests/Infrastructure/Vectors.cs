using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Velsigil.Client.Tests.Infrastructure;

/// <summary>Access to sdks/test-vectors.json (linked into the test output directory).</summary>
internal static class Vectors
{
    public const string ProductId = "0b9f4c1e-8d6a-4f7e-9c3b-2a1d5e6f7a8b";
    public const string TestHwid = "test-hwid-0001-abcdef";

    private static readonly Lazy<JsonDocument> Document = new Lazy<JsonDocument>(() =>
        JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "test-vectors.json"))));

    public static JsonElement Root => Document.Value.RootElement;

    public static JsonElement Keys => Root.GetProperty("keys");

    public static string PublicKey => Keys.GetProperty("publicKey").GetString()!;

    public static string WrongPublicKey => Keys.GetProperty("wrongPublicKey").GetString()!;

    public static string PrivateSeed => Keys.GetProperty("privateSeedBase64").GetString()!;

    public static string WrongPrivateSeed => Keys.GetProperty("wrongPrivateSeedBase64").GetString()!;

    public static string KeyId => Keys.GetProperty("keyId").GetString()!;

    public static JsonElement Envelope(string name) =>
        Root.GetProperty("envelopes").EnumerateArray().Single(e => e.GetProperty("name").GetString() == name);

    /// <summary>The hwid a device-bound envelope vector answers (its optional "hwid" field), else null.</summary>
    public static string? RequestHwid(JsonElement envelopeVector) =>
        envelopeVector.TryGetProperty("hwid", out var hwid) ? hwid.GetString() : null;

    /// <summary>The endpoint an envelope vector answers (its "requestType" field).</summary>
    public static string RequestType(JsonElement envelopeVector) => envelopeVector.GetProperty("requestType").GetString()!;

    public static JsonElement Lease(string name) =>
        Root.GetProperty("leases").EnumerateArray().Single(e => e.GetProperty("name").GetString() == name);

    public static IEnumerable<object[]> EnvelopeNames() =>
        Root.GetProperty("envelopes").EnumerateArray().Select(e => new object[] { e.GetProperty("name").GetString()! }).ToList();

    public static IEnumerable<object[]> LeaseNames() =>
        Root.GetProperty("leases").EnumerateArray().Select(e => new object[] { e.GetProperty("name").GetString()! }).ToList();

    public static IEnumerable<object[]> HwidExampleIndexes() =>
        Enumerable.Range(0, Root.GetProperty("hwid").GetProperty("examples").GetArrayLength()).Select(i => new object[] { i }).ToList();

    /// <summary>The token of the valid lease vector (exp 1767312000, features pro/export).</summary>
    public static string ValidLeaseToken => Lease("lease_ok").GetProperty("token").GetString()!;

    public const long LeaseIssuedAt = 1767225600;
    public const long LeaseExpiresAt = 1767312000;
}
