using System;

namespace Velsigil.Client.Internal;

/// <summary>Test-vector public keys whose private seeds are published; refused outside loopback hosts.</summary>
internal static class PublishedTestKeys
{
    /// <summary>The refusal message; the same text in every Velsigil SDK.</summary>
    public const string RefusalMessage =
        "This is the public test key from the Velsigil SDK test vectors, whose private key is published: anyone could " +
        "forge license answers for it. Use your product's public key (panel: Products > your product > Integration).";

    // Compared as decoded bytes so no other encoding can slip through.
    private static readonly byte[][] RawKeys =
    {
        Convert.FromBase64String("I8lY1RS9MwgbPMa+7xrzLkdKhAGCoMbVmRApSuJjToI="), // keys.publicKey
        Convert.FromBase64String("b/OKSQM/kKwu80PNfHkda3EM9dk1/ZmNKkQz/1azw/Q="), // keys.wrongPublicKey
    };

    /// <summary>True when <paramref name="rawKey"/> (decoded key bytes) is one of the published test keys.</summary>
    public static bool Contains(byte[] rawKey)
    {
        if (rawKey is null) return false;
        foreach (var testKey in RawKeys)
        {
            if (BytesEqual(testKey, rawKey)) return true;
        }
        return false;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (var i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
