using System;
using System.Security.Cryptography;
using System.Text;

namespace Velsigil.Client.Internal;

/// <summary>Hashing and encoding helpers for netstandard2.0 and net8.0.</summary>
internal static class Crypto
{
    private static readonly char[] HexDigits = "0123456789abcdef".ToCharArray();

    /// <summary>Lowercase hexadecimal encoding.</summary>
    public static string ToHex(byte[] data)
    {
        var chars = new char[data.Length * 2];
        for (var i = 0; i < data.Length; i++)
        {
            chars[i * 2] = HexDigits[data[i] >> 4];
            chars[(i * 2) + 1] = HexDigits[data[i] & 0x0F];
        }
        return new string(chars);
    }

    public static byte[] Sha256(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    /// <summary>Lowercase hex SHA-256 of the UTF-8 bytes of <paramref name="text"/>.</summary>
    public static string Sha256Hex(string text) => ToHex(Sha256(Encoding.UTF8.GetBytes(text)));

    /// <summary>Fills a new array with <paramref name="count"/> bytes from the OS CSPRNG.</summary>
    public static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return bytes;
    }

    /// <summary>True when <paramref name="value"/> is exactly 64 hexadecimal characters.</summary>
    public static bool IsSha256Hex(string value)
    {
        if (value.Length != 64) return false;
        foreach (var c in value)
        {
            var isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex) return false;
        }
        return true;
    }

    /// <summary>Constant-time, case-insensitive comparison of two hex strings.</summary>
    public static bool HexEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++)
        {
            diff |= char.ToLowerInvariant(a[i]) ^ char.ToLowerInvariant(b[i]);
        }
        return diff == 0;
    }
}
