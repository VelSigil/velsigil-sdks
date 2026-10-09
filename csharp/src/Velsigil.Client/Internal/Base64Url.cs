using System;
using System.Diagnostics.CodeAnalysis;

namespace Velsigil.Client.Internal;

/// <summary>Base64url helpers: no padding on encode; decode accepts optional, correct padding.</summary>
internal static class Base64Url
{
    /// <summary>Encodes <paramref name="data"/> as base64url without padding.</summary>
    public static string Encode(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>True when <paramref name="c"/> belongs to the base64url alphabet (padding excluded).</summary>
    public static bool IsAlphabetChar(char c) =>
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';

    /// <summary>Non-empty and only base64url characters (no padding, no whitespace).</summary>
    public static bool IsUnpaddedAlphabet(string? value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        foreach (var c in value!)
        {
            if (!IsAlphabetChar(c)) return false;
        }
        return true;
    }

    /// <summary>Strict base64url decode; padding is optional but must be correct.</summary>
    public static bool TryDecode(string? value, [NotNullWhen(true)] out byte[]? bytes)
    {
        bytes = null;
        if (value is null) return false;

        var end = value.Length;
        var padding = 0;
        while (end > 0 && value[end - 1] == '=')
        {
            end--;
            padding++;
        }
        if (padding > 2) return false;

        for (var i = 0; i < end; i++)
        {
            if (!IsAlphabetChar(value[i])) return false;
        }

        var remainder = end % 4;
        if (remainder == 1) return false;
        var requiredPadding = remainder == 0 ? 0 : 4 - remainder;
        // Padding is optional, but when present it must be exactly right.
        if (padding != 0 && padding != requiredPadding) return false;

        var chars = new char[end + requiredPadding];
        for (var i = 0; i < end; i++)
        {
            var c = value[i];
            chars[i] = c == '-' ? '+' : c == '_' ? '/' : c;
        }
        for (var i = end; i < chars.Length; i++)
        {
            chars[i] = '=';
        }

        try
        {
            bytes = Convert.FromBase64CharArray(chars, 0, chars.Length);
            return true;
        }
        catch (FormatException)
        {
            bytes = null;
            return false;
        }
    }
}
