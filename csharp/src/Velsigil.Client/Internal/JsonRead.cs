using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text.Json;

namespace Velsigil.Client.Internal;

/// <summary>
/// Strictly-typed accessors over <see cref="JsonElement"/>. All of them return false on a type mismatch
/// so callers can fail closed. No reflection-based (de)serialisation is used anywhere in the SDK, which
/// keeps it trimming/AOT/IL2CPP friendly.
/// </summary>
internal static class JsonRead
{
    /// <summary>Largest unix time (seconds) representable by <see cref="DateTimeOffset"/> (9999-12-31).</summary>
    public const long MaxUnixSeconds = 253402300799L;

    public static readonly JsonDocumentOptions DocumentOptions = new JsonDocumentOptions
    {
        MaxDepth = 32,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
    };

    public static bool TryParse(byte[] utf8, out JsonDocument? document)
    {
        try
        {
            document = JsonDocument.Parse(utf8, DocumentOptions);
            return true;
        }
        catch (JsonException)
        {
            document = null;
            return false;
        }
        catch (ArgumentException)
        {
            // Thrown for invalid UTF-8 on some framework versions.
            document = null;
            return false;
        }
    }

    public static bool TryGetString(JsonElement obj, string name, out string value)
    {
        value = string.Empty;
        if (!obj.TryGetProperty(name, out var prop) || prop.ValueKind != JsonValueKind.String) return false;
        value = prop.GetString() ?? string.Empty;
        return true;
    }

    /// <summary>Absent or JSON null → null; string → value; anything else → false.</summary>
    public static bool TryGetOptionalString(JsonElement obj, string name, out string? value)
    {
        value = null;
        if (!obj.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null) return true;
        if (prop.ValueKind != JsonValueKind.String) return false;
        value = prop.GetString();
        return true;
    }

    public static bool TryGetBoolean(JsonElement obj, string name, out bool value)
    {
        value = false;
        if (!obj.TryGetProperty(name, out var prop)) return false;
        switch (prop.ValueKind)
        {
            case JsonValueKind.True:
                value = true;
                return true;
            case JsonValueKind.False:
                return true;
            default:
                return false;
        }
    }

    /// <summary>Absent or JSON null → false (not set); true/false → value; anything else → returns false (malformed).</summary>
    public static bool TryGetOptionalBoolean(JsonElement obj, string name, out bool value)
    {
        value = false;
        if (!obj.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null) return true;
        switch (prop.ValueKind)
        {
            case JsonValueKind.True:
                value = true;
                return true;
            case JsonValueKind.False:
                return true;
            default:
                return false;
        }
    }

    public static bool TryGetInt64(JsonElement obj, string name, out long value)
    {
        value = 0;
        return obj.TryGetProperty(name, out var prop)
            && prop.ValueKind == JsonValueKind.Number
            && prop.TryGetInt64(out value);
    }

    public static bool TryGetInt32(JsonElement obj, string name, out int value)
    {
        value = 0;
        return obj.TryGetProperty(name, out var prop)
            && prop.ValueKind == JsonValueKind.Number
            && prop.TryGetInt32(out value);
    }

    /// <summary>Unix seconds in the range DateTimeOffset can represent.</summary>
    public static bool TryGetUnixTime(JsonElement obj, string name, out long value) =>
        TryGetInt64(obj, name, out value) && value >= 0 && value <= MaxUnixSeconds;

    /// <summary>Absent or JSON null → null; unix seconds → value; anything else → false.</summary>
    public static bool TryGetOptionalUnixTime(JsonElement obj, string name, out long? value)
    {
        value = null;
        if (!obj.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null) return true;
        if (prop.ValueKind != JsonValueKind.Number || !prop.TryGetInt64(out var seconds)) return false;
        if (seconds < 0 || seconds > MaxUnixSeconds) return false;
        value = seconds;
        return true;
    }

    public static bool TryGetStringArray(JsonElement obj, string name, out IReadOnlyList<string> value)
    {
        value = Array.Empty<string>();
        if (!obj.TryGetProperty(name, out var prop) || prop.ValueKind != JsonValueKind.Array) return false;
        var items = new List<string>(prop.GetArrayLength());
        foreach (var item in prop.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) return false;
            items.Add(item.GetString() ?? string.Empty);
        }
        value = new ReadOnlyCollection<string>(items);
        return true;
    }

    /// <summary>
    /// Absent or JSON null → <paramref name="isPresent"/> false; object → <paramref name="value"/>;
    /// anything else → returns false (malformed).
    /// </summary>
    public static bool TryGetOptionalObject(JsonElement obj, string name, out JsonElement value, out bool isPresent)
    {
        value = default;
        isPresent = false;
        if (!obj.TryGetProperty(name, out var prop) || prop.ValueKind == JsonValueKind.Null) return true;
        if (prop.ValueKind != JsonValueKind.Object) return false;
        value = prop;
        isPresent = true;
        return true;
    }
}
