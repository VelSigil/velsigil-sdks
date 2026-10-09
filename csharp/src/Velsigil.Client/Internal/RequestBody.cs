using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Velsigil.Client.Internal;

/// <summary>JSON request body; null fields are omitted because the server schemas are strict.</summary>
internal sealed class RequestBody
{
    private readonly List<KeyValuePair<string, string>> _fields = new List<KeyValuePair<string, string>>();

    public RequestBody Add(string name, string? value)
    {
        if (value != null) _fields.Add(new KeyValuePair<string, string>(name, value));
        return this;
    }

    public byte[] Build(string nonce, long timestamp)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var field in _fields)
            {
                writer.WriteString(field.Key, field.Value);
            }
            writer.WriteString("nonce", nonce);
            writer.WriteNumber("timestamp", timestamp);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }
}
