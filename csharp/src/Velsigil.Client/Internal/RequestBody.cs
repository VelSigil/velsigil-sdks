using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Velsigil.Client.Internal;

/// <summary>
/// Builds the JSON request body. Optional fields are omitted entirely when null (the server's schemas
/// are strict); <c>nonce</c> and <c>timestamp</c> are appended per attempt so a retry is a fresh request.
/// </summary>
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
