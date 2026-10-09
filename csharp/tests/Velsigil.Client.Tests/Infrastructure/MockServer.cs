using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Velsigil.Client.Tests.Infrastructure;

/// <summary>A captured client request.</summary>
internal sealed class MockRequest
{
    public MockRequest(HttpMethod method, Uri uri, string? body, IReadOnlyDictionary<string, string> headers)
    {
        Method = method;
        Uri = uri;
        Body = body;
        Headers = headers;
        if (!string.IsNullOrEmpty(body) && body.TrimStart().StartsWith("{", StringComparison.Ordinal))
        {
            Json = JsonNode.Parse(body) as JsonObject;
        }
    }

    public HttpMethod Method { get; }

    public Uri Uri { get; }

    public string Path => Uri.AbsolutePath;

    public string? Body { get; }

    public JsonObject? Json { get; }

    public IReadOnlyDictionary<string, string> Headers { get; }

    public string Nonce => Json!["nonce"]!.GetValue<string>();

    public long Timestamp => Json!["timestamp"]!.GetValue<long>();

    public bool Has(string field) => Json != null && Json.ContainsKey(field);

    public string? Field(string field) => Json != null && Json.TryGetPropertyValue(field, out var node) ? node?.GetValue<string>() : null;
}

/// <summary>In-process stand-in for the server: records requests and answers through a test handler.</summary>
internal sealed class MockServer : HttpMessageHandler
{
    private readonly List<MockRequest> _requests = new List<MockRequest>();

    public Func<MockRequest, CancellationToken, Task<HttpResponseMessage>> Handler { get; set; } =
        (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

    public IReadOnlyList<MockRequest> Requests
    {
        get
        {
            lock (_requests)
            {
                return _requests.ToArray();
            }
        }
    }

    public void Respond(Func<MockRequest, HttpResponseMessage> handler) => Handler = (request, _) => Task.FromResult(handler(request));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        if (request.Content != null)
        {
            foreach (var header in request.Content.Headers) headers[header.Key] = string.Join(",", header.Value);
        }

        var captured = new MockRequest(request.Method, request.RequestUri!, body, headers);
        lock (_requests)
        {
            _requests.Add(captured);
        }
        return await Handler(captured, cancellationToken);
    }
}

/// <summary>Builders for server responses.</summary>
internal static class Responses
{
    public static HttpResponseMessage Json(int status, string json, params (string Name, string Value)[] headers)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
        foreach (var (name, value) in headers) response.Headers.TryAddWithoutValidation(name, value);
        return response;
    }

    public static HttpResponseMessage Text(int status, string text, string mediaType = "text/html") =>
        new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(text, Encoding.UTF8, mediaType) };

    /// <summary>A response with an empty body (<c>Content-Length: 0</c>, no content type).</summary>
    public static HttpResponseMessage Empty(int status, params (string Name, string Value)[] headers)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new ByteArrayContent(Array.Empty<byte>()) };
        foreach (var (name, value) in headers) response.Headers.TryAddWithoutValidation(name, value);
        return response;
    }

    public static HttpResponseMessage Signed(JsonObject payload, TestSigner? signer = null) =>
        Json(200, (signer ?? TestSigner.Primary).Envelope(payload));

    public static HttpResponseMessage Error(int status, string code, string requestId = "11111111-2222-4333-8444-555555555555", params (string Name, string Value)[] headers) =>
        Json(status, new JsonObject
        {
            ["error"] = new JsonObject { ["code"] = code, ["message"] = "Server says: " + code, ["requestId"] = requestId },
        }.ToJsonString(), headers);
}

/// <summary>Builders for signed payload objects.</summary>
internal static class Payloads
{
    public const long ServerTime = 1767225600;
    public const string DeviceSecret = "dsk_Xq3vR9mT2pL8wN5kJ7hG4fD1sA6zC0bV9yU2iO3eW4r";

    public static string TypeFor(MockRequest request) => request.Path.Split('/').Last() switch
    {
        "validate" => "validate",
        "deactivate" => "deactivate",
        "update-check" => "update_check",
        "download" => "download",
        var other => other,
    };

    public static JsonObject Base(MockRequest request, bool ok, string code, string message = "Message.", long serverTime = ServerTime) => new JsonObject
    {
        ["v"] = 1,
        ["type"] = TypeFor(request),
        ["ok"] = ok,
        ["code"] = code,
        ["message"] = message,
        ["nonce"] = request.Nonce,
        ["requestId"] = "3f2e1d0c-9b8a-4765-a432-10fedcba9876",
        ["serverTime"] = serverTime,
        ["productId"] = Vectors.ProductId,
        ["license"] = null,
        ["activation"] = null,
        ["lease"] = null,
        ["update"] = null,
    };

    public static JsonObject License(string status = "active", long? expiresAt = 1769817600, params string[] features) => new JsonObject
    {
        ["id"] = "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
        ["plan"] = "Monthly",
        ["status"] = status,
        ["features"] = new JsonArray((features.Length == 0 ? new[] { "pro", "export" } : features).Select(f => (JsonNode?)JsonValue.Create(f)).ToArray()),
        ["expiresAt"] = expiresAt,
        ["maxDevices"] = 2,
        ["devicesUsed"] = 1,
        ["createdAt"] = 1767139200,
    };

    public static JsonObject Activation(string? deviceSecret) => new JsonObject
    {
        ["id"] = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d",
        ["status"] = "active",
        ["firstSeenAt"] = ServerTime,
        ["deviceSecret"] = deviceSecret,
    };

    public static JsonObject Lease(string token, long expiresAt) => new JsonObject { ["token"] = token, ["expiresAt"] = expiresAt };

    public static JsonObject Update(string latest = "1.4.0", bool available = true, bool mandatory = false) => new JsonObject
    {
        ["latestVersion"] = latest,
        ["minVersion"] = "1.0.0",
        ["updateAvailable"] = available,
        ["mandatory"] = mandatory,
        ["changelog"] = "Bug fixes and improvements.",
    };

    /// <summary>A successful validate payload carrying the vector lease and (optionally) a new device secret.</summary>
    public static JsonObject ValidateOk(MockRequest request, string? newDeviceSecret = DeviceSecret, long serverTime = ServerTime)
    {
        var payload = Base(request, true, "ok", "License is valid.", serverTime);
        payload["license"] = License();
        payload["activation"] = Activation(newDeviceSecret);
        payload["lease"] = Lease(Vectors.ValidLeaseToken, Vectors.LeaseExpiresAt);
        payload["update"] = Update();
        return payload;
    }
}

/// <summary>A controllable clock.</summary>
internal sealed class FakeClock
{
    public FakeClock(long unixSeconds) => Now = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

    public DateTimeOffset Now { get; set; }

    public DateTimeOffset GetNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}
