using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Velsigil.Client.Internal;

/// <summary>HTTP plumbing shared by the client: bounded body reads and unsigned-error mapping.</summary>
internal static class HttpHelpers
{
    private static readonly string[] KnownUnsignedCodes =
    {
        ResultCodes.ValidationError,
        ResultCodes.IpBlocked,
        ResultCodes.UnknownProduct,
        ResultCodes.RateLimited,
        ResultCodes.InternalError,
        ResultCodes.PayloadTooLarge,
        ResultCodes.UnsupportedMediaType,
    };

    private static readonly TimeSpan MaxRetryAfter = TimeSpan.FromDays(1);

    /// <summary>Reads at most <paramref name="maxBytes"/>; null when the body is larger (never buffered).</summary>
    public static async Task<byte[]?> ReadBodyAsync(HttpContent? content, int maxBytes, CancellationToken cancellationToken)
    {
        if (content is null) return Array.Empty<byte>();
        var declared = content.Headers.ContentLength;
        if (declared.HasValue && declared.Value > maxBytes) return null;

#if NET8_0_OR_GREATER
        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#else
        using var stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (buffer.Length + read > maxBytes) return null;
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    /// <summary>Maps a non-200 response to a failure code, the same in every Velsigil SDK.</summary>
    public static string MapUnsignedErrorCode(int status, byte[]? body, out string? requestId, bool trialRequest = false)
    {
        requestId = null;
        var bodyCode = TryReadErrorBody(body, out requestId);
        if (bodyCode != null && KnownUnsignedCodes.Contains(bodyCode, StringComparer.Ordinal)) return bodyCode;
        if (trialRequest && status == 404 && string.Equals(bodyCode, "not_found", StringComparison.Ordinal)) return ResultCodes.PanelTooOld;
        var velsigilBody = bodyCode != null;

        switch (status)
        {
            case 400:
                return ResultCodes.ValidationError;
            case 413:
                return ResultCodes.PayloadTooLarge;
            case 415:
                return ResultCodes.UnsupportedMediaType;
            case 429:
                return ResultCodes.RateLimited;
            case 502:
            case 503:
            case 504:
                return velsigilBody ? ResultCodes.InternalError : ResultCodes.NetworkError;
        }
        if (status >= 500 && status <= 599) return ResultCodes.InternalError;
        return ResultCodes.InvalidResponse;
    }

    /// <summary>Fixed, SDK-defined messages for unsigned failures (unsigned text is never surfaced).</summary>
    public static string MessageFor(string code, int status)
    {
        switch (code)
        {
            case ResultCodes.ValidationError:
                return "The server rejected the request as invalid.";
            case ResultCodes.IpBlocked:
                return "Requests from this network are temporarily blocked.";
            case ResultCodes.UnknownProduct:
                return "The product is not known to the license server.";
            case ResultCodes.RateLimited:
                return "Too many requests; try again later.";
            case ResultCodes.InternalError:
                return "The license server encountered an error.";
            case ResultCodes.PayloadTooLarge:
                return "The request was too large.";
            case ResultCodes.UnsupportedMediaType:
                return "The server rejected the request content type.";
            case ResultCodes.NetworkError:
                return "The license server is unavailable (HTTP " + status.ToString(CultureInfo.InvariantCulture) + ").";
            case ResultCodes.PanelTooOld:
                return "The license server does not support starting free trials from the app yet. The seller needs to update the Velsigil panel.";
            default:
                return "Unexpected HTTP " + status.ToString(CultureInfo.InvariantCulture) + " response from the license server.";
        }
    }

    /// <summary>Parses the <c>Retry-After</c> header (delta-seconds or HTTP date), capped at one day.</summary>
    public static TimeSpan? ReadRetryAfter(HttpResponseHeaders headers, DateTimeOffset now)
    {
        var retryAfter = headers.RetryAfter;
        if (retryAfter is null) return null;
        TimeSpan? value = null;
        if (retryAfter.Delta.HasValue)
        {
            value = retryAfter.Delta.Value;
        }
        else if (retryAfter.Date.HasValue)
        {
            value = retryAfter.Date.Value - now;
        }
        if (!value.HasValue) return null;
        if (value.Value < TimeSpan.Zero) return TimeSpan.Zero;
        return value.Value > MaxRetryAfter ? MaxRetryAfter : value.Value;
    }

    /// <summary>The <c>X-Request-Id</c> header when it looks like a request id.</summary>
    public static string? ReadRequestIdHeader(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("X-Request-Id", out var values))
        {
            foreach (var value in values)
            {
                if (IsSafeRequestId(value)) return value;
            }
        }
        return null;
    }

    private static string? TryReadErrorBody(byte[]? body, out string? requestId)
    {
        requestId = null;
        if (body is null || body.Length == 0) return null;
        if (!JsonRead.TryParse(body, out var document) || document is null) return null;
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("error", out var error)
                || error.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            if (JsonRead.TryGetString(error, "requestId", out var id) && IsSafeRequestId(id)) requestId = id;
            return JsonRead.TryGetString(error, "code", out var code) ? code : null;
        }
    }

    private static bool IsSafeRequestId(string? value)
    {
        if (string.IsNullOrEmpty(value) || value!.Length > 64) return false;
        foreach (var c in value)
        {
            var ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>Request content for a JSON body (exact <c>application/json</c> media type).</summary>
    public static ByteArrayContent JsonContent(byte[] body)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }
}
