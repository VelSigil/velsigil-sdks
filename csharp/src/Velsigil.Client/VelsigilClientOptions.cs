using System;
using System.Net.Http;
using Velsigil.Client.Storage;

namespace Velsigil.Client;

/// <summary>Optional settings for <see cref="VelsigilClient"/>. Values are copied when the client is created.</summary>
public sealed class VelsigilClientOptions
{
    /// <summary>
    /// Per-request timeout (default 15 s, allowed range 1 s to 10 min). For file downloads it is applied
    /// to the response headers and as an inactivity timeout between reads.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Overrides the hardware id sent to the server (8..256 characters). By default the SDK derives it
    /// from the OS machine id (<see cref="Velsigil.Client.HardwareId.Get"/>). Use a stable value: changing it makes
    /// the server see a new device.
    /// </summary>
    public string? HardwareId { get; set; }

    /// <summary>
    /// Where the device secret and offline lease are persisted. Default: a <see cref="FileStore"/> in
    /// the per-user application data directory (falls back to <see cref="MemoryStore"/> when no such
    /// directory exists).
    /// </summary>
    public IVelsigilStore? Store { get; set; }

    /// <summary>
    /// Allows plain <c>http://</c> to hosts other than localhost / 127.0.0.1 / ::1. Never enable this in
    /// production: license keys and device secrets would travel in clear text.
    /// </summary>
    public bool AllowInsecureHttp { get; set; }

    /// <summary>
    /// An externally owned <see cref="System.Net.Http.HttpClient"/> (proxies, certificate pinning, Unity
    /// handlers...). The client never disposes it. When null the SDK creates its own client with
    /// redirects and cookies disabled.
    /// <para>
    /// Build an injected client on a handler with <c>AllowAutoRedirect = false</c> (the .NET default is
    /// <c>true</c>). The SDK rejects any answer that does not come from the URI it requested
    /// (<c>invalid_response</c>, or <c>download_failed</c> for downloads), but a handler that follows a
    /// 307/308 redirect has already re-sent the request body (license key, device secret) to the new
    /// location by then.
    /// </para>
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>Clock used for request timestamps and offline lease expiry. Default: system UTC clock.</summary>
    public Func<DateTimeOffset>? Clock { get; set; }

    /// <summary>
    /// Invoked (never with secrets in the message) when the store fails to read or write. Store failures
    /// never fail a validation; without persistence the device secret is simply not remembered.
    /// </summary>
    public Action<Exception>? StoreErrorHandler { get; set; }
}

/// <summary>Optional parameters for <see cref="VelsigilClient.ValidateAsync"/>.</summary>
public sealed class ValidateOptions
{
    /// <summary>The running application version (max 32 chars); enables minimum-version enforcement and update info.</summary>
    public string? Version { get; set; }

    /// <summary>A human-friendly device name shown to the seller and customer (max 255 chars).</summary>
    public string? DeviceName { get; set; }
}

/// <summary>Per-call options of <see cref="VelsigilClient.StartTrialAsync"/>.</summary>
public sealed class StartTrialOptions
{
    /// <summary>The running application version (max 32 chars).</summary>
    public string? Version { get; set; }

    /// <summary>A human-friendly device name shown to the seller and customer (max 255 chars).</summary>
    public string? DeviceName { get; set; }

    /// <summary>
    /// The customer's e-mail address (max 254 chars). Sent only when set, and read only when the seller's trial
    /// offer confirms an address first: the answer is then <see cref="ResultCodes.TrialConfirmationSent"/> and the
    /// key arrives by e-mail.
    /// </summary>
    public string? Email { get; set; }
}
