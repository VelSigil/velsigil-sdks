using System;
using System.Net.Http;
using Velsigil.Client.Storage;

namespace Velsigil.Client;

/// <summary>Optional settings for <see cref="VelsigilClient"/>. Values are copied when the client is created.</summary>
public sealed class VelsigilClientOptions
{
    /// <summary>Per-request timeout (default 15 s, 1 s to 10 min); for downloads also the inactivity timeout.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Overrides the hardware id (8..256 characters). Keep it stable: a new value is a new device.</summary>
    public string? HardwareId { get; set; }

    /// <summary>Where the device secret and lease are stored. Default: a per-user <see cref="FileStore"/>.</summary>
    public IVelsigilStore? Store { get; set; }

    /// <summary>Allows plain <c>http://</c> to non-loopback hosts. Never enable in production.</summary>
    public bool AllowInsecureHttp { get; set; }

    /// <summary>
    /// An externally owned <see cref="System.Net.Http.HttpClient"/>; the client never disposes it.
    /// Build it with <c>AllowAutoRedirect = false</c>, or a redirect re-sends the license key elsewhere.
    /// </summary>
    public HttpClient? HttpClient { get; set; }

    /// <summary>Clock used for request timestamps and offline lease expiry. Default: system UTC clock.</summary>
    public Func<DateTimeOffset>? Clock { get; set; }

    /// <summary>Called when the store fails to read or write; store failures never fail a validation.</summary>
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

    /// <summary>The customer's e-mail (max 254 chars), used only when the trial offer confirms an address.</summary>
    public string? Email { get; set; }
}
