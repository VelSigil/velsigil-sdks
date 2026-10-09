using System;
using System.Collections.Generic;

namespace Velsigil.Client;

/// <summary>License status values reported by the server (<see cref="LicenseInfo.Status"/>).</summary>
public static class LicenseStatuses
{
    /// <summary>Created but never activated.</summary>
    public const string Pending = "pending";

    /// <summary>Activated and usable.</summary>
    public const string Active = "active";

    /// <summary>Temporarily suspended by the seller.</summary>
    public const string Suspended = "suspended";

    /// <summary>Past its expiry date.</summary>
    public const string Expired = "expired";

    /// <summary>Permanently revoked (for example after a refund).</summary>
    public const string Revoked = "revoked";

    /// <summary>Permanently banned for abuse.</summary>
    public const string Banned = "banned";
}

/// <summary>License details from a signed server response.</summary>
/// <remarks>On a failed result <see cref="Features"/> is informational; gate features with <see cref="VelsigilResult.HasFeature"/>.</remarks>
public sealed class LicenseInfo
{
    private readonly bool _granted;

    internal LicenseInfo(
        string id,
        string plan,
        string status,
        IReadOnlyList<string> features,
        long? expiresAtUnix,
        int maxDevices,
        int devicesUsed,
        long createdAtUnix,
        bool granted,
        bool isTrial = false,
        string? trialRef = null)
    {
        Id = id;
        Plan = plan;
        Status = status;
        Features = features;
        ExpiresAtUnix = expiresAtUnix;
        MaxDevices = maxDevices;
        DevicesUsed = devicesUsed;
        CreatedAtUnix = createdAtUnix;
        _granted = granted;
        IsTrial = isTrial;
        TrialRef = trialRef;
    }

    /// <summary>True for a free-trial license; a purchase with the same e-mail turns it false.</summary>
    public bool IsTrial { get; }

    /// <summary>Opaque reference a purchase uses to convert this trial; see <see cref="VelsigilResult.TrialRef"/>.</summary>
    public string? TrialRef { get; }

    /// <summary>License id (UUID).</summary>
    public string Id { get; }

    /// <summary>Plan name.</summary>
    public string Plan { get; }

    /// <summary>Server-side status; see <see cref="LicenseStatuses"/>.</summary>
    public string Status { get; }

    /// <summary>Feature flags granted by the license (plan features or per-license override).</summary>
    public IReadOnlyList<string> Features { get; }

    /// <summary>Expiry as unix seconds, or null for a lifetime license (or one whose term has not started).</summary>
    public long? ExpiresAtUnix { get; }

    /// <summary>Expiry as a UTC timestamp, or null for a lifetime license.</summary>
    public DateTimeOffset? ExpiresAt => ExpiresAtUnix.HasValue ? DateTimeOffset.FromUnixTimeSeconds(ExpiresAtUnix.Value) : (DateTimeOffset?)null;

    /// <summary>True when the license has no expiry date.</summary>
    public bool IsLifetime => !ExpiresAtUnix.HasValue;

    /// <summary>Maximum number of devices that may be activated.</summary>
    public int MaxDevices { get; }

    /// <summary>Number of devices currently activated.</summary>
    public int DevicesUsed { get; }

    /// <summary>Creation time as unix seconds.</summary>
    public long CreatedAtUnix { get; }

    /// <summary>Creation time as a UTC timestamp.</summary>
    public DateTimeOffset CreatedAt => DateTimeOffset.FromUnixTimeSeconds(CreatedAtUnix);

    /// <summary>True only for an ok, active or pending license that lists <paramref name="name"/>.</summary>
    public bool HasFeature(string name) =>
        _granted
        && (string.Equals(Status, LicenseStatuses.Active, StringComparison.Ordinal) || string.Equals(Status, LicenseStatuses.Pending, StringComparison.Ordinal))
        && FeatureList.Contains(Features, name);
}

/// <summary>The server-side device record (activation) for this machine.</summary>
public sealed class ActivationInfo
{
    internal ActivationInfo(string id, string status, long firstSeenAtUnix, bool deviceSecretIssued)
    {
        Id = id;
        Status = status;
        FirstSeenAtUnix = firstSeenAtUnix;
        DeviceSecretIssued = deviceSecretIssued;
    }

    /// <summary>Activation (device) id (UUID).</summary>
    public string Id { get; }

    /// <summary><c>active</c> or <c>revoked</c>.</summary>
    public string Status { get; }

    /// <summary>First time the server saw this device, unix seconds.</summary>
    public long FirstSeenAtUnix { get; }

    /// <summary>First time the server saw this device.</summary>
    public DateTimeOffset FirstSeenAt => DateTimeOffset.FromUnixTimeSeconds(FirstSeenAtUnix);

    /// <summary>True when this response issued a new device secret (already stored, never exposed).</summary>
    public bool DeviceSecretIssued { get; }
}

/// <summary>An offline lease token returned by a successful validation.</summary>
public sealed class LeaseInfo
{
    internal LeaseInfo(string token, long expiresAtUnix)
    {
        Token = token;
        ExpiresAtUnix = expiresAtUnix;
    }

    /// <summary>The signed lease token (<c>base64url(payload).base64url(signature)</c>).</summary>
    public string Token { get; }

    /// <summary>Lease expiry, unix seconds.</summary>
    public long ExpiresAtUnix { get; }

    /// <summary>Lease expiry.</summary>
    public DateTimeOffset ExpiresAt => DateTimeOffset.FromUnixTimeSeconds(ExpiresAtUnix);
}

/// <summary>Verified claims of an offline lease (see <see cref="LeaseVerifier"/>).</summary>
/// <remarks>Claims of an expired or mismatched lease are diagnostics; <see cref="HasFeature"/> is then false.</remarks>
public sealed class LeaseClaims
{
    private readonly bool _valid;

    internal LeaseClaims(
        string productId,
        string licenseId,
        string activationId,
        string hwidHash,
        string plan,
        IReadOnlyList<string> features,
        long? licenseExpiresAtUnix,
        long issuedAtUnix,
        long expiresAtUnix,
        bool valid,
        bool isTrial = false)
    {
        _valid = valid;
        IsTrial = isTrial;
        ProductId = productId;
        LicenseId = licenseId;
        ActivationId = activationId;
        HwidHash = hwidHash;
        Plan = plan;
        Features = features;
        LicenseExpiresAtUnix = licenseExpiresAtUnix;
        IssuedAtUnix = issuedAtUnix;
        ExpiresAtUnix = expiresAtUnix;
    }

    /// <summary>Product id the lease was issued for.</summary>
    public string ProductId { get; }

    /// <summary>License id.</summary>
    public string LicenseId { get; }

    /// <summary>Activation (device) id.</summary>
    public string ActivationId { get; }

    /// <summary>Lowercase hex SHA-256 of the hardware id the lease is bound to.</summary>
    public string HwidHash { get; }

    /// <summary>Plan name.</summary>
    public string Plan { get; }

    /// <summary>Feature flags at issue time.</summary>
    public IReadOnlyList<string> Features { get; }

    /// <summary>True when the lease belongs to a free-trial license.</summary>
    public bool IsTrial { get; }

    /// <summary>License expiry at issue time (unix seconds), or null for a lifetime license.</summary>
    public long? LicenseExpiresAtUnix { get; }

    /// <summary>License expiry at issue time, or null for a lifetime license.</summary>
    public DateTimeOffset? LicenseExpiresAt => LicenseExpiresAtUnix.HasValue ? DateTimeOffset.FromUnixTimeSeconds(LicenseExpiresAtUnix.Value) : (DateTimeOffset?)null;

    /// <summary>Issue time, unix seconds.</summary>
    public long IssuedAtUnix { get; }

    /// <summary>Issue time.</summary>
    public DateTimeOffset IssuedAt => DateTimeOffset.FromUnixTimeSeconds(IssuedAtUnix);

    /// <summary>Lease expiry, unix seconds.</summary>
    public long ExpiresAtUnix { get; }

    /// <summary>Lease expiry.</summary>
    public DateTimeOffset ExpiresAt => DateTimeOffset.FromUnixTimeSeconds(ExpiresAtUnix);

    /// <summary>True only for a valid lease that lists <paramref name="name"/> (ordinal comparison).</summary>
    public bool HasFeature(string name) => _valid && FeatureList.Contains(Features, name);
}

/// <summary>Release information returned by validation and update checks.</summary>
public sealed class UpdateInfo
{
    internal UpdateInfo(string latestVersion, string? minVersion, bool updateAvailable, bool mandatory, string changelog)
    {
        LatestVersion = latestVersion;
        MinVersion = minVersion;
        UpdateAvailable = updateAvailable;
        Mandatory = mandatory;
        Changelog = changelog;
    }

    /// <summary>Latest published version.</summary>
    public string LatestVersion { get; }

    /// <summary>Minimum supported version, if the seller configured one.</summary>
    public string? MinVersion { get; }

    /// <summary>True when <see cref="LatestVersion"/> is newer than the version sent in the request.</summary>
    public bool UpdateAvailable { get; }

    /// <summary>True when the update must be installed (mandatory release or below the minimum version).</summary>
    public bool Mandatory { get; }

    /// <summary>Release notes (plain text).</summary>
    public string Changelog { get; }
}

/// <summary>A short-lived download grant returned by <see cref="VelsigilClient.GetDownloadAsync"/>.</summary>
public sealed class DownloadInfo
{
    internal DownloadInfo(string url, long expiresAtUnix, string fileName, long size, string sha256, string version)
    {
        Url = url;
        ExpiresAtUnix = expiresAtUnix;
        FileName = fileName;
        Size = size;
        Sha256 = sha256;
        Version = version;
    }

    /// <summary>Download URL (absolute, or relative to the server origin). Treat it as a short-lived secret.</summary>
    public string Url { get; }

    /// <summary>Link expiry, unix seconds.</summary>
    public long ExpiresAtUnix { get; }

    /// <summary>Link expiry.</summary>
    public DateTimeOffset ExpiresAt => DateTimeOffset.FromUnixTimeSeconds(ExpiresAtUnix);

    /// <summary>Server-sanitised file name. Still validate it before using it as a local path.</summary>
    public string FileName { get; }

    /// <summary>File size in bytes.</summary>
    public long Size { get; }

    /// <summary>Lowercase hex SHA-256 of the file (signed by the server).</summary>
    public string Sha256 { get; }

    /// <summary>Release version.</summary>
    public string Version { get; }

    /// <inheritdoc />
    public override string ToString() => $"DownloadInfo(Version={Version}, FileName={FileName}, Size={Size})";
}

internal static class FeatureList
{
    public static bool Contains(IReadOnlyList<string> features, string name)
    {
        if (name is null) return false;
        for (var i = 0; i < features.Count; i++)
        {
            if (string.Equals(features[i], name, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}
