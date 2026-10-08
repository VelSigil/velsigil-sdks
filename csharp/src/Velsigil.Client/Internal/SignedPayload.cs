using System.Text.Json;

namespace Velsigil.Client.Internal;

/// <summary>A response payload whose signature, nonce, product and type have been verified.</summary>
internal sealed class SignedPayload
{
    public string Type { get; private set; } = string.Empty;
    public bool Ok { get; private set; }
    public string Code { get; private set; } = string.Empty;
    public string Message { get; private set; } = string.Empty;
    public string Nonce { get; private set; } = string.Empty;
    public string RequestId { get; private set; } = string.Empty;
    public long ServerTime { get; private set; }
    public string ProductId { get; private set; } = string.Empty;
    public LicenseInfo? License { get; private set; }
    public ActivationInfo? Activation { get; private set; }

    /// <summary>The newly issued device secret (only ever stored, never surfaced on results).</summary>
    public string? DeviceSecret { get; private set; }

    /// <summary>
    /// Optional <c>activation.hwidHash</c> (lowercase hex SHA-256 of the hwid the activation belongs to);
    /// checked against the requesting device by <see cref="EnvelopeVerifier"/>. Null when not sent.
    /// </summary>
    public string? ActivationHwidHash { get; private set; }

    public LeaseInfo? Lease { get; private set; }
    public UpdateInfo? Update { get; private set; }
    public DownloadInfo? Download { get; private set; }

    /// <summary>
    /// The key of a started in-app trial (SPEC 10.1): required on an ok answer of type <c>trial</c>, never read
    /// from any other answer (there the field is ignored like an unknown one).
    /// </summary>
    public string? TrialKey { get; private set; }

    private const int MaxDeviceSecretLength = 512;
    private const int MaxTrialKeyLength = 64;

    /// <summary>
    /// Parses the decoded payload object (SPEC 10.1). Every documented field is type-checked; unknown
    /// fields are ignored. Returns null when anything is malformed (callers fail closed).
    /// </summary>
    public static SignedPayload? Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;
        if (!JsonRead.TryGetInt64(root, "v", out var version) || version != 1) return null;

        var p = new SignedPayload();
        if (!JsonRead.TryGetString(root, "type", out var type)) return null;
        if (!JsonRead.TryGetBoolean(root, "ok", out var ok)) return null;
        if (!JsonRead.TryGetString(root, "code", out var code) || code.Length == 0) return null;
        if (!JsonRead.TryGetString(root, "message", out var message)) return null;
        if (!JsonRead.TryGetString(root, "nonce", out var nonce)) return null;
        if (!JsonRead.TryGetString(root, "requestId", out var requestId)) return null;
        if (!JsonRead.TryGetUnixTime(root, "serverTime", out var serverTime)) return null;
        if (!JsonRead.TryGetString(root, "productId", out var productId)) return null;

        p.Type = type;
        p.Ok = ok;
        p.Code = code;
        p.Message = message;
        p.Nonce = nonce;
        p.RequestId = requestId;
        p.ServerTime = serverTime;
        p.ProductId = productId;

        if (!JsonRead.TryGetOptionalObject(root, "license", out var license, out var hasLicense)) return null;
        if (hasLicense)
        {
            if (!JsonRead.TryGetString(license, "id", out var id)
                || !JsonRead.TryGetString(license, "plan", out var plan)
                || !JsonRead.TryGetString(license, "status", out var status)
                || !JsonRead.TryGetStringArray(license, "features", out var features)
                || !JsonRead.TryGetOptionalUnixTime(license, "expiresAt", out var expiresAt)
                || !JsonRead.TryGetInt32(license, "maxDevices", out var maxDevices)
                || !JsonRead.TryGetInt32(license, "devicesUsed", out var devicesUsed)
                || !JsonRead.TryGetUnixTime(license, "createdAt", out var createdAt)
                // Optional free-trial flag (SPEC 9.7): absent/null = not a trial; a non-boolean is malformed.
                || !JsonRead.TryGetOptionalBoolean(license, "trial", out var trial)
                // Optional trial conversion reference (SPEC 9.7): absent/null = none; anything but a string is malformed.
                || !JsonRead.TryGetOptionalString(license, "trialRef", out var trialRef))
            {
                return null;
            }
            // ...and a string must be 1-200 characters of [A-Za-z0-9_-].
            if (trialRef != null && !TrialReference.IsWellFormed(trialRef)) return null;
            // Only an ok answer grants features through the license-level helper too (MONEY-V1).
            p.License = new LicenseInfo(id, plan, status, features, expiresAt, maxDevices, devicesUsed, createdAt, granted: ok, isTrial: trial, trialRef: trialRef);
        }

        if (!JsonRead.TryGetOptionalObject(root, "activation", out var activation, out var hasActivation)) return null;
        if (hasActivation)
        {
            if (!JsonRead.TryGetString(activation, "id", out var id)
                || !JsonRead.TryGetString(activation, "status", out var status)
                || !JsonRead.TryGetUnixTime(activation, "firstSeenAt", out var firstSeenAt)
                || !JsonRead.TryGetOptionalString(activation, "deviceSecret", out var deviceSecret)
                || !JsonRead.TryGetOptionalString(activation, "hwidHash", out var activationHwidHash))
            {
                return null;
            }
            if (deviceSecret != null && !IsAcceptableSecret(deviceSecret)) return null;
            if (activationHwidHash != null && !Crypto.IsSha256Hex(activationHwidHash)) return null;
            p.DeviceSecret = deviceSecret;
            p.ActivationHwidHash = activationHwidHash?.ToLowerInvariant();
            p.Activation = new ActivationInfo(id, status, firstSeenAt, deviceSecret != null);
        }

        if (!JsonRead.TryGetOptionalObject(root, "lease", out var lease, out var hasLease)) return null;
        if (hasLease)
        {
            if (!JsonRead.TryGetString(lease, "token", out var token)
                || token.Length == 0
                || !JsonRead.TryGetUnixTime(lease, "expiresAt", out var leaseExpiresAt))
            {
                return null;
            }
            p.Lease = new LeaseInfo(token, leaseExpiresAt);
        }

        if (!JsonRead.TryGetOptionalObject(root, "update", out var update, out var hasUpdate)) return null;
        if (hasUpdate)
        {
            if (!JsonRead.TryGetString(update, "latestVersion", out var latest)
                || !JsonRead.TryGetOptionalString(update, "minVersion", out var minVersion)
                || !JsonRead.TryGetBoolean(update, "updateAvailable", out var available)
                || !JsonRead.TryGetBoolean(update, "mandatory", out var mandatory)
                || !JsonRead.TryGetString(update, "changelog", out var changelog))
            {
                return null;
            }
            p.Update = new UpdateInfo(latest, minVersion, available, mandatory, changelog);
        }

        if (!JsonRead.TryGetOptionalObject(root, "download", out var download, out var hasDownload)) return null;
        if (hasDownload)
        {
            if (!JsonRead.TryGetString(download, "url", out var url)
                || url.Length == 0
                || !JsonRead.TryGetUnixTime(download, "expiresAt", out var downloadExpiresAt)
                || !JsonRead.TryGetString(download, "fileName", out var fileName)
                || !JsonRead.TryGetInt64(download, "size", out var size)
                || size < 0
                || !JsonRead.TryGetString(download, "sha256", out var sha256)
                || !Crypto.IsSha256Hex(sha256)
                || !JsonRead.TryGetString(download, "version", out var releaseVersion))
            {
                return null;
            }
            p.Download = new DownloadInfo(url, downloadExpiresAt, fileName, size, sha256.ToLowerInvariant(), releaseVersion);
        }

        // A started in-app trial must carry a well-formed key (1-64 printable ASCII characters, like every key).
        if (ok && string.Equals(type, "trial", System.StringComparison.Ordinal))
        {
            if (!JsonRead.TryGetOptionalObject(root, "trial", out var trialObject, out var hasTrial) || !hasTrial) return null;
            if (!JsonRead.TryGetString(trialObject, "key", out var trialKey) || !IsPrintableAscii(trialKey, MaxTrialKeyLength)) return null;
            p.TrialKey = trialKey;
        }

        return p;
    }

    private static bool IsAcceptableSecret(string secret) => IsPrintableAscii(secret, MaxDeviceSecretLength);

    private static bool IsPrintableAscii(string value, int maxLength)
    {
        if (value.Length == 0 || value.Length > maxLength) return false;
        foreach (var c in value)
        {
            // Printable ASCII only: the value is echoed back in JSON and persisted / shown by the app.
            if (c < 0x21 || c > 0x7E) return false;
        }
        return true;
    }
}
