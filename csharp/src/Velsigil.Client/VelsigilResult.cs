using System;
using System.Collections.Generic;
using Velsigil.Client.Internal;
using LeaseOutcome = Velsigil.Client.LeaseStatus;

namespace Velsigil.Client;

/// <summary>Outcome of a client call; failures are reported with <see cref="Ok"/> = false and never throw.</summary>
/// <remarks><see cref="Ok"/> is true only for a verified signed response or a valid offline lease.</remarks>
public sealed class VelsigilResult
{
    private VelsigilResult(bool ok, string code, string message, long referenceTimeUnix)
    {
        Ok = ok;
        Code = code;
        Message = message;
        ReferenceTimeUnix = referenceTimeUnix;
    }

    /// <summary>True when the operation succeeded (always false for unsigned or unverifiable responses).</summary>
    public bool Ok { get; }

    /// <summary>Machine-readable result code; see <see cref="ResultCodes"/>.</summary>
    public string Code { get; }

    /// <summary>Human-readable message (from the signed response, or an SDK message).</summary>
    public string Message { get; }

    /// <summary>License details (signed responses only; null when the key was not found).</summary>
    public LicenseInfo? License { get; private set; }

    /// <summary>This device's activation record, when the server returned one.</summary>
    public ActivationInfo? Activation { get; private set; }

    /// <summary>The offline lease returned by the server, or the stored lease for offline results.</summary>
    public LeaseInfo? Lease { get; private set; }

    /// <summary>Verified lease claims; set for offline results (see <see cref="Offline"/>).</summary>
    public LeaseClaims? LeaseClaims { get; private set; }

    /// <summary>Release / update information, when available.</summary>
    public UpdateInfo? Update { get; private set; }

    /// <summary>The download grant (from <see cref="VelsigilClient.GetDownloadAsync"/>).</summary>
    public DownloadInfo? Download { get; private set; }

    /// <summary>The server request id (quote it to support). Null for SDK-side failures.</summary>
    public string? RequestId { get; private set; }

    /// <summary>True when the result was produced from the stored offline lease, not the server.</summary>
    public bool Offline { get; private set; }

    /// <summary>Offline results with a stored lease: why the lease is or is not valid; null otherwise.</summary>
    public LeaseStatus? LeaseStatus { get; private set; }

    /// <summary>True when the result is backed by a verified signature (signed response or lease).</summary>
    public bool Verified { get; private set; }

    /// <summary>Authoritative server time from a signed response (unix seconds).</summary>
    public long? ServerTimeUnix { get; private set; }

    /// <summary>HTTP status for unsigned/HTTP-level failures; 200 for signed responses; null otherwise.</summary>
    public int? HttpStatus { get; private set; }

    /// <summary>How long to wait before retrying, from the Retry-After of an HTTP 429 or 503 (capped at one day).</summary>
    public TimeSpan? RetryAfter { get; private set; }

    /// <summary>Key of the trial <see cref="VelsigilClient.StartTrialAsync"/> just started. The server sends it only once; store it.</summary>
    public string? TrialKey { get; private set; }

    /// <summary>The time the result refers to (unix seconds): server time if signed, else the corrected local clock.</summary>
    public long ReferenceTimeUnix { get; }

    /// <summary>Feature flags of the license (from the response or, offline, from the lease).</summary>
    public IReadOnlyList<string> Features => License?.Features ?? LeaseClaims?.Features ?? (IReadOnlyList<string>)Array.Empty<string>();

    /// <summary>True only when the result is ok and the license grants <paramref name="name"/>.</summary>
    public bool HasFeature(string name) => Ok && FeatureList.Contains(Features, name);

    /// <summary>License expiry (from the response or the offline lease); null for lifetime or unknown.</summary>
    public DateTimeOffset? ExpiresAt
    {
        get
        {
            var seconds = ExpiresAtUnix;
            return seconds.HasValue ? DateTimeOffset.FromUnixTimeSeconds(seconds.Value) : (DateTimeOffset?)null;
        }
    }

    /// <summary>True when the license is a free trial (online or from the stored lease).</summary>
    public bool IsTrial => License != null ? License.IsTrial : LeaseClaims != null && LeaseClaims.IsTrial;

    /// <summary>The trial's conversion reference for a "Buy now" link (online results only), or null.</summary>
    public string? TrialRef => License?.TrialRef;

    /// <summary><paramref name="buyUrl"/> with this trial's conversion reference, or unchanged when there is none.</summary>
    public string WithTrialRef(string buyUrl) => TrialReference.Append(buyUrl, TrialRef);

    /// <summary>True when the license is known and has no expiry date.</summary>
    public bool IsLifetime =>
        License != null ? License.IsLifetime : LeaseClaims != null && !LeaseClaims.LicenseExpiresAtUnix.HasValue;

    /// <summary>Time left until the license expires, measured at <see cref="ReferenceTimeUnix"/>; null for lifetime/unknown.</summary>
    public TimeSpan? TimeRemaining => GetTimeRemaining(DateTimeOffset.FromUnixTimeSeconds(ReferenceTimeUnix));

    /// <summary>Days left until the license expires, rounded up, at <see cref="ReferenceTimeUnix"/>; null for lifetime/unknown.</summary>
    public int? DaysRemaining
    {
        get
        {
            var remaining = TimeRemaining;
            return remaining.HasValue ? (int)Math.Ceiling(remaining.Value.TotalDays) : (int?)null;
        }
    }

    /// <summary>Time left until the license expires as of <paramref name="now"/> (never negative); null for lifetime/unknown.</summary>
    public TimeSpan? GetTimeRemaining(DateTimeOffset now)
    {
        var expires = ExpiresAtUnix;
        if (!expires.HasValue) return null;
        var seconds = expires.Value - now.ToUnixTimeSeconds();
        return TimeSpan.FromSeconds(seconds > 0 ? seconds : 0);
    }

    /// <summary>True when the license expires within <paramref name="window"/> of <see cref="ReferenceTimeUnix"/>.</summary>
    public bool IsExpiringWithin(TimeSpan window)
    {
        var remaining = TimeRemaining;
        return remaining.HasValue && remaining.Value <= window;
    }

    private long? ExpiresAtUnix => License != null ? License.ExpiresAtUnix : LeaseClaims?.LicenseExpiresAtUnix;

    /// <summary>A diagnostic summary. Never contains license keys, device secrets or lease tokens.</summary>
    public override string ToString() =>
        $"VelsigilResult(Ok={Ok}, Code={Code}, Offline={Offline}, Verified={Verified}, RequestId={RequestId ?? "-"})";

    internal static VelsigilResult FromPayload(SignedPayload payload) =>
        new VelsigilResult(payload.Ok, payload.Code, payload.Message, payload.ServerTime)
        {
            License = payload.License,
            Activation = payload.Activation,
            Lease = payload.Lease,
            Update = payload.Update,
            Download = payload.Download,
            RequestId = payload.RequestId,
            Verified = true,
            ServerTimeUnix = payload.ServerTime,
            HttpStatus = 200,
            TrialKey = payload.Ok ? payload.TrialKey : null,
        };

    internal static VelsigilResult Failure(
        string code,
        string message,
        long referenceTimeUnix,
        int? httpStatus = null,
        string? requestId = null,
        TimeSpan? retryAfter = null) =>
        new VelsigilResult(false, code, message, referenceTimeUnix)
        {
            HttpStatus = httpStatus,
            RequestId = requestId,
            RetryAfter = retryAfter,
        };

    internal static VelsigilResult FromLease(LeaseVerification verification, string token, long nowUnix)
    {
        string code;
        string message;
        switch (verification.Status)
        {
            case LeaseOutcome.Valid:
                code = ResultCodes.Ok;
                message = "License is valid (offline lease).";
                break;
            case LeaseOutcome.Expired:
                code = ResultCodes.LeaseExpired;
                message = "The offline lease has expired; connect to the internet to revalidate.";
                break;
            case LeaseOutcome.InvalidSignature:
                code = ResultCodes.LeaseInvalid;
                message = "The stored offline lease is not valid (invalid signature).";
                break;
            case LeaseOutcome.ProductMismatch:
                code = ResultCodes.LeaseInvalid;
                message = "The stored offline lease is not valid (issued for a different product).";
                break;
            case LeaseOutcome.HwidMismatch:
                code = ResultCodes.LeaseInvalid;
                message = "The stored offline lease is not valid (issued for a different device).";
                break;
            default:
                code = ResultCodes.LeaseInvalid;
                message = "The stored offline lease is not valid (malformed).";
                break;
        }

        var valid = verification.Status == LeaseOutcome.Valid;
        var claims = verification.Claims;
        return new VelsigilResult(valid, code, message, nowUnix)
        {
            Offline = true,
            LeaseStatus = verification.Status,
            Verified = claims != null,
            LeaseClaims = claims,
            Lease = claims != null ? new LeaseInfo(token, claims.ExpiresAtUnix) : null,
        };
    }

    internal static VelsigilResult OfflineFailure(string code, string message, long nowUnix) =>
        new VelsigilResult(false, code, message, nowUnix) { Offline = true };

    /// <summary>Copies the failed online attempt's retry-after onto an offline fallback result.</summary>
    internal VelsigilResult WithRetryAfter(TimeSpan? retryAfter)
    {
        RetryAfter = retryAfter;
        return this;
    }

    internal static VelsigilResult DownloadCompleted(DownloadInfo download, long nowUnix) =>
        new VelsigilResult(true, ResultCodes.Ok, "Download completed and verified against the signed SHA-256.", nowUnix)
        {
            Download = download,
            Verified = true,
            HttpStatus = 200,
        };
}
