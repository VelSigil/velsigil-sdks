using System;
using System.Collections.Generic;
using Velsigil.Client.Internal;
using LeaseOutcome = Velsigil.Client.LeaseStatus;

namespace Velsigil.Client;

/// <summary>
/// The outcome of a client call. Business failures (expired license, device limit, ...) and transport
/// failures are reported here with <see cref="Ok"/> = false and a <see cref="Code"/>; they never throw.
/// </summary>
/// <remarks>
/// <see cref="Ok"/> can only be true for a response whose Ed25519 signature, nonce, product id and request
/// type were verified, or for a verified, unexpired offline lease bound to this device.
/// </remarks>
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

    /// <summary>
    /// For offline results with a stored lease: the detailed verification outcome (why a lease is
    /// <see cref="ResultCodes.LeaseInvalid"/>); null otherwise.
    /// </summary>
    public LeaseStatus? LeaseStatus { get; private set; }

    /// <summary>
    /// True when the result is backed by a verified signature (signed server response or signed lease).
    /// Unsigned HTTP errors and SDK-side failures are never verified.
    /// </summary>
    public bool Verified { get; private set; }

    /// <summary>Authoritative server time from a signed response (unix seconds).</summary>
    public long? ServerTimeUnix { get; private set; }

    /// <summary>HTTP status for unsigned/HTTP-level failures; 200 for signed responses; null otherwise.</summary>
    public int? HttpStatus { get; private set; }

    /// <summary>
    /// How long the server asked to wait before trying again: the <c>Retry-After</c> header (delta-seconds or HTTP
    /// date, capped at one day) of every HTTP 429 or 503 answer, whatever code it maps to
    /// (<see cref="ResultCodes.RateLimited"/>; <see cref="ResultCodes.NetworkError"/> for the empty 503 of a server whose
    /// database is unreachable, or a gateway's 503; <see cref="ResultCodes.InternalError"/> for 503 <c>service_busy</c>;
    /// <see cref="VelsigilClient.DownloadFileAsync"/> reports a 503 as <see cref="ResultCodes.NetworkError"/>).
    /// The results of the offline fallback of <see cref="VelsigilClient.ValidateWithOfflineFallbackAsync"/>
    /// (<see cref="ResultCodes.Ok"/>, <see cref="ResultCodes.LeaseExpired"/>, <see cref="ResultCodes.LeaseInvalid"/>)
    /// carry the value of the failed online attempt, so the app knows when to try online again. Null when the header is
    /// absent or unparseable, for every other status and for <see cref="VelsigilClient.ValidateOffline"/>.
    /// </summary>
    public TimeSpan? RetryAfter { get; private set; }

    /// <summary>
    /// The license key of the free trial <see cref="VelsigilClient.StartTrialAsync"/> just started (ok results of
    /// that method only; null otherwise). The server sends it once and can never send it again: store it right
    /// away, like a key the user typed, and use it with <see cref="VelsigilClient.ValidateAsync"/> from then on. The
    /// SDK never persists it, and <see cref="ToString"/> never shows it.
    /// </summary>
    public string? TrialKey { get; private set; }

    /// <summary>
    /// The time the result refers to (unix seconds): the server time for signed responses, otherwise the
    /// client's clock (corrected by the learned server offset). Used by the expiry helpers.
    /// </summary>
    public long ReferenceTimeUnix { get; }

    /// <summary>Feature flags of the license (from the response or, offline, from the lease).</summary>
    public IReadOnlyList<string> Features => License?.Features ?? LeaseClaims?.Features ?? (IReadOnlyList<string>)Array.Empty<string>();

    /// <summary>
    /// True when the result is successful <b>and</b> the license grants <paramref name="name"/>. Always
    /// false for failed results, so a feature can never be unlocked by an expired/invalid response.
    /// </summary>
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

    /// <summary>
    /// True when the license is a free trial (SPEC 9.7): the optional signed <c>trial</c> field of the response, or
    /// of the stored lease for offline results. Use it with <see cref="DaysRemaining"/> for a "Trial: N days left"
    /// notice; a purchase with the same e-mail keeps the key and turns this false at the next online validation.
    /// </summary>
    public bool IsTrial => License != null ? License.IsTrial : LeaseClaims != null && LeaseClaims.IsTrial;

    /// <summary>
    /// The current trial's conversion reference (SPEC 9.7), or null: present on online results for a free trial a
    /// purchase can still convert, also on <c>license_expired</c> (the moment to offer "Buy now"). Add it to the
    /// "Buy now" link with <see cref="WithTrialRef"/>: the purchase then converts THIS trial into the paid license (same
    /// key) whatever e-mail address the buyer pays with. A fresh one comes with every answer; offline results have none.
    /// </summary>
    public string? TrialRef => License?.TrialRef;

    /// <summary>
    /// <paramref name="buyUrl"/> with this trial's conversion reference (<c>velsigil_trial=&lt;ref&gt;</c>; Stripe Payment
    /// Links: <c>client_reference_id</c>), or <paramref name="buyUrl"/> unchanged when there is none.
    /// </summary>
    public string WithTrialRef(string buyUrl) => TrialReference.Append(buyUrl, TrialRef);

    /// <summary>True when the license is known and has no expiry date.</summary>
    public bool IsLifetime =>
        License != null ? License.IsLifetime : LeaseClaims != null && !LeaseClaims.LicenseExpiresAtUnix.HasValue;

    /// <summary>Time left until the license expires, measured at <see cref="ReferenceTimeUnix"/>; null for lifetime/unknown.</summary>
    public TimeSpan? TimeRemaining => GetTimeRemaining(DateTimeOffset.FromUnixTimeSeconds(ReferenceTimeUnix));

    /// <summary>
    /// Days left until the license expires, rounded up (never negative), measured at <see cref="ReferenceTimeUnix"/>
    /// (the signed server time online, the time of the check offline); null for lifetime/unknown. The "days left" rule
    /// of CLIENT_PROTOCOL 5.2, the same in every Velsigil SDK: an N-day trial shows N right after
    /// <see cref="VelsigilClient.StartTrialAsync"/>, 1 throughout its last day and 0 once expired.
    /// </summary>
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

    // ---- Factories (internal: results can only be produced by the SDK) ------------------------------

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
            // Only expose claims and the token when they were authenticated.
            LeaseClaims = claims,
            Lease = claims != null ? new LeaseInfo(token, claims.ExpiresAtUnix) : null,
        };
    }

    internal static VelsigilResult OfflineFailure(string code, string message, long nowUnix) =>
        new VelsigilResult(false, code, message, nowUnix) { Offline = true };

    /// <summary>
    /// Sets <see cref="RetryAfter"/> on an offline result the SDK has just built and not handed out yet: the fallback of
    /// <see cref="VelsigilClient.ValidateWithOfflineFallbackAsync"/> copies the failed online answer's value onto it.
    /// </summary>
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
