namespace Velsigil.Client;

/// <summary>
/// Every <see cref="VelsigilResult.Code"/> the SDK can return. Codes are stable snake_case strings so new
/// server codes can surface without an SDK update; compare against these constants.
/// </summary>
public static class ResultCodes
{
    // ---- Signed server codes (SPEC section 10.3) -------------------------------------------------

    /// <summary>The request succeeded.</summary>
    public const string Ok = "ok";

    /// <summary>The license key does not exist for this product.</summary>
    public const string InvalidKey = "invalid_key";

    /// <summary>The license has expired.</summary>
    public const string LicenseExpired = "license_expired";

    /// <summary>The license is suspended.</summary>
    public const string LicenseSuspended = "license_suspended";

    /// <summary>The license was revoked.</summary>
    public const string LicenseRevoked = "license_revoked";

    /// <summary>The license was banned.</summary>
    public const string LicenseBanned = "license_banned";

    /// <summary>The license already has the maximum number of devices.</summary>
    public const string DeviceLimitReached = "device_limit_reached";

    /// <summary>This device was revoked for the license.</summary>
    public const string DeviceRevoked = "device_revoked";

    /// <summary>The device secret did not match (strict device binding).</summary>
    public const string DeviceVerificationFailed = "device_verification_failed";

    /// <summary>No device record exists for this machine (deactivate).</summary>
    public const string DeviceNotFound = "device_not_found";

    /// <summary>The device must be activated through validation first (download).</summary>
    public const string DeviceNotActivated = "device_not_activated";

    /// <summary>Too many new devices were activated recently.</summary>
    public const string ActivationRateLimited = "activation_rate_limited";

    /// <summary>A new device was activated too recently.</summary>
    public const string ActivationCooldown = "activation_cooldown";

    /// <summary>New activations are disabled by the seller.</summary>
    public const string ActivationsDisabled = "activations_disabled";

    /// <summary>Downloads are disabled by the seller.</summary>
    public const string DownloadsDisabled = "downloads_disabled";

    /// <summary>The device, IP address or customer is blacklisted.</summary>
    public const string Blacklisted = "blacklisted";

    /// <summary>The application version is below the product's minimum version.</summary>
    public const string OutdatedVersion = "outdated_version";

    /// <summary>The product is paused (maintenance).</summary>
    public const string ProductPaused = "product_paused";

    /// <summary>The product is disabled.</summary>
    public const string ProductDisabled = "product_disabled";

    /// <summary>The local clock is too far from the server clock (the SDK corrects and retries once).</summary>
    public const string ClockSkew = "clock_skew";

    /// <summary>The request nonce was already used.</summary>
    public const string ReplayDetected = "replay_detected";

    /// <summary>No release is published for the product.</summary>
    public const string NoRelease = "no_release";

    /// <summary>The requested release version does not exist.</summary>
    public const string ReleaseNotFound = "release_not_found";

    /// <summary>
    /// This device already used a free trial of the product (SPEC 9.7). A signed failure that keeps the stored
    /// offline lease; offer a purchase.
    /// </summary>
    public const string TrialAlreadyUsed = "trial_already_used";

    /// <summary>
    /// In-app trials (<see cref="VelsigilClient.StartTrialAsync"/>): the seller offers no in-app trial right now
    /// (switched off, today's limit, too many trials from this network). A signed failure.
    /// </summary>
    public const string TrialUnavailable = "trial_unavailable";

    /// <summary>In-app trials: the offer confirms an e-mail address first and none was sent.</summary>
    public const string TrialEmailRequired = "trial_email_required";

    /// <summary>In-app trials: the e-mail address is not valid.</summary>
    public const string TrialEmailInvalid = "trial_email_invalid";

    /// <summary>In-app trials: the e-mail domain is not accepted (throwaway or blocked domain).</summary>
    public const string TrialEmailNotAccepted = "trial_email_not_accepted";

    /// <summary>
    /// In-app trials: a confirmation link was e-mailed (the same answer for every valid address). Not an error of
    /// the user: the key arrives by e-mail and is entered like any key.
    /// </summary>
    public const string TrialConfirmationSent = "trial_confirmation_sent";

    // ---- Unsigned HTTP errors (never successful) -------------------------------------------------

    /// <summary>The server rejected the request body (HTTP 400).</summary>
    public const string ValidationError = "validation_error";

    /// <summary>The caller's IP address is blocked (HTTP 403).</summary>
    public const string IpBlocked = "ip_blocked";

    /// <summary>The product id is unknown to the server (HTTP 404).</summary>
    public const string UnknownProduct = "unknown_product";

    /// <summary>Too many requests (HTTP 429); see <see cref="VelsigilResult.RetryAfter"/>.</summary>
    public const string RateLimited = "rate_limited";

    /// <summary>The server failed (HTTP 500).</summary>
    public const string InternalError = "internal_error";

    /// <summary>The request body was too large (HTTP 413).</summary>
    public const string PayloadTooLarge = "payload_too_large";

    /// <summary>The request content type was rejected (HTTP 415).</summary>
    public const string UnsupportedMediaType = "unsupported_media_type";

    // ---- SDK-side codes (SPEC section 14; identical names in every Velsigil SDK) -------------------

    /// <summary>
    /// The response was unsigned, carried an invalid signature, a foreign nonce/product/type, a signed
    /// lease or activation of another device (hardware id), a download URL outside the https policy, or
    /// was otherwise malformed. Treat as hostile; never as success.
    /// </summary>
    public const string InvalidResponse = "invalid_response";

    /// <summary>
    /// The server could not be reached (DNS, connection, TLS, timeout), or a gateway answered 502/503/504
    /// without a Velsigil error body. The only code that triggers the offline fallback.
    /// </summary>
    public const string NetworkError = "network_error";

    /// <summary>
    /// Invalid client configuration. The .NET SDK reports configuration mistakes idiomatically by throwing
    /// <see cref="System.ArgumentException"/> from the constructor; this constant is the cross-SDK name for
    /// that condition (apps that map exceptions to codes should use it).
    /// </summary>
    public const string InvalidConfiguration = "invalid_configuration";

    /// <summary>Offline validation: no lease is stored for this product.</summary>
    public const string NoLease = "no_lease";

    /// <summary>Offline validation: the stored lease has expired.</summary>
    public const string LeaseExpired = "lease_expired";

    /// <summary>
    /// Offline validation: the stored lease is not acceptable (invalid signature, another product or
    /// device, or not a lease token). <see cref="VelsigilResult.LeaseStatus"/> tells which.
    /// </summary>
    public const string LeaseInvalid = "lease_invalid";

    /// <summary>A downloaded file did not match the signed size / SHA-256 (it was discarded).</summary>
    public const string IntegrityMismatch = "integrity_mismatch";

    /// <summary>
    /// A download could not be completed: non-200 status (an expired link answers 410: request a new one) or
    /// a download URL rejected by the HTTPS policy.
    /// </summary>
    public const string DownloadFailed = "download_failed";

    /// <summary>A download could not be written to the destination (local file-system error).</summary>
    public const string IoError = "io_error";

    /// <summary>
    /// <see cref="VelsigilClient.StartTrialAsync"/> reached a Velsigil server without the in-app trial endpoint
    /// (HTTP 404 with the Velsigil error code <c>not_found</c>): the seller must update the panel.
    /// </summary>
    public const string PanelTooOld = "panel_too_old";

    /// <summary>
    /// <see cref="VelsigilClient.StartTrialAsync"/> refused locally: a device secret or an offline lease is already
    /// stored for the product, so this device holds a license that a trial must not replace. Nothing was sent and the
    /// stored state is unchanged; validate the saved key, or call <see cref="VelsigilClient.DeactivateAsync"/> /
    /// <see cref="VelsigilClient.ClearStoredState"/> first.
    /// </summary>
    public const string AlreadyLicensed = "already_licensed";

    /// <summary>
    /// <see cref="VelsigilClient.StartTrialAsync"/> refused locally: the store could not be read, so it cannot tell
    /// whether this device already holds a license (a failed read is never "nothing stored"). Nothing was sent; try
    /// again once the store can be read.
    /// </summary>
    public const string StoreUnavailable = "store_unavailable";
}
