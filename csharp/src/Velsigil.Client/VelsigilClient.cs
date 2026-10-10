using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Velsigil.Client.Internal;
using Velsigil.Client.Storage;
using HardwareIdProvider = Velsigil.Client.HardwareId;

namespace Velsigil.Client;

/// <summary>Client for the Velsigil license server (<c>/api/client/v1</c>).</summary>
/// <remarks>
/// Only answers signed with the constructor's key and bound to the request are trusted.
/// Business failures never throw: check <see cref="VelsigilResult.Ok"/>. Thread-safe; keep one instance per product.
/// </remarks>
public sealed class VelsigilClient : IDisposable
{
    /// <summary>SDK version, sent in the User-Agent header.</summary>
    public const string SdkVersion = "1.0.5";

    private const string TypeValidate = "validate";
    private const string TypeDeactivate = "deactivate";
    private const string TypeUpdateCheck = "update_check";
    private const string TypeDownload = "download";
    private const string TypeTrial = "trial";

    private const int MaxResponseBytes = 1024 * 1024;
    private const int MaxErrorBodyBytes = 64 * 1024;
    private const int MaxLicenseKeyLength = 64; // server-side licenseKeyInput limit
    private const int MaxVersionLength = 32;
    private const int MaxDeviceNameLength = 255;
    private const int MaxEmailLength = 254;
    private const int NonceBytes = 32;
    private const int DownloadBufferSize = 81920;

    private const string AlreadyLicensedMessage =
        "This device already holds a license for this product (a stored device secret or offline lease); a free trial cannot " +
        "replace it. Validate the saved license key instead, or call DeactivateAsync() or ClearStoredState() first. No request was sent.";

    private const string StoreUnavailableMessage =
        "The license store could not be read, so it is unknown whether this device already holds a license for this product; " +
        "a free trial was not started. Try again once the store can be read. No request was sent.";

    private static readonly TimeSpan MinTimeout = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxTimeout = TimeSpan.FromMinutes(10);
    private static readonly string UserAgent = "Velsigil.Client/" + SdkVersion + " (.NET)";

    /// <summary>Signed denials that make the stored lease unusable; the same set in every Velsigil SDK.</summary>
    public static IReadOnlyCollection<string> LeaseRevokingCodes => RevokingCodeSet;

    private static readonly HashSet<string> RevokingCodeSet = new HashSet<string>(StringComparer.Ordinal)
    {
        ResultCodes.InvalidKey,
        ResultCodes.LicenseExpired,
        ResultCodes.LicenseSuspended,
        ResultCodes.LicenseRevoked,
        ResultCodes.LicenseBanned,
        ResultCodes.DeviceRevoked,
        ResultCodes.DeviceVerificationFailed,
        ResultCodes.DeviceLimitReached,
        ResultCodes.DeviceNotActivated,
        ResultCodes.DeviceNotFound,
        ResultCodes.Blacklisted,
        ResultCodes.ProductDisabled,
    };

    private readonly Uri _apiBase;
    private readonly Uri _serverRoot;
    private readonly string _productId;
    private readonly Ed25519Verifier _verifier;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly TimeSpan _timeout;
    private readonly IVelsigilStore _store;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Action<Exception>? _storeErrorHandler;
    private readonly bool _allowInsecureHttp;
    private readonly string _hwid;

    // Serializes device-bound calls so a stored secret or the trial check cannot be overtaken.
    // Never disposed: only AvailableWaitHandle needs that.
    private readonly SemaphoreSlim _deviceLock = new SemaphoreSlim(1, 1);
    private long _clockOffsetSeconds;
    private int _disposed;

    /// <summary>Creates a client for one product.</summary>
    /// <param name="apiUrl">The Velsigil server URL; https unless the host is loopback or <see cref="VelsigilClientOptions.AllowInsecureHttp"/> is set.</param>
    /// <param name="productId">The product id (UUID) from the panel.</param>
    /// <param name="publicKeyBase64">The product's Ed25519 public key from the panel; embed it in your code.</param>
    /// <param name="options">Optional settings.</param>
    /// <exception cref="ArgumentException">An argument is invalid, or a published test key is used with a non-loopback URL.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The timeout is outside 1 s .. 10 min.</exception>
    /// <exception cref="PlatformNotSupportedException">No machine id could be read and no <see cref="VelsigilClientOptions.HardwareId"/> was supplied.</exception>
    public VelsigilClient(string apiUrl, string productId, string publicKeyBase64, VelsigilClientOptions? options = null)
    {
        options ??= new VelsigilClientOptions();
        _allowInsecureHttp = options.AllowInsecureHttp;
        _apiBase = BuildApiBase(apiUrl, _allowInsecureHttp, out _serverRoot);
        _productId = NormalizeProductId(productId);
        _verifier = Ed25519Verifier.FromBase64(publicKeyBase64);
        // Published test keys are only allowed for loopback hosts, the same rule as plain http.
        if (_verifier.IsPublishedTestKey && !IsLoopbackHost(_serverRoot))
        {
            throw new ArgumentException(PublishedTestKeys.RefusalMessage, nameof(publicKeyBase64));
        }

        if (options.Timeout < MinTimeout || options.Timeout > MaxTimeout)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Timeout must be between 1 second and 10 minutes.");
        }
        _timeout = options.Timeout;
        _clock = options.Clock ?? (() => DateTimeOffset.UtcNow);
        _storeErrorHandler = options.StoreErrorHandler;
        _hwid = ResolveHardwareId(options.HardwareId);
        _store = options.Store ?? CreateDefaultStore(_storeErrorHandler);

        if (options.HttpClient != null)
        {
            _http = options.HttpClient;
            _ownsHttpClient = false;
        }
        else
        {
            _http = CreateHttpClient();
            _ownsHttpClient = true;
        }
    }

    /// <summary>The configured product id (normalised to lowercase).</summary>
    public string ProductId => _productId;

    /// <summary>The hardware id this client sends (the override, or the derived machine hwid).</summary>
    public string HardwareId => _hwid;

    /// <summary>Key id of the pinned public key (first 16 hex chars of its SHA-256), for diagnostics.</summary>
    public string KeyId => _verifier.KeyId;

    /// <summary>The client API base URL, ending in <c>/api/client/v1/</c>.</summary>
    public Uri ApiBaseUrl => _apiBase;

    /// <summary>Server-minus-local clock offset in seconds, learned from a signed <c>clock_skew</c> response.</summary>
    public long ClockOffsetSeconds => Interlocked.Read(ref _clockOffsetSeconds);

    /// <summary>Computes this machine's hardware id; see <see cref="Velsigil.Client.HardwareId"/>.</summary>
    /// <exception cref="PlatformNotSupportedException">No machine id is available.</exception>
    public static string GetHardwareId() => HardwareIdProvider.Get();

    /// <summary>Validates the license on this device, activating it when a slot is free; stores the secret and lease.</summary>
    public Task<VelsigilResult> ValidateAsync(string licenseKey, ValidateOptions? options = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var invalid = CheckLicenseKey(licenseKey, out var key)
            ?? CheckLength(options?.Version, MaxVersionLength, "The version string is too long (max 32 characters).")
            ?? CheckLength(options?.DeviceName, MaxDeviceNameLength, "The device name is too long (max 255 characters).");
        if (invalid != null) return Task.FromResult(invalid);

        var deviceName = options?.DeviceName;
        var version = options?.Version;
        return WithDeviceLockAsync(() =>
        {
            var body = new RequestBody()
                .Add("productId", _productId)
                .Add("licenseKey", key)
                .Add("hwid", _hwid)
                .Add("deviceSecret", ReadDeviceSecret())
                .Add("deviceName", deviceName)
                .Add("version", version);
            return ExecuteAsync(TypeValidate, "validate", body, cancellationToken);
        }, cancellationToken);
    }

    /// <summary>Starts an in-app free trial without a license key; <see cref="VelsigilResult.TrialKey"/> holds the new key.</summary>
    /// <remarks>The server sends the trial key only once; store it. Refused (<see cref="ResultCodes.AlreadyLicensed"/>) if a license is stored.</remarks>
    public Task<VelsigilResult> StartTrialAsync(StartTrialOptions? options = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var email = string.IsNullOrWhiteSpace(options?.Email) ? null : options!.Email!.Trim();
        var invalid = CheckLength(options?.Version, MaxVersionLength, "The version string is too long (max 32 characters).")
            ?? CheckLength(options?.DeviceName, MaxDeviceNameLength, "The device name is too long (max 255 characters).")
            ?? CheckLength(email, MaxEmailLength, "The e-mail address is too long (max 254 characters).");
        if (invalid != null) return Task.FromResult(invalid);

        var deviceName = options?.DeviceName;
        var version = options?.Version;
        return WithDeviceLockAsync(() =>
        {
            // Refuse locally so a trial never overwrites this device's stored license.
            // Checked under the device lock, so no concurrent validation slips in between.
            var secret = ReadStore(store => store.GetDeviceSecret(_productId), out var secretRead);
            var lease = ReadStore(store => store.GetLeaseToken(_productId), out var leaseRead);
            if (!secretRead || !leaseRead)
            {
                // A failed read is not "nothing stored"; fail closed.
                return Task.FromResult(VelsigilResult.Failure(ResultCodes.StoreUnavailable, StoreUnavailableMessage, CurrentUnixTime()));
            }
            if (!string.IsNullOrEmpty(secret) || !string.IsNullOrEmpty(lease))
            {
                return Task.FromResult(VelsigilResult.Failure(ResultCodes.AlreadyLicensed, AlreadyLicensedMessage, CurrentUnixTime()));
            }

            var body = new RequestBody()
                .Add("productId", _productId)
                .Add("hwid", _hwid)
                .Add("deviceName", deviceName)
                .Add("version", version)
                .Add("email", email);
            return ExecuteAsync(TypeTrial, "trial", body, cancellationToken);
        }, cancellationToken);
    }

    /// <summary>Releases this device's activation slot; on success the stored secret and lease are removed.</summary>
    public Task<VelsigilResult> DeactivateAsync(string licenseKey, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var invalid = CheckLicenseKey(licenseKey, out var key);
        if (invalid != null) return Task.FromResult(invalid);

        return WithDeviceLockAsync(() =>
        {
            var body = new RequestBody()
                .Add("productId", _productId)
                .Add("licenseKey", key)
                .Add("hwid", _hwid)
                .Add("deviceSecret", ReadDeviceSecret());
            return ExecuteAsync(TypeDeactivate, "deactivate", body, cancellationToken);
        }, cancellationToken);
    }

    /// <summary>Asks for a release newer than <paramref name="currentVersion"/>; no license key needed.</summary>
    public Task<VelsigilResult> CheckUpdateAsync(string? currentVersion = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var invalid = CheckLength(currentVersion, MaxVersionLength, "The version string is too long (max 32 characters).");
        if (invalid != null) return Task.FromResult(invalid);

        var body = new RequestBody()
            .Add("productId", _productId)
            .Add("version", currentVersion);
        return ExecuteAsync(TypeUpdateCheck, "update-check", body, cancellationToken);
    }

    /// <summary>Requests a short-lived download link (latest release when <paramref name="version"/> is null).</summary>
    public Task<VelsigilResult> GetDownloadAsync(string licenseKey, string? version = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        var invalid = CheckLicenseKey(licenseKey, out var key)
            ?? CheckLength(version, MaxVersionLength, "The version string is too long (max 32 characters).");
        if (invalid != null) return Task.FromResult(invalid);

        return WithDeviceLockAsync(() =>
        {
            var body = new RequestBody()
                .Add("productId", _productId)
                .Add("licenseKey", key)
                .Add("hwid", _hwid)
                .Add("deviceSecret", ReadDeviceSecret())
                .Add("version", version);
            return ExecuteAsync(TypeDownload, "download", body, cancellationToken);
        }, cancellationToken);
    }

    /// <summary>Validates online, falling back to the stored lease only when the server is unavailable (no response or unsigned 5xx).</summary>
    /// <remarks>Signed and 4xx answers are returned as they are; check <see cref="VelsigilResult.Offline"/>.</remarks>
    public async Task<VelsigilResult> ValidateWithOfflineFallbackAsync(string licenseKey, ValidateOptions? options = null, CancellationToken cancellationToken = default)
    {
        var online = await ValidateAsync(licenseKey, options, cancellationToken).ConfigureAwait(false);
        if (!IsServerUnavailable(online)) return online;
        var offline = ValidateOffline();
        // Without any stored lease the online failure is the more useful answer.
        if (string.Equals(offline.Code, ResultCodes.NoLease, StringComparison.Ordinal)) return online;
        return offline.WithRetryAfter(online.RetryAfter);
    }

    /// <summary>Validates the stored offline lease without network access.</summary>
    public VelsigilResult ValidateOffline()
    {
        ThrowIfDisposed();
        var now = CurrentUnixTime();
        var token = ReadStore(store => store.GetLeaseToken(_productId));
        if (string.IsNullOrEmpty(token))
        {
            return VelsigilResult.OfflineFailure(ResultCodes.NoLease, "No offline lease is stored for this product; connect to the internet to validate.", now);
        }

        var verification = LeaseVerifier.Verify(token, _verifier, _productId, _hwid, now);
        return VelsigilResult.FromLease(verification, token!, now);
    }

    /// <summary>Removes the stored device secret and lease; waits for a device-bound call in progress.</summary>
    public void ClearStoredState()
    {
        ThrowIfDisposed();
        _deviceLock.Wait();
        try
        {
            WriteStore(store =>
            {
                store.SetLeaseToken(_productId, null);
                store.SetDeviceSecret(_productId, null);
            });
        }
        finally
        {
            _deviceLock.Release();
        }
    }

    /// <summary>Downloads a release from <see cref="GetDownloadAsync"/> and verifies its size and SHA-256 before moving it into place.</summary>
    /// <param name="download">The signed download grant.</param>
    /// <param name="destinationPath">Target file path (overwritten on success).</param>
    /// <param name="progress">Optional progress callback receiving the number of bytes received.</param>
    /// <param name="cancellationToken">Cancels the download (throws <see cref="OperationCanceledException"/>).</param>
    public async Task<VelsigilResult> DownloadFileAsync(
        DownloadInfo download,
        string destinationPath,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (download is null) throw new ArgumentNullException(nameof(download));
        if (string.IsNullOrWhiteSpace(destinationPath)) throw new ArgumentException("A destination path is required.", nameof(destinationPath));

        if (!TryResolveDownloadUri(download.Url, out var uri))
        {
            return VelsigilResult.Failure(ResultCodes.DownloadFailed, "The download URL is not allowed (https is required).", CurrentUnixTime());
        }

        var destination = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(destination);
        if (string.IsNullOrEmpty(directory)) throw new ArgumentException("The destination path has no directory.", nameof(destinationPath));
        var temp = Path.Combine(directory, "." + Path.GetFileName(destination) + "." + Guid.NewGuid().ToString("N") + ".part");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        // Distinguishes local file-system failures (io_error) from transport failures (network_error).
        var localIo = false;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            using var abort = timeout.Token.Register(DisposeState, response);

            var status = (int)response.StatusCode;
            if (WasRedirected(response, uri))
            {
                return VelsigilResult.Failure(ResultCodes.DownloadFailed, "The download request was redirected.", CurrentUnixTime(), status);
            }
            if (status != 200) return MapDownloadHttpFailure(response, status);
            if (response.Content.Headers.ContentLength is long declared && declared != download.Size)
            {
                return IntegrityFailure();
            }

#if NET8_0_OR_GREATER
            using var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
#else
            using var source = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
            using var sha = SHA256.Create();
            long total = 0;
            localIo = true;
            Directory.CreateDirectory(directory);
            using (var target = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, DownloadBufferSize))
            {
                var buffer = new byte[DownloadBufferSize];
                while (true)
                {
                    timeout.CancelAfter(_timeout); // inactivity timeout between reads
                    localIo = false;
                    var read = await source.ReadAsync(buffer, 0, buffer.Length, timeout.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    total += read;
                    if (total > download.Size) return IntegrityFailure();
                    sha.TransformBlock(buffer, 0, read, null, 0);
                    localIo = true;
                    await target.WriteAsync(buffer, 0, read, timeout.Token).ConfigureAwait(false);
                    progress?.Report(total);
                }
                localIo = true;
                target.Flush(flushToDisk: true);
            }

            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            var digest = Crypto.ToHex(sha.Hash ?? Array.Empty<byte>());
            if (total != download.Size || !Crypto.HexEquals(digest, download.Sha256)) return IntegrityFailure();

            FileUtil.ReplaceFile(temp, destination);
            return VelsigilResult.DownloadCompleted(download, CurrentUnixTime());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested && IsTransportException(ex))
        {
            throw new OperationCanceledException("The download was cancelled.", ex, cancellationToken);
        }
        catch (Exception ex) when (IsTransportException(ex) && !(localIo && ex is IOException))
        {
            return NetworkFailure(timeout.IsCancellationRequested);
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            return VelsigilResult.Failure(ResultCodes.IoError, "The file could not be written to the destination.", CurrentUnixTime());
        }
        finally
        {
            FileUtil.TryDelete(temp);
        }
    }

    /// <summary>Disposes the internally created <see cref="HttpClient"/> (an injected one is left alone).</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (_ownsHttpClient) _http.Dispose();
    }

    private readonly struct Exchange
    {
        private Exchange(SignedPayload? payload, VelsigilResult? failure)
        {
            Payload = payload;
            Failure = failure;
        }

        public SignedPayload? Payload { get; }

        public VelsigilResult? Failure { get; }

        public static Exchange Success(SignedPayload payload) => new Exchange(payload, null);

        public static Exchange Fail(VelsigilResult failure) => new Exchange(null, failure);
    }

    /// <summary>Runs one device-bound call under the device lock.</summary>
    private async Task<VelsigilResult> WithDeviceLockAsync(Func<Task<VelsigilResult>> operation, CancellationToken cancellationToken)
    {
        await _deviceLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await operation().ConfigureAwait(false);
        }
        finally
        {
            _deviceLock.Release();
        }
    }

    private async Task<VelsigilResult> ExecuteAsync(string type, string endpoint, RequestBody body, CancellationToken cancellationToken)
    {
        var uri = new Uri(_apiBase, endpoint);
        for (var attempt = 1; ; attempt++)
        {
            // Fresh nonce and timestamp per attempt: a retry is a new request.
            var nonce = Base64Url.Encode(Crypto.RandomBytes(NonceBytes));
            var bytes = body.Build(nonce, CurrentUnixTime());
            Exchange exchange;
            try
            {
                exchange = await SendAsync(uri, type, bytes, nonce, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // The body holds the license key and device secret; clear it.
                Array.Clear(bytes, 0, bytes.Length);
            }

            var payload = exchange.Payload;
            if (payload is null) return exchange.Failure!;

            if (!payload.Ok && string.Equals(payload.Code, ResultCodes.ClockSkew, StringComparison.Ordinal))
            {
                // Signed, nonce-bound server time: learn the offset and retry once.
                LearnClockOffset(payload.ServerTime);
                if (attempt == 1) continue;
            }

            // Reject a download URL that breaks the transport policy here, like the other SDKs.
            if (payload.Download != null && !TryResolveDownloadUri(payload.Download.Url, out _))
            {
                return InvalidResponse("The server returned a download URL that is not allowed (https is required).");
            }

            Persist(type, payload);
            return VelsigilResult.FromPayload(payload);
        }
    }

    private async Task<Exchange> SendAsync(Uri uri, string type, byte[] body, string nonce, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = HttpHelpers.JsonContent(body) };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            using var abort = timeout.Token.Register(DisposeState, response);
            var status = (int)response.StatusCode;

            // Redirects are never followed; an answer from another URI is invalid even when signed.
            if (WasRedirected(response, uri))
            {
                return Exchange.Fail(InvalidResponse("The server redirected the request."));
            }

            if (status == 200)
            {
                var raw = await HttpHelpers.ReadBodyAsync(response.Content, MaxResponseBytes, timeout.Token).ConfigureAwait(false);
                if (raw is null)
                {
                    return Exchange.Fail(InvalidResponse("The response exceeded the maximum allowed size."));
                }

                // Device-bound requests (all but update_check): the lease/activation must belong to this device.
                var boundHwid = string.Equals(type, TypeUpdateCheck, StringComparison.Ordinal) ? null : _hwid;
                var verdict = EnvelopeVerifier.Verify(_verifier, raw, nonce, _productId, type, boundHwid, out var payload);
                if (verdict != EnvelopeStatus.Valid || payload is null)
                {
                    return Exchange.Fail(InvalidResponse(DescribeEnvelopeFailure(verdict)));
                }
                return Exchange.Success(payload);
            }

            // Anything but 200 is an unsigned error and can never be a success.
            var errorBody = await HttpHelpers.ReadBodyAsync(response.Content, MaxErrorBodyBytes, timeout.Token).ConfigureAwait(false);
            var code = HttpHelpers.MapUnsignedErrorCode(status, errorBody, out var requestId, string.Equals(type, TypeTrial, StringComparison.Ordinal));
            requestId ??= HttpHelpers.ReadRequestIdHeader(response);
            // Retry-After of every 429 and 503, the same in every Velsigil SDK.
            var retryAfter = status == 429 || status == 503
                ? HttpHelpers.ReadRetryAfter(response.Headers, _clock())
                : null;
            return Exchange.Fail(VelsigilResult.Failure(code, HttpHelpers.MessageFor(code, status), CurrentUnixTime(), status, requestId, retryAfter));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested && IsTransportException(ex))
        {
            throw new OperationCanceledException("The request was cancelled.", ex, cancellationToken);
        }
        catch (Exception ex) when (IsTransportException(ex))
        {
            return Exchange.Fail(NetworkFailure(timeout.IsCancellationRequested));
        }
    }

    private void Persist(string type, SignedPayload payload)
    {
        if (payload.DeviceSecret != null)
        {
            var secret = payload.DeviceSecret;
            WriteStore(store => store.SetDeviceSecret(_productId, secret));
        }

        var revokesLease = !payload.Ok && RevokingCodeSet.Contains(payload.Code);
        switch (type)
        {
            case TypeValidate:
            case TypeTrial: // a started trial is a validation of the new license
                if (payload.Ok)
                {
                    // Replace or clear the stored lease; one that would not verify here is never stored.
                    var token = payload.Lease?.Token;
                    if (token != null && !LeaseVerifier.Verify(token, _verifier, _productId, _hwid, payload.ServerTime).IsValid)
                    {
                        token = null;
                    }
                    WriteStore(store => store.SetLeaseToken(_productId, token));
                }
                else if (revokesLease)
                {
                    WriteStore(store => store.SetLeaseToken(_productId, null));
                }
                break;

            case TypeDeactivate:
                // device_not_found also makes the secret and lease worthless.
                if (payload.Ok || string.Equals(payload.Code, ResultCodes.DeviceNotFound, StringComparison.Ordinal))
                {
                    WriteStore(store =>
                    {
                        store.SetLeaseToken(_productId, null);
                        store.SetDeviceSecret(_productId, null);
                    });
                }
                else if (revokesLease)
                {
                    WriteStore(store => store.SetLeaseToken(_productId, null));
                }
                break;

            case TypeDownload:
                if (revokesLease) WriteStore(store => store.SetLeaseToken(_productId, null));
                break;
        }
    }

    private long LocalUnixTime() => _clock().ToUnixTimeSeconds();

    private long CurrentUnixTime() => LocalUnixTime() + Interlocked.Read(ref _clockOffsetSeconds);

    private void LearnClockOffset(long serverTime) => Interlocked.Exchange(ref _clockOffsetSeconds, serverTime - LocalUnixTime());

    private string? ReadDeviceSecret()
    {
        var secret = ReadStore(store => store.GetDeviceSecret(_productId));
        return string.IsNullOrEmpty(secret) ? null : secret;
    }

    private string? ReadStore(Func<IVelsigilStore, string?> read) => ReadStore(read, out _);

    /// <summary>One store read; <paramref name="ok"/> is false when the store threw (not "nothing stored").</summary>
    private string? ReadStore(Func<IVelsigilStore, string?> read, out bool ok)
    {
        try
        {
            var value = read(_store);
            ok = true;
            return value;
        }
        catch (Exception ex)
        {
            ok = false;
            ReportStoreError(_storeErrorHandler, ex);
            return null;
        }
    }

    private void WriteStore(Action<IVelsigilStore> write)
    {
        try
        {
            write(_store);
        }
        catch (Exception ex)
        {
            ReportStoreError(_storeErrorHandler, ex);
        }
    }

    private static void ReportStoreError(Action<Exception>? handler, Exception error)
    {
        if (handler is null) return;
        try
        {
            handler(error);
        }
        catch (Exception)
        {
            // A faulty error handler must not turn a validation into an exception.
        }
    }

    private VelsigilResult? CheckLicenseKey(string? licenseKey, out string key)
    {
        key = licenseKey?.Trim() ?? string.Empty;
        if (key.Length == 0) return LocalValidationFailure("A license key is required.");
        if (key.Length > MaxLicenseKeyLength) return LocalValidationFailure("The license key is too long.");
        return null;
    }

    private VelsigilResult? CheckLength(string? value, int maxLength, string message) =>
        value != null && value.Length > maxLength ? LocalValidationFailure(message) : null;

    private VelsigilResult LocalValidationFailure(string message) =>
        VelsigilResult.Failure(ResultCodes.ValidationError, message, CurrentUnixTime());

    private VelsigilResult InvalidResponse(string message) =>
        VelsigilResult.Failure(ResultCodes.InvalidResponse, message, CurrentUnixTime(), httpStatus: 200);

    private VelsigilResult NetworkFailure(bool timedOut) =>
        VelsigilResult.Failure(
            ResultCodes.NetworkError,
            timedOut ? "The license server did not respond in time." : "The license server could not be reached.",
            CurrentUnixTime());

    private VelsigilResult IntegrityFailure() =>
        VelsigilResult.Failure(ResultCodes.IntegrityMismatch, "The downloaded file does not match the signed size and SHA-256; it was discarded.", CurrentUnixTime(), 200);

    private VelsigilResult MapDownloadHttpFailure(HttpResponseMessage response, int status)
    {
        var now = CurrentUnixTime();
        var requestId = HttpHelpers.ReadRequestIdHeader(response);
        switch (status)
        {
            case 429:
                return VelsigilResult.Failure(ResultCodes.RateLimited, HttpHelpers.MessageFor(ResultCodes.RateLimited, status), now, status, requestId,
                    HttpHelpers.ReadRetryAfter(response.Headers, _clock()));
            case 503:
                // Retry-After of every 429 and 503, as in SendAsync.
                return VelsigilResult.Failure(ResultCodes.NetworkError, HttpHelpers.MessageFor(ResultCodes.NetworkError, status), now, status, requestId,
                    HttpHelpers.ReadRetryAfter(response.Headers, _clock()));
            case 502:
            case 504:
                return VelsigilResult.Failure(ResultCodes.NetworkError, HttpHelpers.MessageFor(ResultCodes.NetworkError, status), now, status, requestId);
            case 410:
                return VelsigilResult.Failure(ResultCodes.DownloadFailed, "The download link has expired; request a new one.", now, status, requestId);
            default:
                return VelsigilResult.Failure(ResultCodes.DownloadFailed, "The download is not available.", now, status, requestId);
        }
    }

    private static string DescribeEnvelopeFailure(EnvelopeStatus status)
    {
        switch (status)
        {
            case EnvelopeStatus.InvalidSignature:
                return "The response signature is missing or invalid.";
            case EnvelopeStatus.NonceMismatch:
                return "The response does not belong to this request (nonce mismatch).";
            case EnvelopeStatus.ProductMismatch:
                return "The response is for a different product.";
            case EnvelopeStatus.TypeMismatch:
                return "The response answers a different kind of request.";
            case EnvelopeStatus.HwidMismatch:
                return "The response is for a different device (its lease or activation belongs to another hardware id).";
            default:
                return "The response is malformed.";
        }
    }

    /// <summary>Offline-fallback rule: no HTTP response, or any unsigned 5xx whatever its body.</summary>
    /// <remarks>Safe: whoever can inject an unsigned 5xx can also drop the connection, and the lease is signed.</remarks>
    private static bool IsServerUnavailable(VelsigilResult online)
    {
        if (online.Ok || online.Verified || online.Offline) return false;
        if (string.Equals(online.Code, ResultCodes.NetworkError, StringComparison.Ordinal)) return true;
        return online.HttpStatus is int status && status >= 500 && status <= 599;
    }

    private static bool IsTransportException(Exception ex) =>
        ex is HttpRequestException
        || ex is IOException
        || ex is SocketException
        || ex is OperationCanceledException
        || ex is ObjectDisposedException;

    private static void DisposeState(object? state) => (state as IDisposable)?.Dispose();

    /// <summary>True when an injected <see cref="HttpClient"/> followed a redirect to another URI.</summary>
    private static bool WasRedirected(HttpResponseMessage response, Uri requested)
    {
        var answered = response.RequestMessage?.RequestUri;
        return answered != null && answered != requested;
    }

    private bool TryResolveDownloadUri(string url, out Uri uri)
    {
        uri = _serverRoot;
        if (string.IsNullOrWhiteSpace(url)) return false;

        Uri? candidate;
        if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out candidate)) return false;
        }
        else
        {
            if (url.StartsWith("//", StringComparison.Ordinal) || !Uri.TryCreate(url, UriKind.Relative, out var relative)) return false;
            candidate = new Uri(_serverRoot, relative);
        }

        if (!IsTransportAllowed(candidate, _allowInsecureHttp) || !string.IsNullOrEmpty(candidate.UserInfo)) return false;
        uri = candidate;
        return true;
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0) throw new ObjectDisposedException(nameof(VelsigilClient));
    }

    private static string ResolveHardwareId(string? overrideValue)
    {
        if (overrideValue is null) return HardwareIdProvider.Get();
        if (overrideValue.Length < 8 || overrideValue.Length > 256)
        {
            throw new ArgumentException("VelsigilClientOptions.HardwareId must be 8 to 256 characters long.", "options");
        }
        return overrideValue;
    }

    private static IVelsigilStore CreateDefaultStore(Action<Exception>? errorHandler)
    {
        try
        {
            return FileStore.CreateDefault();
        }
        catch (InvalidOperationException ex)
        {
            ReportStoreError(errorHandler, ex);
            return new MemoryStore();
        }
    }

    private static HttpClient CreateHttpClient()
    {
        // Redirects are never followed: a redirect could forward the license key to another host.
#if NET8_0_OR_GREATER
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
#else
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
        };
#endif
        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static string NormalizeProductId(string productId)
    {
        if (productId is null || !Guid.TryParseExact(productId.Trim(), "D", out var id))
        {
            throw new ArgumentException("The product id must be a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).", nameof(productId));
        }
        return id.ToString("D");
    }

    private static Uri BuildApiBase(string apiUrl, bool allowInsecureHttp, out Uri serverRoot)
    {
        if (string.IsNullOrWhiteSpace(apiUrl)) throw new ArgumentException("The API URL is required.", nameof(apiUrl));
        if (!Uri.TryCreate(apiUrl.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("The API URL must be an absolute http(s) URL.", nameof(apiUrl));
        }
        if (!string.IsNullOrEmpty(uri.UserInfo)) throw new ArgumentException("The API URL must not contain credentials.", nameof(apiUrl));
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("The API URL must not contain a query string or fragment.", nameof(apiUrl));
        }
        if (!IsTransportAllowed(uri, allowInsecureHttp))
        {
            throw new ArgumentException(
                "The API URL must use https (plain http is only allowed for localhost, 127.0.0.1 and ::1 unless AllowInsecureHttp is set).",
                nameof(apiUrl));
        }

        const string clientApiSuffix = "/api/client/v1";
        var path = uri.AbsolutePath.TrimEnd('/');
        if (path.EndsWith(clientApiSuffix, StringComparison.OrdinalIgnoreCase))
        {
            path = path.Substring(0, path.Length - clientApiSuffix.Length);
        }

        serverRoot = new Uri(uri.Scheme + "://" + uri.Authority + path + "/", UriKind.Absolute);
        return new Uri(serverRoot, "api/client/v1/");
    }

    private static bool IsTransportAllowed(Uri uri, bool allowInsecureHttp)
    {
        if (uri.Scheme == Uri.UriSchemeHttps) return true;
        if (uri.Scheme != Uri.UriSchemeHttp) return false;
        return allowInsecureHttp || IsLoopbackHost(uri);
    }

    // The loopback hosts: plain http is allowed for them, and so are the published test keys (constructor).
    private static bool IsLoopbackHost(Uri uri)
    {
        var host = uri.Host;
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || host == "127.0.0.1") return true;
        if (uri.HostNameType != UriHostNameType.IPv6) return false;

        // Compare ::1 as bytes: .NET Framework spells it in full, and ::ffff:127.0.0.1 must not pass.
        var text = host.Length > 2 && host[0] == '[' && host[host.Length - 1] == ']' ? host.Substring(1, host.Length - 2) : host;
        if (!System.Net.IPAddress.TryParse(text, out var address) || address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length - 1; i++)
        {
            if (bytes[i] != 0) return false;
        }
        return bytes.Length == 16 && bytes[15] == 1;
    }
}
