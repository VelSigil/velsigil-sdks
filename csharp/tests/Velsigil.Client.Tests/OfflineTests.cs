using System;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

public class OfflineTests
{
    private const string Key = TestClients.LicenseKey;

    [Fact]
    public void Validate_offline_without_a_lease()
    {
        using var client = TestClients.Create(new MockServer());

        var result = client.ValidateOffline();

        Assert.False(result.Ok);
        Assert.True(result.Offline);
        Assert.Equal(ResultCodes.NoLease, result.Code);
        Assert.False(result.Verified);
    }

    [Fact]
    public async Task Fallback_uses_the_stored_lease_only_when_the_server_is_unreachable()
    {
        var online = true;
        var server = new MockServer
        {
            Handler = (r, _) => online
                ? Task.FromResult(Responses.Signed(Payloads.ValidateOk(r)))
                : throw new HttpRequestException("Connection refused"),
        };
        var store = new MemoryStore();
        var clock = new FakeClock(Payloads.ServerTime);
        using var client = TestClients.Create(server, store, clock);

        var first = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.True(first.Ok);
        Assert.False(first.Offline);
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));

        // Hours later, with the server unreachable.
        online = false;
        clock.Advance(TimeSpan.FromHours(6));
        var offline = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.True(offline.Ok);
        Assert.True(offline.Offline);
        Assert.True(offline.Verified);
        Assert.Equal(ResultCodes.Ok, offline.Code);
        Assert.True(offline.HasFeature("pro"));
        Assert.Equal("5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f", offline.LeaseClaims!.LicenseId);
        Assert.Equal(Vectors.LeaseExpiresAt, offline.Lease!.ExpiresAtUnix);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1769817600), offline.ExpiresAt);
        Assert.Null(offline.RequestId);

        // Past the lease expiry the fallback fails closed.
        clock.Now = DateTimeOffset.FromUnixTimeSeconds(Vectors.LeaseExpiresAt);
        var expired = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.False(expired.Ok);
        Assert.True(expired.Offline);
        Assert.Equal(ResultCodes.LeaseExpired, expired.Code);
        Assert.False(expired.HasFeature("pro"));
    }

    [Fact]
    public async Task Fallback_also_applies_to_gateway_errors()
    {
        var server = new MockServer();
        server.Respond(_ => Responses.Text(503, "Service Unavailable", "text/plain"));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.True(result.Ok);
        Assert.True(result.Offline);
    }

    [Theory]
    [InlineData("license_revoked")]
    [InlineData("license_suspended")]
    public async Task Fallback_is_not_used_when_the_server_answers_and_revocation_clears_the_lease(string code)
    {
        var online = true;
        var server = new MockServer
        {
            Handler = (r, _) => online
                ? Task.FromResult(Responses.Signed(Payloads.Base(r, false, code, "Denied.")))
                : throw new HttpRequestException("Connection refused"),
        };
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var denied = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.False(denied.Ok);
        Assert.False(denied.Offline);
        Assert.Equal(code, denied.Code);
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));

        online = false;
        var later = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.False(later.Ok);
        // No lease left: the original network failure is reported.
        Assert.Equal(ResultCodes.NetworkError, later.Code);
        Assert.False(later.Offline);
        Assert.Equal(ResultCodes.NoLease, client.ValidateOffline().Code);
    }

    [Fact]
    public async Task Fallback_without_a_stored_lease_returns_the_original_network_error()
    {
        var server = new MockServer { Handler = (_, _) => throw new HttpRequestException("Connection refused") };
        using var client = TestClients.Create(server, new MemoryStore());

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.False(result.Ok);
        Assert.False(result.Offline);
        Assert.Equal(ResultCodes.NetworkError, result.Code);
        Assert.Null(result.LeaseStatus);
    }

    /// <summary>Unsigned 5xx answers: database down, app down behind a proxy, gateway timeout, odd bodies.</summary>
    private static HttpResponseMessage Unavailable(string kind) => kind switch
    {
        "500-json" => Responses.Error(500, "internal_error"),
        "503-json-busy" => Responses.Error(503, "service_busy", headers: new[] { ("Retry-After", "5") }),
        "503-empty" => Responses.Empty(503, ("Retry-After", "30")),
        "502-html" => Responses.Text(502, "<html><head><title>502 Bad Gateway</title></head><body>Bad Gateway</body></html>"),
        "504-empty" => Responses.Empty(504),
        "500-empty" => Responses.Empty(500),
        "500-garbled" => Responses.Text(500, "{\"error\":{\"code\":\"internal_err", "application/json"),
        "501-html" => Responses.Text(501, "<html>Not Implemented</html>"),
        "599-text" => Responses.Text(599, "Network connect timeout error", "text/plain"),
        "503-json-rate-limited" => Responses.Error(503, "rate_limited"), // the status decides, not the body's code
        "503-oversized" => Responses.Text(503, new string('x', 70 * 1024)), // over the 64 KB error-body cap
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    [Theory]
    [InlineData("500-json", 500, "internal_error")]
    [InlineData("503-json-busy", 503, "internal_error")]
    [InlineData("503-empty", 503, "network_error")]
    [InlineData("502-html", 502, "network_error")]
    [InlineData("504-empty", 504, "network_error")]
    [InlineData("500-empty", 500, "internal_error")]
    [InlineData("500-garbled", 500, "internal_error")]
    [InlineData("501-html", 501, "internal_error")]
    [InlineData("599-text", 599, "internal_error")]
    [InlineData("503-json-rate-limited", 503, "rate_limited")]
    [InlineData("503-oversized", 503, "network_error")]
    public async Task Fallback_uses_the_stored_lease_when_the_server_answers_an_unsigned_5xx(string kind, int status, string onlineCode)
    {
        var server = new MockServer();
        server.Respond(_ => Unavailable(kind));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        store.SetDeviceSecret(Vectors.ProductId, Payloads.DeviceSecret);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        // ValidateAsync itself never falls back.
        var online = await client.ValidateAsync(Key);
        Assert.False(online.Ok);
        Assert.False(online.Offline);
        Assert.False(online.Verified);
        Assert.Equal(onlineCode, online.Code);
        Assert.Equal(status, online.HttpStatus);

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.True(result.Ok);
        Assert.True(result.Offline);
        Assert.True(result.Verified);
        Assert.Equal(ResultCodes.Ok, result.Code);
        Assert.Equal(LeaseStatus.Valid, result.LeaseStatus);
        Assert.True(result.HasFeature("pro"));
        Assert.Equal(2, server.Requests.Count); // one online attempt per call, no retry
        // An unsigned answer never touches the stored state.
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    [Theory]
    [InlineData("500-json", 500, "internal_error")]
    [InlineData("503-json-busy", 503, "internal_error")]
    [InlineData("503-empty", 503, "network_error")]
    [InlineData("502-html", 502, "network_error")]
    [InlineData("504-empty", 504, "network_error")]
    [InlineData("500-garbled", 500, "internal_error")]
    public async Task Fallback_without_a_stored_lease_returns_the_original_5xx_error(string kind, int status, string expected)
    {
        var server = new MockServer();
        server.Respond(_ => Unavailable(kind));
        using var client = TestClients.Create(server, new MemoryStore(), new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.False(result.Ok);
        Assert.False(result.Offline);
        Assert.False(result.Verified);
        Assert.Equal(expected, result.Code);
        Assert.Equal(status, result.HttpStatus);
        Assert.Null(result.LeaseStatus);
        Assert.Equal(kind.Contains("-json", StringComparison.Ordinal) ? "11111111-2222-4333-8444-555555555555" : null, result.RequestId);
    }

    [Theory]
    [InlineData("500-json")]
    [InlineData("503-empty")]
    [InlineData("502-html")]
    [InlineData("504-empty")]
    public async Task Fallback_with_an_expired_lease_returns_lease_expired(string kind)
    {
        var server = new MockServer();
        server.Respond(_ => Unavailable(kind));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Vectors.LeaseExpiresAt));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.False(result.Ok);
        Assert.True(result.Offline);
        Assert.Equal(ResultCodes.LeaseExpired, result.Code);
        Assert.Equal(LeaseStatus.Expired, result.LeaseStatus);
        Assert.False(result.HasFeature("pro"));
    }

    [Theory]
    [InlineData("500-json")]
    [InlineData("503-empty")]
    public async Task Fallback_with_an_unusable_lease_returns_lease_invalid(string kind)
    {
        var server = new MockServer();
        server.Respond(_ => Unavailable(kind));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, "not-a-lease-token");
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.False(result.Ok);
        Assert.True(result.Offline);
        Assert.Equal(ResultCodes.LeaseInvalid, result.Code);
        Assert.False(result.Verified);
    }

    [Theory]
    [InlineData("429", "rate_limited", 429)]
    [InlineData("400", "validation_error", 400)]
    [InlineData("400-internal-error-body", "internal_error", 400)] // a 4xx stays final whatever code its body carries
    [InlineData("404-html", "invalid_response", 404)]
    [InlineData("200-html", "invalid_response", 200)]               // a proxy page with status 200 is not "unavailable"
    [InlineData("bad-signature", "invalid_response", 200)]
    [InlineData("signed-revoked", "license_revoked", 200)]
    [InlineData("signed-expired", "license_expired", 200)]
    [InlineData("signed-paused", "product_paused", 200)]
    public async Task Fallback_is_not_used_for_final_answers(string kind, string expected, int status)
    {
        var server = new MockServer();
        server.Respond(r => kind switch
        {
            "429" => Responses.Error(429, "rate_limited", headers: new[] { ("Retry-After", "12") }),
            "400" => Responses.Error(400, "validation_error"),
            "400-internal-error-body" => Responses.Error(400, "internal_error"),
            "404-html" => Responses.Text(404, "<html>Not Found</html>"),
            "200-html" => Responses.Text(200, "<html>Maintenance</html>"),
            "bad-signature" => Responses.Signed(Payloads.ValidateOk(r), TestSigner.Wrong),
            "signed-revoked" => Responses.Signed(Payloads.Base(r, false, "license_revoked", "Revoked.")),
            "signed-expired" => Responses.Signed(Payloads.Base(r, false, "license_expired", "Expired.")),
            "signed-paused" => Responses.Signed(Payloads.Base(r, false, "product_paused", "Paused.")),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.False(result.Ok);
        Assert.False(result.Offline);
        Assert.Equal(expected, result.Code);
        Assert.Equal(status, result.HttpStatus);
        Assert.Null(result.LeaseStatus);
        Assert.Equal(kind == "429" ? TimeSpan.FromSeconds(12) : (TimeSpan?)null, result.RetryAfter);
        // Revoking denials delete the lease; other final answers keep it.
        var revokes = kind == "signed-revoked" || kind == "signed-expired";
        Assert.Equal(revokes ? null : Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
    }

    [Fact]
    public async Task Fallback_applies_to_a_client_side_timeout()
    {
        var server = new MockServer
        {
            Handler = async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            },
        };
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60), timeout: TimeSpan.FromSeconds(1));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.True(result.Ok);
        Assert.True(result.Offline);
    }

    [Theory]
    [InlineData("503-empty", "network_error")] // what a server answers while its database is unreachable
    [InlineData("500-json", "internal_error")]
    [InlineData("502-html", "network_error")]
    public async Task Fallback_over_real_sockets_with_the_default_http_client(string kind, string onlineCode)
    {
        using var http = new LocalHttpServer(_ => Unavailable(kind));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = new VelsigilClient(http.BaseUrl, Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { Store = store, HardwareId = Vectors.TestHwid, Clock = new FakeClock(Payloads.ServerTime + 60).GetNow });

        var online = await client.ValidateAsync(Key);
        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.Equal(onlineCode, online.Code);
        // The empty 503 carries Retry-After: 30, and the fallback result keeps it.
        var retryAfter = kind == "503-empty" ? TimeSpan.FromSeconds(30) : (TimeSpan?)null;
        Assert.Equal(retryAfter, online.RetryAfter);
        Assert.True(result.Ok);
        Assert.True(result.Offline);
        Assert.Equal(retryAfter, result.RetryAfter);
        Assert.Equal(2, http.Requests.Count);
    }

    [Theory]
    [InlineData("503-empty", 30)]     // the empty 503 of a database outage
    [InlineData("503-json-busy", 5)]  // 503 service_busy
    [InlineData("500-json", null)]
    [InlineData("502-html", null)]
    public async Task Fallback_results_carry_the_retry_after_of_the_failed_online_answer(string kind, int? seconds)
    {
        var expected = seconds.HasValue ? TimeSpan.FromSeconds(seconds.Value) : (TimeSpan?)null;
        var server = new MockServer();
        server.Respond(_ => Unavailable(kind));
        VelsigilClient ClientWith(string? lease, long now)
        {
            var store = new MemoryStore();
            if (lease != null) store.SetLeaseToken(Vectors.ProductId, lease);
            return TestClients.Create(server, store, new FakeClock(now));
        }

        using var valid = ClientWith(Vectors.ValidLeaseToken, Payloads.ServerTime + 60);
        using var expired = ClientWith(Vectors.ValidLeaseToken, Vectors.LeaseExpiresAt);
        using var invalid = ClientWith("not-a-lease-token", Payloads.ServerTime + 60);
        using var none = ClientWith(null, Payloads.ServerTime + 60);

        foreach (var (client, code) in new[] { (valid, ResultCodes.Ok), (expired, ResultCodes.LeaseExpired), (invalid, ResultCodes.LeaseInvalid) })
        {
            var result = await client.ValidateWithOfflineFallbackAsync(Key);
            Assert.Equal(code, result.Code);
            Assert.True(result.Offline);
            Assert.Equal(expected, result.RetryAfter);
        }
        // Nothing stored: the online result itself, which already has it.
        var original = await none.ValidateWithOfflineFallbackAsync(Key);
        Assert.False(original.Offline);
        Assert.Equal(expected, original.RetryAfter);
        // A direct offline check made no online attempt.
        var direct = valid.ValidateOffline();
        Assert.True(direct.Ok);
        Assert.Null(direct.RetryAfter);
    }

    [Fact]
    public async Task Fallback_after_a_connection_failure_has_no_retry_after()
    {
        var server = new MockServer { Handler = (_, _) => throw new HttpRequestException("Connection refused") };
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.True(result.Ok);
        Assert.True(result.Offline);
        Assert.Null(result.RetryAfter);
    }

    [Fact]
    public void Lease_revoking_codes_are_exactly_the_binding_cross_sdk_set()
    {
        var binding = new[]
        {
            "invalid_key", "license_expired", "license_suspended", "license_revoked", "license_banned", "device_revoked",
            "device_verification_failed", "device_limit_reached", "device_not_activated", "device_not_found", "blacklisted",
            "product_disabled",
        };
        Assert.Equal(binding.OrderBy(c => c, StringComparer.Ordinal), VelsigilClient.LeaseRevokingCodes.OrderBy(c => c, StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("invalid_key")]
    [InlineData("license_expired")]
    [InlineData("license_banned")]
    [InlineData("device_revoked")]
    [InlineData("device_verification_failed")]
    [InlineData("device_limit_reached")]
    [InlineData("device_not_activated")]
    [InlineData("blacklisted")]
    [InlineData("product_disabled")]
    public async Task Definitive_signed_denials_clear_the_lease_but_keep_the_device_secret(string code)
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, code, "Denied.")));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        store.SetDeviceSecret(Vectors.ProductId, Payloads.DeviceSecret);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateAsync(Key);

        Assert.Equal(code, result.Code);
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    [Theory]
    [InlineData("product_paused")]
    [InlineData("outdated_version")]
    [InlineData("activation_rate_limited")]
    [InlineData("activations_disabled")]
    [InlineData("replay_detected")]
    [InlineData("trial_already_used")] // another key's trial refused on this device
    public async Task Non_definitive_signed_failures_keep_the_lease(string code)
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, code, "Not now.")));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateAsync(Key);

        Assert.Equal(code, result.Code);
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
        Assert.True(client.ValidateOffline().Ok);
    }

    [Fact]
    public async Task Deactivate_device_not_found_clears_secret_and_lease()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, "device_not_found", "Unknown device.")));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        store.SetDeviceSecret(Vectors.ProductId, Payloads.DeviceSecret);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.DeactivateAsync(Key);

        Assert.Equal(ResultCodes.DeviceNotFound, result.Code);
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
    }

    [Theory]
    [InlineData("invalid_response")]
    [InlineData("rate_limited")]
    public async Task Fallback_is_not_used_for_invalid_responses_or_rate_limits(string expected)
    {
        var server = new MockServer();
        server.Respond(r => expected == "rate_limited"
            ? Responses.Error(429, "rate_limited")
            : Responses.Signed(Payloads.ValidateOk(r), TestSigner.Wrong));
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateWithOfflineFallbackAsync(Key);

        Assert.False(result.Ok);
        Assert.False(result.Offline);
        Assert.Equal(expected, result.Code);
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
    }

    [Fact]
    public void Lifetime_lease_reports_lifetime_license()
    {
        var token = TestSigner.Primary.LeaseToken(new JsonObject
        {
            ["v"] = 1,
            ["typ"] = "lease",
            ["productId"] = Vectors.ProductId,
            ["licenseId"] = "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
            ["activationId"] = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d",
            ["hwidHash"] = HardwareId.HashHwid(Vectors.TestHwid),
            ["plan"] = "Lifetime",
            ["features"] = new JsonArray("pro"),
            ["licenseExpiresAt"] = null,
            ["iat"] = Payloads.ServerTime,
            ["exp"] = Payloads.ServerTime + 86400,
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, token);
        using var client = TestClients.Create(new MockServer(), store, new FakeClock(Payloads.ServerTime + 10));

        var result = client.ValidateOffline();

        Assert.True(result.Ok);
        Assert.True(result.IsLifetime);
        Assert.Null(result.ExpiresAt);
        Assert.Null(result.TimeRemaining);
        Assert.Null(result.DaysRemaining);
        Assert.Equal("Lifetime", result.LeaseClaims!.Plan);
    }

    [Fact]
    public void Lease_from_another_hwid_override_is_rejected()
    {
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = new VelsigilClient(TestClients.ApiUrl, Vectors.ProductId, Vectors.PublicKey, new VelsigilClientOptions
        {
            Store = store,
            HardwareId = "another-device-hwid",
            Clock = new FakeClock(Payloads.ServerTime + 60).GetNow,
        });

        var result = client.ValidateOffline();

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.LeaseInvalid, result.Code);
        Assert.Equal(LeaseStatus.HwidMismatch, result.LeaseStatus);
    }

    [Fact]
    public async Task A_success_whose_lease_belongs_to_another_device_is_rejected_and_nothing_is_stored()
    {
        // A license-sharing proxy rewrote the request, so the signed answer carries another device's lease.
        var foreignLease = TestSigner.Primary.LeaseToken(new JsonObject
        {
            ["v"] = 1,
            ["typ"] = "lease",
            ["productId"] = Vectors.ProductId,
            ["licenseId"] = "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
            ["activationId"] = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d",
            ["hwidHash"] = HardwareId.HashHwid("some-other-device"),
            ["plan"] = "Monthly",
            ["features"] = new JsonArray("pro"),
            ["licenseExpiresAt"] = null,
            ["iat"] = Payloads.ServerTime,
            ["exp"] = Payloads.ServerTime + 86400,
        });
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["lease"] = Payloads.Lease(foreignLease, Payloads.ServerTime + 86400);
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Contains("different device", result.Message, StringComparison.Ordinal);
        Assert.False(result.Verified);
        Assert.Null(result.License);
        Assert.False(result.HasFeature("pro"));
        // The own lease survives, the foreign device secret is not persisted.
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        // invalid_response never triggers the offline fallback.
        var fallback = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.Equal(ResultCodes.InvalidResponse, fallback.Code);
        Assert.False(fallback.Offline);
    }

    [Fact]
    public async Task An_own_lease_that_is_unusable_for_other_reasons_is_not_stored_but_the_success_stands()
    {
        var expiredLease = TestSigner.Primary.LeaseToken(new JsonObject
        {
            ["v"] = 1,
            ["typ"] = "lease",
            ["productId"] = Vectors.ProductId,
            ["licenseId"] = "5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f",
            ["activationId"] = "9a7b6c5d-4e3f-4a1b-8c2d-1e0f9a8b7c6d",
            ["hwidHash"] = HardwareId.HashHwid(Vectors.TestHwid),
            ["plan"] = "Monthly",
            ["features"] = new JsonArray("pro"),
            ["licenseExpiresAt"] = null,
            ["iat"] = Payloads.ServerTime - 7200,
            ["exp"] = Payloads.ServerTime - 3600,
        });
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["lease"] = Payloads.Lease(expiredLease, Payloads.ServerTime - 3600);
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync(Key);

        Assert.True(result.Ok);
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    [Fact]
    public void Clear_stored_state_removes_secret_and_lease()
    {
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        store.SetDeviceSecret(Vectors.ProductId, Payloads.DeviceSecret);
        using var client = TestClients.Create(new MockServer(), store);

        client.ClearStoredState();

        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(ResultCodes.NoLease, client.ValidateOffline().Code);
    }
}
