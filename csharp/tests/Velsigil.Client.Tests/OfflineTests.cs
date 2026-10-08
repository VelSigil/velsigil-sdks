using System;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Nodes;
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

        // 1. Online: verified response, lease persisted.
        var first = await client.ValidateWithOfflineFallbackAsync(Key);
        Assert.True(first.Ok);
        Assert.False(first.Offline);
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));

        // 2. Server unreachable a few hours later: the lease carries the app.
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

        // 3. Past the lease expiry the fallback fails closed.
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
        // No lease left: the original network failure is reported (same as every Velsigil SDK).
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
    [InlineData("trial_already_used")] // SPEC 9.7: another key's trial refused on this device
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
        // LIC-4: a license-sharing proxy rewrites hwid + device secret to those of one real activation;
        // the signed answer then carries that device's lease (and a secret not meant for this device).
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
