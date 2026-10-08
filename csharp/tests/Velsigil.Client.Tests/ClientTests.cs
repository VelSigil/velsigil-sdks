using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

public class ClientTests
{
    private const string Key = TestClients.LicenseKey;

    // ---- Happy path -----------------------------------------------------------------------------------

    [Fact]
    public async Task Validate_ok_returns_verified_license_and_persists_secret_and_lease()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.ValidateOk(r)));
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync("  " + Key + " ", new ValidateOptions { Version = "1.2.0", DeviceName = "Workstation" });

        Assert.True(result.Ok);
        Assert.Equal(ResultCodes.Ok, result.Code);
        Assert.Equal("License is valid.", result.Message);
        Assert.True(result.Verified);
        Assert.False(result.Offline);
        Assert.Equal(200, result.HttpStatus);
        Assert.Equal("3f2e1d0c-9b8a-4765-a432-10fedcba9876", result.RequestId);
        Assert.Equal(Payloads.ServerTime, result.ServerTimeUnix);

        var license = result.License!;
        Assert.Equal("5d2c8e4a-3f1b-4c6d-9e8f-0a1b2c3d4e5f", license.Id);
        Assert.Equal("Monthly", license.Plan);
        Assert.Equal(LicenseStatuses.Active, license.Status);
        Assert.Equal(2, license.MaxDevices);
        Assert.Equal(1, license.DevicesUsed);
        Assert.True(result.HasFeature("pro"));
        Assert.True(result.HasFeature("export"));
        Assert.False(result.HasFeature("Pro"));
        Assert.False(result.HasFeature("enterprise"));

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1769817600), result.ExpiresAt);
        Assert.False(result.IsLifetime);
        Assert.Equal(30, result.DaysRemaining);
        Assert.Equal(TimeSpan.FromDays(30), result.TimeRemaining);
        Assert.True(result.IsExpiringWithin(TimeSpan.FromDays(31)));
        Assert.False(result.IsExpiringWithin(TimeSpan.FromDays(29)));
        Assert.Equal(TimeSpan.Zero, result.GetTimeRemaining(DateTimeOffset.FromUnixTimeSeconds(1769817600 + 10)));

        Assert.True(result.Activation!.DeviceSecretIssued);
        Assert.Equal(Vectors.ValidLeaseToken, result.Lease!.Token);
        Assert.Equal("1.4.0", result.Update!.LatestVersion);
        Assert.True(result.Update.UpdateAvailable);

        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));

        var request = server.Requests.Single();
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/api/client/v1/validate", request.Path);
        Assert.StartsWith("application/json", request.Headers["Content-Type"], StringComparison.Ordinal);
        Assert.StartsWith("Velsigil.Client/", request.Headers["User-Agent"], StringComparison.Ordinal);
        Assert.Equal(
            new[] { "deviceName", "hwid", "licenseKey", "nonce", "productId", "timestamp", "version" },
            request.Json!.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(Vectors.ProductId, request.Field("productId"));
        Assert.Equal(Key, request.Field("licenseKey"));
        Assert.Equal(Vectors.TestHwid, request.Field("hwid"));
        Assert.Equal("Workstation", request.Field("deviceName"));
        Assert.Equal("1.2.0", request.Field("version"));
        Assert.Equal(43, request.Nonce.Length);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", request.Nonce);
        Assert.Equal(Payloads.ServerTime, request.Timestamp);
    }

    [Fact]
    public async Task Result_ToString_never_contains_secrets()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.ValidateOk(r)));
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        var text = result.ToString();
        Assert.DoesNotContain(Key, text, StringComparison.Ordinal);
        Assert.DoesNotContain(Payloads.DeviceSecret, text, StringComparison.Ordinal);
        Assert.DoesNotContain(Vectors.ValidLeaseToken, text, StringComparison.Ordinal);
        Assert.DoesNotContain(Payloads.DeviceSecret, result.Activation!.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_request_uses_a_fresh_nonce()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.ValidateOk(r, newDeviceSecret: null)));
        using var client = TestClients.Create(server);

        for (var i = 0; i < 5; i++) Assert.True((await client.ValidateAsync(Key)).Ok);

        var nonces = server.Requests.Select(r => r.Nonce).ToList();
        Assert.Equal(nonces.Count, nonces.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task Concurrent_calls_are_safe()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.ValidateOk(r)));
        using var client = TestClients.Create(server);

        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => client.ValidateAsync(Key))));

        Assert.All(results, r => Assert.True(r.Ok));
        Assert.Equal(32, server.Requests.Select(r => r.Nonce).Distinct(StringComparer.Ordinal).Count());
    }

    // Final sweep F-SDK-2: device-bound calls are serialized per client (as in the Node and Python SDKs), so the
    // second of two concurrent first activations sends the secret the first one stored instead of none (which the
    // server counts as a secret mismatch, and strict binding answers with device_verification_failed).
    [Fact]
    public async Task Concurrent_first_activations_send_the_secret_the_first_one_stored()
    {
        var server = new MockServer();
        var issued = 0;
        server.Handler = async (request, cancellationToken) =>
        {
            await Task.Delay(50, cancellationToken); // keep the first call in flight while the second one starts
            var first = Interlocked.Exchange(ref issued, 1) == 0;
            return Responses.Signed(Payloads.ValidateOk(request, first ? Payloads.DeviceSecret : null));
        };
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var results = await Task.WhenAll(client.ValidateAsync(Key), client.ValidateAsync(Key), client.GetDownloadAsync(Key));

        Assert.True(results[0].Ok);
        Assert.True(results[1].Ok);
        var requests = server.Requests;
        Assert.Equal(3, requests.Count);
        Assert.False(requests[0].Has("deviceSecret"));
        Assert.Equal(Payloads.DeviceSecret, requests[1].Field("deviceSecret"));
        Assert.Equal(Payloads.DeviceSecret, requests[2].Field("deviceSecret"));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    // ---- Device secret ------------------------------------------------------------------------------

    [Fact]
    public async Task Device_secret_is_persisted_and_sent_on_every_request_across_instances()
    {
        var directory = TestClients.TempDirectory();
        var server = new MockServer();
        var issued = false;
        server.Respond(r =>
        {
            switch (Payloads.TypeFor(r))
            {
                case "validate":
                {
                    // Issue the secret once, like the server does for a new device.
                    var payload = Payloads.ValidateOk(r, newDeviceSecret: issued ? null : Payloads.DeviceSecret);
                    issued = true;
                    return Responses.Signed(payload);
                }
                case "download":
                {
                    var payload = Payloads.Base(r, true, "ok", "Download ready.");
                    payload["download"] = new JsonObject
                    {
                        ["url"] = "/api/download/token", ["expiresAt"] = Payloads.ServerTime + 600, ["fileName"] = "app.zip",
                        ["size"] = 3, ["sha256"] = new string('a', 64), ["version"] = "1.4.0",
                    };
                    return Responses.Signed(payload);
                }
                default:
                    return Responses.Signed(Payloads.Base(r, true, "ok", "Device deactivated."));
            }
        });

        using (var first = TestClients.Create(server, new FileStore(directory)))
        {
            var activation = await first.ValidateAsync(Key);
            Assert.True(activation.Ok);
            Assert.False(server.Requests[0].Has("deviceSecret"));
        }

        using var second = TestClients.Create(server, new FileStore(directory));
        Assert.True((await second.ValidateAsync(Key)).Ok);
        Assert.True((await second.GetDownloadAsync(Key)).Ok);
        Assert.True((await second.DeactivateAsync(Key)).Ok);

        var requests = server.Requests;
        Assert.Equal(4, requests.Count);
        Assert.All(requests.Skip(1), r => Assert.Equal(Payloads.DeviceSecret, r.Field("deviceSecret")));
        Assert.Equal("/api/client/v1/deactivate", requests[3].Path);
        Assert.Equal(
            new[] { "deviceSecret", "hwid", "licenseKey", "nonce", "productId", "timestamp" },
            requests[3].Json!.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));

        // Successful deactivation forgets the device secret and the lease.
        var reloaded = new FileStore(directory);
        Assert.Null(reloaded.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(reloaded.GetLeaseToken(Vectors.ProductId));
    }

    [Fact]
    public async Task Device_secret_from_an_unverified_response_is_never_stored()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.ValidateOk(r), TestSigner.Wrong));
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync(Key);

        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
    }

    // ---- Business failures --------------------------------------------------------------------------

    [Theory]
    [InlineData("license_suspended", true)]
    [InlineData("license_revoked", true)]
    [InlineData("license_banned", true)]
    [InlineData("license_expired", true)]
    [InlineData("invalid_key", true)]
    [InlineData("device_revoked", true)]
    [InlineData("device_verification_failed", true)]
    [InlineData("blacklisted", true)]
    [InlineData("product_disabled", true)]
    [InlineData("device_limit_reached", true)] // SPEC 14 binding lease-clearing set
    [InlineData("product_paused", false)]
    [InlineData("outdated_version", false)]
    [InlineData("activation_cooldown", false)]
    [InlineData("replay_detected", false)]
    [InlineData("trial_already_used", false)]
    public async Task Business_failure_is_a_result_not_an_exception(string code, bool clearsLease)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, false, code, "Signed failure: " + code);
            payload["license"] = Payloads.License(status: "suspended");
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        store.SetDeviceSecret(Vectors.ProductId, Payloads.DeviceSecret);
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(code, result.Code);
        Assert.Equal("Signed failure: " + code, result.Message);
        Assert.True(result.Verified);
        Assert.False(result.HasFeature("pro")); // features never unlock on failure
        Assert.Equal("suspended", result.License!.Status);
        Assert.Equal(clearsLease ? null : Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    // SPEC 9.7: the optional signed "trial" field of the license.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Trial_flag_is_read_from_the_signed_license(bool trial)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "License is valid.");
            var license = Payloads.License();
            if (trial) license["trial"] = true;
            payload["license"] = license;
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server, new MemoryStore());

        var result = await client.ValidateAsync(Key);

        Assert.True(result.Ok);
        Assert.Equal(trial, result.IsTrial);
        Assert.Equal(trial, result.License!.IsTrial);
    }

    [Fact]
    public async Task Non_boolean_trial_field_is_an_invalid_response()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "License is valid.");
            var license = Payloads.License();
            license["trial"] = "yes";
            payload["license"] = license;
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server, new MemoryStore());

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.False(result.IsTrial);
    }

    // SPEC 9.7: the trial conversion reference is exposed as is; anything but a well-formed string is refused.
    [Theory]
    [InlineData("vtr1_Ab3_-Ab3_-Ab3_-", true)]
    [InlineData("has space", false)]
    [InlineData("", false)]
    [InlineData(42, false)]
    public async Task Trial_reference_field_is_exposed_or_refused(object value, bool valid)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "License is valid.");
            var license = Payloads.License();
            license["trialRef"] = value is string text ? System.Text.Json.Nodes.JsonValue.Create(text) : System.Text.Json.Nodes.JsonValue.Create((int)value);
            license["trial"] = true;
            payload["license"] = license;
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server, new MemoryStore());

        var result = await client.ValidateAsync(Key);

        if (valid)
        {
            Assert.True(result.Ok);
            Assert.Equal(value, result.TrialRef);
            Assert.Equal("https://shop.example.com/buy?velsigil_trial=" + value, result.WithTrialRef("https://shop.example.com/buy"));
        }
        else
        {
            Assert.False(result.Ok);
            Assert.Equal(ResultCodes.InvalidResponse, result.Code);
            Assert.Null(result.TrialRef);
        }
    }

    // MONEY-V1: a signed denial never unlocks a feature through License.HasFeature either, even when an
    // (older) server still listed the plan's features on it; License.Features stays informational.
    [Theory]
    [InlineData("license_revoked", "revoked")]
    [InlineData("license_banned", "banned")]
    [InlineData("license_suspended", "suspended")]
    [InlineData("license_expired", "expired")]
    [InlineData("device_limit_reached", "active")]
    public async Task Denial_with_features_grants_nothing_through_the_license(string code, string status)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, false, code, "Signed failure: " + code);
            payload["license"] = Payloads.License(status: status);
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server, new MemoryStore());

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(status, result.License!.Status);
        Assert.Equal(new[] { "pro", "export" }, result.License.Features);
        Assert.False(result.License.HasFeature("pro"));
        Assert.False(result.HasFeature("pro"));
    }

    [Fact]
    public async Task Ok_result_grants_features_through_the_license()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "License is valid.");
            payload["license"] = Payloads.License();
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server, new MemoryStore());

        var result = await client.ValidateAsync(Key);

        Assert.True(result.Ok, result.Message);
        Assert.True(result.License!.HasFeature("pro"));
        Assert.False(result.License.HasFeature("enterprise"));
        Assert.True(result.HasFeature("pro"));
    }

    [Fact]
    public async Task Successful_validation_without_lease_clears_the_stored_lease()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.ValidateOk(r, newDeviceSecret: null);
            payload["lease"] = null;
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store);

        Assert.True((await client.ValidateAsync(Key)).Ok);
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
    }

    // ---- Hostile / broken responses -----------------------------------------------------------------

    public static IEnumerable<object[]> HostileResponses()
    {
        yield return Case("signed with another key", r => Responses.Signed(Payloads.ValidateOk(r), TestSigner.Wrong));
        yield return Case("nonce mismatch", r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["nonce"] = "some-other-nonce-0000000000000000";
            return Responses.Signed(payload);
        });
        yield return Case("product mismatch", r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["productId"] = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6";
            return Responses.Signed(payload);
        });
        yield return Case("type mismatch", r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["type"] = "download";
            return Responses.Signed(payload);
        });
        yield return Case("tampered data", r =>
        {
            var envelope = JsonNode.Parse(TestSigner.Primary.Envelope(Payloads.ValidateOk(r)))!.AsObject();
            var forged = Payloads.ValidateOk(r);
            forged["license"]!["maxDevices"] = 999;
            envelope["data"] = TestSigner.EncodePayload(forged);
            return Responses.Json(200, envelope.ToJsonString());
        });
        yield return Case("missing signature", r =>
        {
            var envelope = JsonNode.Parse(TestSigner.Primary.Envelope(Payloads.ValidateOk(r)))!.AsObject();
            envelope.Remove("sig");
            return Responses.Json(200, envelope.ToJsonString());
        });
        yield return Case("signature over padded data", r =>
        {
            var data = TestSigner.EncodePayload(Payloads.ValidateOk(r)) + "==";
            return Responses.Json(200, new JsonObject { ["data"] = data, ["sig"] = TestSigner.Primary.SignAscii(data) }.ToJsonString());
        });
        yield return Case("unsupported version", r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["v"] = 2;
            return Responses.Signed(payload);
        });
        yield return Case("malformed license", r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["license"]!["features"] = "pro";
            return Responses.Signed(payload);
        });
        yield return Case("ok as string", r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["ok"] = "true";
            return Responses.Signed(payload);
        });
        yield return Case("unsigned payload", r => Responses.Json(200, Payloads.ValidateOk(r).ToJsonString()));
        yield return Case("unsigned ping-style body", _ => Responses.Json(200, "{\"ok\":true,\"serverTime\":1767225600}"));
        yield return Case("html captive portal", _ => Responses.Text(200, "<html><body>Login to Wi-Fi</body></html>"));
        yield return Case("empty body", _ => Responses.Text(200, string.Empty));
        yield return Case("oversized body", _ => Responses.Text(200, "{\"data\":\"" + new string('A', 1_200_000) + "\"}", "application/json"));
        yield return Case("signed envelope with non-200 status", r => Responses.Json(201, TestSigner.Primary.Envelope(Payloads.ValidateOk(r))));
        yield return Case("redirect", _ =>
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.Found);
            response.Headers.Location = new Uri("https://evil.example/collect");
            return response;
        });
        yield return Case("unknown error code", _ => Responses.Error(418, "totally_ok")); // 400 maps to validation_error (SPEC 14)

        static object[] Case(string name, Func<MockRequest, HttpResponseMessage> responder) => new object[] { name, new Responder(responder) };
    }

    /// <summary>Wraps a delegate so xUnit can display theory cases by name.</summary>
    public sealed class Responder
    {
        internal Responder(Func<MockRequest, HttpResponseMessage> respond) => Respond = respond;

        internal Func<MockRequest, HttpResponseMessage> Respond { get; }

        public override string ToString() => "responder";
    }

    [Theory]
    [MemberData(nameof(HostileResponses))]
    public async Task Hostile_or_broken_responses_are_invalid_and_never_ok(string name, Responder responder)
    {
        var server = new MockServer();
        server.Respond(responder.Respond);
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok, name);
        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.False(result.Verified);
        Assert.Null(result.License);
        Assert.False(result.HasFeature("pro"));
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
        Assert.Single(server.Requests);
    }

    // ---- Clock skew ---------------------------------------------------------------------------------

    [Fact]
    public async Task Clock_skew_learns_offset_and_retries_once_with_a_fresh_nonce()
    {
        const long serverNow = Payloads.ServerTime + 3600; // local clock is an hour behind
        var server = new MockServer();
        server.Respond(r =>
        {
            if (Math.Abs(r.Timestamp - serverNow) > 300)
            {
                return Responses.Signed(Payloads.Base(r, false, "clock_skew", "Request timestamp is outside the allowed window.", serverNow));
            }
            return Responses.Signed(Payloads.ValidateOk(r, serverTime: serverNow));
        });
        using var client = TestClients.Create(server, clock: new FakeClock(Payloads.ServerTime));

        var result = await client.ValidateAsync(Key);

        Assert.True(result.Ok);
        Assert.Equal(3600, client.ClockOffsetSeconds);
        var requests = server.Requests;
        Assert.Equal(2, requests.Count);
        Assert.Equal(Payloads.ServerTime, requests[0].Timestamp);
        Assert.Equal(serverNow, requests[1].Timestamp);
        Assert.NotEqual(requests[0].Nonce, requests[1].Nonce);

        // The learned offset is kept: the next call needs a single request.
        Assert.True((await client.ValidateAsync(Key)).Ok);
        Assert.Equal(3, server.Requests.Count);
        Assert.Equal(serverNow, server.Requests[2].Timestamp);
    }

    [Fact]
    public async Task Clock_skew_is_retried_only_once()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, "clock_skew", "Skewed.", Payloads.ServerTime + 5000)));
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.ClockSkew, result.Code);
        Assert.True(result.Verified);
        Assert.Equal(2, server.Requests.Count);
    }

    [Fact]
    public async Task Unsigned_clock_skew_is_not_trusted()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Json(200, Payloads.Base(r, false, "clock_skew", "Skewed.", Payloads.ServerTime + 99999).ToJsonString()));
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Equal(0, client.ClockOffsetSeconds);
        Assert.Single(server.Requests);
    }

    // ---- Unsigned HTTP errors -----------------------------------------------------------------------

    [Theory]
    [InlineData(400, "validation_error", "validation_error")]
    [InlineData(403, "ip_blocked", "ip_blocked")]
    [InlineData(404, "unknown_product", "unknown_product")]
    [InlineData(413, "payload_too_large", "payload_too_large")]
    [InlineData(415, "unsupported_media_type", "unsupported_media_type")]
    [InlineData(429, "rate_limited", "rate_limited")]
    [InlineData(500, "internal_error", "internal_error")]
    [InlineData(503, "internal_error", "internal_error")]
    public async Task Unsigned_errors_map_to_their_code_and_are_never_ok(int status, string serverCode, string expected)
    {
        var server = new MockServer();
        server.Respond(_ => Responses.Error(status, serverCode, headers: new[] { ("Retry-After", "30") }));
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(expected, result.Code);
        Assert.False(result.Verified);
        Assert.Equal(status, result.HttpStatus);
        Assert.Equal("11111111-2222-4333-8444-555555555555", result.RequestId);
        Assert.DoesNotContain("Server says", result.Message, StringComparison.Ordinal);
        Assert.Equal(status == 429 ? TimeSpan.FromSeconds(30) : (TimeSpan?)null, result.RetryAfter);
    }

    [Theory]
    [InlineData(502, "{\"message\":\"Bad Gateway\"}", "network_error")]   // a proxy's own JSON page is not a Velsigil body
    [InlineData(503, "{\"error\":{\"code\":\"something_new\"}}", "internal_error")]
    [InlineData(504, "{\"error\":{\"code\":\"internal_error\"}}", "internal_error")]
    [InlineData(400, "{\"error\":{\"code\":\"ok\"}}", "validation_error")]  // unknown codes are ignored; status decides
    public async Task Gateway_and_unknown_codes_follow_the_cross_sdk_mapping(int status, string json, string expected)
    {
        var server = new MockServer();
        server.Respond(_ => Responses.Json(status, json));
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(expected, result.Code);
    }

    [Theory]
    [InlineData(500, "internal_error")]
    [InlineData(429, "rate_limited")]
    [InlineData(502, "network_error")]
    [InlineData(503, "network_error")]
    [InlineData(504, "network_error")]
    [InlineData(400, "validation_error")]
    [InlineData(413, "payload_too_large")]
    [InlineData(415, "unsupported_media_type")]
    [InlineData(401, "invalid_response")]
    [InlineData(404, "invalid_response")]
    public async Task Errors_without_a_Velsigil_body_map_by_status(int status, string expected)
    {
        var server = new MockServer();
        server.Respond(_ => Responses.Text(status, "<html>Bad Gateway</html>"));
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(expected, result.Code);
    }

    // ---- Transport failures -------------------------------------------------------------------------

    [Fact]
    public async Task Timeout_is_a_network_error()
    {
        var server = new MockServer
        {
            Handler = async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            },
        };
        using var client = TestClients.Create(server, timeout: TimeSpan.FromSeconds(1));

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.NetworkError, result.Code);
        Assert.Contains("in time", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Handler_exception_is_a_network_error()
    {
        var server = new MockServer { Handler = (_, _) => throw new HttpRequestException("No such host is known.") };
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.Equal(ResultCodes.NetworkError, result.Code);
        Assert.False(result.Ok);
    }

    [Fact]
    public async Task Connection_refused_is_a_network_error()
    {
        var port = LocalHttpServer.GetClosedPort();
        using var client = new VelsigilClient("http://127.0.0.1:" + port, Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid, Timeout = TimeSpan.FromSeconds(5) });

        var result = await client.ValidateAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.NetworkError, result.Code);
    }

    [Fact]
    public async Task Caller_cancellation_throws_OperationCanceledException()
    {
        var server = new MockServer
        {
            Handler = async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            },
        };
        using var client = TestClients.Create(server);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ValidateAsync(Key, cancellationToken: cts.Token));
    }

    // ---- Real sockets ---------------------------------------------------------------------------------

    [Fact]
    public async Task Works_against_a_local_http_server_with_the_default_http_client()
    {
        var calls = 0;
        using var http = new LocalHttpServer(r =>
            Interlocked.Increment(ref calls) == 1
                ? Responses.Signed(Payloads.ValidateOk(r))
                : Responses.Error(429, "rate_limited", headers: new[] { ("Retry-After", "12") }));
        var store = new MemoryStore();
        using var client = new VelsigilClient(http.BaseUrl, Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { Store = store, HardwareId = Vectors.TestHwid, Clock = new FakeClock(Payloads.ServerTime).GetNow });

        var ok = await client.ValidateAsync(Key);
        var limited = await client.ValidateAsync(Key);

        Assert.True(ok.Ok);
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(ResultCodes.RateLimited, limited.Code);
        Assert.Equal(TimeSpan.FromSeconds(12), limited.RetryAfter);
        Assert.Equal(Payloads.DeviceSecret, http.Requests[1].Field("deviceSecret"));
        Assert.Equal("/api/client/v1/validate", http.Requests[0].Path);
        Assert.Equal("application/json", http.Requests[0].Headers["Content-Type"]);
    }

    [Theory]
    [InlineData(307)]
    [InlineData(308)]
    public async Task Redirect_followed_by_an_injected_http_client_is_an_invalid_response(int redirectStatus)
    {
        // SDK-2: an injected HttpClient keeps .NET's default AllowAutoRedirect = true, and a 307/308
        // re-sends the POST to the Location host. Its signed answer must still be rejected: the protocol
        // never follows redirects.
        using var target = new LocalHttpServer(r => Responses.Signed(Payloads.ValidateOk(r)));
        using var origin = new LocalHttpServer(r =>
        {
            var response = new HttpResponseMessage((System.Net.HttpStatusCode)redirectStatus);
            response.Headers.Location = new Uri(target.BaseUrl + r.Path);
            return response;
        });
        using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, UseCookies = false });
        var options = new VelsigilClientOptions { HttpClient = http, HardwareId = Vectors.TestHwid, Clock = new FakeClock(Payloads.ServerTime).GetNow };

        // Control: the same injected client works when nothing redirects.
        options.Store = new MemoryStore();
        using (var direct = new VelsigilClient(target.BaseUrl, Vectors.ProductId, Vectors.PublicKey, options))
        {
            Assert.True((await direct.ValidateAsync(Key)).Ok);
        }

        var store = new MemoryStore();
        options.Store = store;
        using var client = new VelsigilClient(origin.BaseUrl, Vectors.ProductId, Vectors.PublicKey, options);

        var result = await client.ValidateAsync(Key);

        Assert.Equal(2, target.Requests.Count); // the handler did follow the redirect (body re-sent)...
        Assert.Equal(Key, target.Requests[1].Field("licenseKey"));
        Assert.False(result.Ok); // ...but the genuinely signed answer is not accepted
        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Contains("redirected", result.Message, StringComparison.Ordinal);
        Assert.False(result.Verified);
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
    }

    // ---- Local validation & configuration ----------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task Missing_license_key_fails_locally(string? key)
    {
        var server = new MockServer();
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(key!);

        Assert.Equal(ResultCodes.ValidationError, result.Code);
        Assert.False(result.Ok);
        Assert.Empty(server.Requests);
    }

    [Fact]
    public async Task Oversized_optional_fields_fail_locally()
    {
        var server = new MockServer();
        using var client = TestClients.Create(server);

        Assert.Equal(ResultCodes.ValidationError, (await client.ValidateAsync(Key, new ValidateOptions { Version = new string('1', 33) })).Code);
        Assert.Equal(ResultCodes.ValidationError, (await client.ValidateAsync(Key, new ValidateOptions { DeviceName = new string('n', 256) })).Code);
        Assert.Equal(ResultCodes.ValidationError, (await client.CheckUpdateAsync(new string('1', 33))).Code);
        Assert.Equal(ResultCodes.ValidationError, (await client.ValidateAsync(new string('K', 300))).Code);
        Assert.Equal(ResultCodes.ValidationError, (await client.ValidateAsync(new string('K', 65))).Code); // server limit is 64
        Assert.Empty(server.Requests);
    }

    [Theory]
    [InlineData("http://licenses.example.com")]
    [InlineData("http://10.0.0.5:3000")]
    [InlineData("http://[::ffff:127.0.0.1]:3000")] // plain http: exactly localhost, 127.0.0.1 and ::1
    [InlineData("http://localhost.:3000")]
    [InlineData("ftp://licenses.example.com")]
    [InlineData("licenses.example.com")]
    [InlineData("https://user:pass@licenses.example.com")]
    [InlineData("https://licenses.example.com/?x=1")]
    [InlineData("")]
    public void Insecure_or_invalid_api_urls_are_rejected(string url)
    {
        // A freshly generated key: the published test-vector keys are refused for non-loopback hosts anyway.
        Assert.Throws<ArgumentException>(() => new VelsigilClient(url, Vectors.ProductId, TestSigner.Random().PublicKeyBase64,
            new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid }));
    }

    [Theory]
    [InlineData("http://localhost:3000", "http://localhost:3000/api/client/v1/")]
    [InlineData("http://127.0.0.1:3000/", "http://127.0.0.1:3000/api/client/v1/")]
    [InlineData("http://[::1]:3000", "http://[::1]:3000/api/client/v1/")]
    [InlineData("https://licenses.example.com", "https://licenses.example.com/api/client/v1/")]
    [InlineData("https://licenses.example.com/api/client/v1", "https://licenses.example.com/api/client/v1/")]
    [InlineData("https://example.com/licensing/", "https://example.com/licensing/api/client/v1/")]
    public void Accepted_api_urls_resolve_to_the_client_api(string url, string expected)
    {
        using var client = new VelsigilClient(url, Vectors.ProductId, TestSigner.Random().PublicKeyBase64,
            new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid });
        Assert.Equal(expected, client.ApiBaseUrl.ToString());
    }

    [Fact]
    public void Plain_http_to_a_remote_host_requires_explicit_opt_in()
    {
        using var client = new VelsigilClient("http://licenses.example.com", Vectors.ProductId, TestSigner.Random().PublicKeyBase64,
            new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid, AllowInsecureHttp = true });
        Assert.Equal("http://licenses.example.com/api/client/v1/", client.ApiBaseUrl.ToString());
    }

    [Fact]
    public void Constructor_validates_arguments()
    {
        VelsigilClient Create(string productId, string key, VelsigilClientOptions options) =>
            new VelsigilClient(TestClients.ApiUrl, productId, key, options);
        var good = new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid };

        Assert.Throws<ArgumentException>(() => Create("not-a-uuid", Vectors.PublicKey, good));
        Assert.Throws<ArgumentException>(() => Create(Vectors.ProductId, "AAAA", good));
        Assert.Throws<ArgumentException>(() => Create(Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = "short" }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Create(Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { Store = new MemoryStore(), HardwareId = Vectors.TestHwid, Timeout = TimeSpan.Zero }));

        using var upper = Create(Vectors.ProductId.ToUpperInvariant(), Vectors.PublicKey, good);
        Assert.Equal(Vectors.ProductId, upper.ProductId);
        Assert.Equal(Vectors.TestHwid, upper.HardwareId);
    }

    [Fact]
    public async Task Disposed_client_throws_ObjectDisposedException()
    {
        var client = TestClients.Create(new MockServer());
        client.Dispose();
        client.Dispose(); // idempotent

        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ValidateAsync(Key));
        Assert.Throws<ObjectDisposedException>(() => client.ValidateOffline());
    }

    [Fact]
    public async Task Store_failures_never_fail_validation()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.ValidateOk(r)));
        var errors = new List<Exception>();
        using var client = TestClients.Create(server, new ThrowingStore(), storeErrorHandler: errors.Add);

        var result = await client.ValidateAsync(Key);

        Assert.True(result.Ok);
        Assert.NotEmpty(errors);
        Assert.All(errors, e => Assert.IsType<InvalidOperationException>(e));
    }

    // ---- Update check -------------------------------------------------------------------------------

    [Fact]
    public async Task Check_update_sends_no_license_data_and_returns_update_info()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "Update available.");
            payload["update"] = Payloads.Update(mandatory: true);
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server);

        var result = await client.CheckUpdateAsync("1.0.0");

        Assert.True(result.Ok);
        Assert.True(result.Update!.UpdateAvailable);
        Assert.True(result.Update.Mandatory);
        Assert.Equal("1.0.0", result.Update.MinVersion);
        var request = server.Requests.Single();
        Assert.Equal("/api/client/v1/update-check", request.Path);
        Assert.Equal(
            new[] { "nonce", "productId", "timestamp", "version" },
            request.Json!.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public async Task Check_update_with_no_release()
    {
        var server = new MockServer();
        // Exactly what the server sends (SPEC 10.2): ok = true, code no_release, update = null.
        server.Respond(r => Responses.Signed(Payloads.Base(r, true, "no_release", "No release has been published yet.")));
        using var client = TestClients.Create(server);

        var result = await client.CheckUpdateAsync();

        Assert.True(result.Ok);
        Assert.Equal(ResultCodes.NoRelease, result.Code);
        Assert.Null(result.Update);
        Assert.False(server.Requests.Single().Has("version"));
    }

    private sealed class ThrowingStore : IVelsigilStore
    {
        public string? GetDeviceSecret(string productId) => throw new InvalidOperationException("disk unavailable");

        public void SetDeviceSecret(string productId, string? deviceSecret) => throw new InvalidOperationException("disk unavailable");

        public string? GetLeaseToken(string productId) => throw new InvalidOperationException("disk unavailable");

        public void SetLeaseToken(string productId, string? leaseToken) => throw new InvalidOperationException("disk unavailable");
    }
}
