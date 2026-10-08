using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

/// <summary>In-app free trials: <see cref="VelsigilClient.StartTrialAsync"/> (SPEC 9.7 "In-app trials").</summary>
public class TrialTests
{
    private const string TrialKey = "DEMO-7K3QM-P9XWD-R4TNB-H2CFY-M8LJV";

    private static string TrialLeaseToken => Vectors.Lease("lease_trial").GetProperty("token").GetString()!;

    private static JsonObject Started(MockRequest request)
    {
        var payload = Payloads.Base(request, true, "ok", "Your free trial has started.");
        var license = Payloads.License();
        license["plan"] = "Trial";
        license["trial"] = true;
        payload["license"] = license;
        var activation = Payloads.Activation(Payloads.DeviceSecret);
        activation["hwidHash"] = HardwareId.HashHwid(Vectors.TestHwid);
        payload["activation"] = activation;
        payload["lease"] = Payloads.Lease(TrialLeaseToken, Vectors.LeaseExpiresAt);
        payload["trial"] = new JsonObject { ["key"] = TrialKey };
        return payload;
    }

    [Fact]
    public async Task StartTrial_returns_the_key_and_persists_the_device_secret_and_lease()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Started(r)));
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.StartTrialAsync(new StartTrialOptions { Version = "1.2.0", DeviceName = "Laptop" });

        Assert.True(result.Ok);
        Assert.Equal(TrialKey, result.TrialKey);
        Assert.True(result.IsTrial);
        Assert.True(result.Activation!.DeviceSecretIssued);
        Assert.DoesNotContain(TrialKey, result.ToString(), StringComparison.Ordinal);
        var request = server.Requests.Single();
        Assert.Equal("/api/client/v1/trial", request.Path);
        Assert.Equal(
            new[] { "deviceName", "hwid", "nonce", "productId", "timestamp", "version" },
            request.Json!.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(TrialLeaseToken, store.GetLeaseToken(Vectors.ProductId));

        // The SDK never stores the key; offline the lease says "trial".
        var offline = client.ValidateOffline();
        Assert.True(offline.Ok);
        Assert.True(offline.IsTrial);
        Assert.Null(offline.TrialKey);
    }

    [Theory]
    [InlineData(ResultCodes.TrialAlreadyUsed)]
    [InlineData(ResultCodes.TrialUnavailable)]
    [InlineData(ResultCodes.TrialEmailRequired)]
    [InlineData(ResultCodes.TrialEmailInvalid)]
    [InlineData(ResultCodes.TrialEmailNotAccepted)]
    [InlineData(ResultCodes.TrialConfirmationSent)]
    public async Task StartTrial_signed_failures_are_results_and_store_nothing(string code)
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, code, "Server text.")));
        // A trial is only ever sent with nothing stored (a stored secret or lease answers already_licensed locally).
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.StartTrialAsync(new StartTrialOptions { Email = " jane@example.com " });

        Assert.False(result.Ok);
        Assert.Equal(code, result.Code);
        Assert.Equal("Server text.", result.Message);
        Assert.Null(result.TrialKey);
        Assert.DoesNotContain(code, VelsigilClient.LeaseRevokingCodes);
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
        Assert.Equal("jane@example.com", server.Requests.Single().Field("email"));
    }

    // Review finding 7: a trial answer would overwrite the device secret and lease of the license this device holds.
    private const string PaidSecret = "dsk_P4idL1c3P4idL1c3P4idL1c3P4idL1c3P4idL1c3abc";

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task StartTrial_refuses_locally_when_a_device_secret_or_lease_is_stored(bool secretStored, bool leaseStored)
    {
        var server = new MockServer();
        // If anything were sent, the server would start a trial whose secret and lease replace the stored ones.
        server.Respond(r => Responses.Signed(Started(r)));
        var store = new MemoryStore();
        if (secretStored) store.SetDeviceSecret(Vectors.ProductId, PaidSecret);
        if (leaseStored) store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store);

        var result = await client.StartTrialAsync(new StartTrialOptions { Version = "1.2.0" });

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.AlreadyLicensed, result.Code);
        Assert.Equal("already_licensed", ResultCodes.AlreadyLicensed);
        Assert.Contains("already holds a license for this product", result.Message, StringComparison.Ordinal);
        Assert.Contains("trial cannot replace it", result.Message, StringComparison.Ordinal);
        Assert.Contains("ClearStoredState()", result.Message, StringComparison.Ordinal);
        Assert.Null(result.TrialKey);
        Assert.Empty(server.Requests);
        Assert.Equal(secretStored ? PaidSecret : null, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(leaseStored ? Vectors.ValidLeaseToken : null, store.GetLeaseToken(Vectors.ProductId));
    }

    // Final sweep F-SDK-1: a failed store read is not "nothing stored"; the guard fails closed.
    private sealed class FlakyStore : IVelsigilStore
    {
        private readonly MemoryStore _inner = new MemoryStore();

        public int FailingReads { get; set; }

        public string? GetDeviceSecret(string productId)
        {
            FailIfAsked();
            return _inner.GetDeviceSecret(productId);
        }

        public void SetDeviceSecret(string productId, string? deviceSecret) => _inner.SetDeviceSecret(productId, deviceSecret);

        public string? GetLeaseToken(string productId)
        {
            FailIfAsked();
            return _inner.GetLeaseToken(productId);
        }

        public void SetLeaseToken(string productId, string? leaseToken) => _inner.SetLeaseToken(productId, leaseToken);

        private void FailIfAsked()
        {
            if (FailingReads <= 0) return;
            FailingReads--;
            throw new System.IO.IOException("The process cannot access the file because it is being used by another process.");
        }
    }

    [Fact]
    public async Task StartTrial_refuses_with_store_unavailable_when_the_store_cannot_be_read()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Started(r)));
        var store = new FlakyStore();
        store.SetDeviceSecret(Vectors.ProductId, PaidSecret);
        store.FailingReads = 1;
        var errors = 0;
        using var client = TestClients.Create(server, store, storeErrorHandler: _ => errors++);

        var result = await client.StartTrialAsync();

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.StoreUnavailable, result.Code);
        Assert.Equal("store_unavailable", ResultCodes.StoreUnavailable);
        Assert.Contains("could not be read", result.Message, StringComparison.Ordinal);
        Assert.Null(result.TrialKey);
        Assert.Empty(server.Requests);
        Assert.Equal(1, errors);

        // Readable again: the guard sees the paid license.
        Assert.Equal(ResultCodes.AlreadyLicensed, (await client.StartTrialAsync()).Code);
        Assert.Empty(server.Requests);
        Assert.Equal(PaidSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    // Final sweep F-CLIENT-4: the already_licensed check and the trial request form one step under the device lock, so
    // a validation in progress cannot store a license between them (the trial answer would then replace it).
    [Fact]
    public async Task StartTrial_waits_for_a_validation_in_progress_and_then_refuses()
    {
        var server = new MockServer();
        var validationEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseValidation = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        server.Handler = async (request, _) =>
        {
            if (request.Path.EndsWith("/trial", StringComparison.Ordinal)) return Responses.Signed(Started(request));
            validationEntered.TrySetResult(true);
            await releaseValidation.Task;
            return Responses.Signed(Payloads.ValidateOk(request));
        };
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var validation = client.ValidateAsync(TestClients.LicenseKey);
        await validationEntered.Task;
        var trial = client.StartTrialAsync();
        releaseValidation.SetResult(true);

        Assert.True((await validation).Ok);
        var refused = await trial;
        Assert.Equal(ResultCodes.AlreadyLicensed, refused.Code);
        Assert.DoesNotContain(server.Requests, r => r.Path.EndsWith("/trial", StringComparison.Ordinal));
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
    }

    // Final sweep F-SDK-4: days left are rounded up (CLIENT_PROTOCOL 5.2): N right after an N-day trial starts, 1 on
    // its last day, 0 once expired.
    [Theory]
    [InlineData(14 * 86400L, 14)]
    [InlineData(14 * 86400L - 1, 14)]
    [InlineData(86400L - 60, 1)]
    [InlineData(1L, 1)]
    [InlineData(0L, 0)]
    public async Task Days_left_are_rounded_up_at_the_signed_server_time(long secondsLeft, int expectedDays)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Started(r);
            payload["license"]!["expiresAt"] = Payloads.ServerTime + secondsLeft;
            return Responses.Signed(payload);
        });
        // The local clock is a second past the signed server time; the helper measures at the server time.
        using var client = TestClients.Create(server, clock: new FakeClock(Payloads.ServerTime + 1));

        var result = await client.StartTrialAsync();

        Assert.True(result.Ok);
        Assert.Equal(expectedDays, result.DaysRemaining);
    }

    [Fact]
    public async Task StartTrial_starts_once_the_stored_state_is_cleared()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Started(r)));
        var store = new MemoryStore();
        store.SetDeviceSecret(Vectors.ProductId, PaidSecret);
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store);

        Assert.Equal(ResultCodes.AlreadyLicensed, (await client.StartTrialAsync()).Code);
        client.ClearStoredState(); // the documented way out
        var result = await client.StartTrialAsync();

        Assert.True(result.Ok);
        Assert.Single(server.Requests);
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
    }

    [Fact]
    public async Task StartTrial_sends_no_email_unless_given_and_checks_lengths_locally()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, ResultCodes.TrialUnavailable)));
        using var client = TestClients.Create(server);

        await client.StartTrialAsync();
        Assert.False(server.Requests.Single().Has("email"));
        var tooLong = await client.StartTrialAsync(new StartTrialOptions { Email = new string('a', 250) + "@x.io" });
        Assert.Equal(ResultCodes.ValidationError, tooLong.Code);
        Assert.Single(server.Requests);
    }

    [Fact]
    public async Task StartTrial_against_a_panel_without_the_endpoint_is_panel_too_old()
    {
        var server = new MockServer();
        server.Respond(_ => Responses.Error(404, "not_found", "rid-old"));
        using var client = TestClients.Create(server);

        var result = await client.StartTrialAsync();
        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.PanelTooOld, result.Code);
        Assert.Contains("update the Velsigil panel", result.Message, StringComparison.Ordinal);
        Assert.Equal("rid-old", result.RequestId);

        // Only the trial endpoint maps a 404 like this; unknown_product keeps its code.
        Assert.Equal(ResultCodes.InvalidResponse, (await client.ValidateAsync(TestClients.LicenseKey)).Code);
        server.Respond(_ => Responses.Error(404, "unknown_product"));
        Assert.Equal(ResultCodes.UnknownProduct, (await client.StartTrialAsync()).Code);
    }

    [Fact]
    public async Task StartTrial_rejects_a_missing_or_malformed_key_another_type_and_another_device()
    {
        var server = new MockServer();
        using var client = TestClients.Create(server);
        var mutations = new Action<JsonObject>[]
        {
            p => p.Remove("trial"),
            p => p["trial"] = new JsonObject { ["key"] = "bad key\n" },
            p => p["type"] = "validate",
            p => ((JsonObject)p["activation"]!)["hwidHash"] = new string('f', 64),
        };
        foreach (var mutate in mutations)
        {
            server.Respond(r =>
            {
                var payload = Started(r);
                mutate(payload);
                return Responses.Signed(payload);
            });
            var result = await client.StartTrialAsync();
            Assert.False(result.Ok);
            Assert.Equal(ResultCodes.InvalidResponse, result.Code);
            Assert.Null(result.TrialKey);
        }
    }

    [Fact]
    public async Task A_key_in_another_answer_is_never_exposed()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.ValidateOk(r);
            payload["trial"] = new JsonObject { ["key"] = TrialKey };
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(TestClients.LicenseKey);
        Assert.True(result.Ok);
        Assert.Null(result.TrialKey);
    }
}
