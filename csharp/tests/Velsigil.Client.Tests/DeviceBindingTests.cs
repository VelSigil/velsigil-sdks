using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

/// <summary>Answers to device-bound requests must describe this device, or nothing from them is used.</summary>
public class DeviceBindingTests
{
    private const string Key = TestClients.LicenseKey;
    private const string OtherSecret = "dsk_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";

    private static JsonObject ActivationOf(string hwid, string? deviceSecret = null)
    {
        var activation = Payloads.Activation(deviceSecret);
        activation["hwidHash"] = HardwareId.HashHwid(hwid);
        return activation;
    }

    [Fact]
    public async Task An_activation_of_this_device_is_accepted()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.ValidateOk(r);
            var activation = ActivationOf(Vectors.TestHwid, Payloads.DeviceSecret);
            activation["hwidHash"] = HardwareId.HashHwid(Vectors.TestHwid).ToUpperInvariant();
            payload["activation"] = activation;
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        using var client = TestClients.Create(server, store);

        var result = await client.ValidateAsync(Key);

        Assert.True(result.Ok, result.Message);
        Assert.True(result.Activation!.DeviceSecretIssued);
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
    }

    [Theory]
    [InlineData("validate")]
    [InlineData("download")]
    [InlineData("deactivate")]
    public async Task An_answer_for_another_device_is_rejected_and_leaves_local_state_untouched(string operation)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "Done.");
            payload["license"] = Payloads.License();
            payload["activation"] = ActivationOf("another-device-hwid", OtherSecret);
            if (operation == "download")
            {
                payload["download"] = new JsonObject
                {
                    ["url"] = "/api/download/abc",
                    ["expiresAt"] = Payloads.ServerTime + 600,
                    ["fileName"] = "app.zip",
                    ["size"] = 1,
                    ["sha256"] = new string('a', 64),
                    ["version"] = "1.4.0",
                };
            }
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        store.SetDeviceSecret(Vectors.ProductId, Payloads.DeviceSecret);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = operation switch
        {
            "validate" => await client.ValidateAsync(Key),
            "download" => await client.GetDownloadAsync(Key),
            _ => await client.DeactivateAsync(Key),
        };

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Null(result.Activation);
        Assert.Null(result.Download);
        // No foreign secret stored, the own lease kept, and a foreign "ok" deactivation clears nothing.
        Assert.Equal(Payloads.DeviceSecret, store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
        Assert.True(client.ValidateOffline().Ok);
    }

    [Fact]
    public async Task A_denial_about_another_device_does_not_revoke_the_lease()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, false, "device_revoked", "Revoked.");
            payload["activation"] = ActivationOf("another-device-hwid");
            return Responses.Signed(payload);
        });
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, Vectors.ValidLeaseToken);
        using var client = TestClients.Create(server, store, new FakeClock(Payloads.ServerTime + 60));

        var result = await client.ValidateAsync(Key);

        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Equal(Vectors.ValidLeaseToken, store.GetLeaseToken(Vectors.ProductId));
    }

    [Theory]
    [InlineData("not-a-hash")]
    [InlineData(42)]
    public async Task A_malformed_activation_hwid_hash_is_rejected(object value)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.ValidateOk(r);
            var activation = Payloads.Activation(null);
            activation["hwidHash"] = value is int number ? JsonValue.Create(number) : JsonValue.Create((string)value);
            payload["activation"] = activation;
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server);

        var result = await client.ValidateAsync(Key);

        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
    }

    [Fact]
    public async Task Update_checks_are_not_device_bound()
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            var payload = Payloads.Base(r, true, "ok", "Update available.");
            payload["update"] = Payloads.Update();
            return Responses.Signed(payload);
        });
        using var client = TestClients.Create(server);

        var result = await client.CheckUpdateAsync("1.0.0");

        Assert.True(result.Ok, result.Message);
        Assert.False(server.Requests[0].Has("hwid"));
    }
}
