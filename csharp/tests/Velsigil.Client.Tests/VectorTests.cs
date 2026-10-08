using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Velsigil.Client.Internal;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

/// <summary>Every vector in sdks/test-vectors.json must be classified exactly as its "expect" field says.</summary>
public class VectorTests
{
    private static readonly Ed25519Verifier PinnedKey = Ed25519Verifier.FromBase64(Vectors.PublicKey);

    public static IEnumerable<object[]> EnvelopeNames() => Vectors.EnvelopeNames();

    public static IEnumerable<object[]> LeaseNames() => Vectors.LeaseNames();

    public static IEnumerable<object[]> HwidExamples() => Vectors.HwidExampleIndexes();

    [Fact]
    public void Vector_file_contains_every_documented_case()
    {
        // 17 until 2026-10-06, then 5 appended for in-app trials and 2 for the trial conversion reference (SPEC 9.7);
        // older vectors keep their positions.
        Assert.Equal(24, Vectors.EnvelopeNames().Count());
        Assert.Contains("type_mismatch", Vectors.EnvelopeNames().Select(n => (string)n[0]));
        foreach (var name in new[]
        {
            "validate_ok_trial", "trial_already_used", "unknown_fields",
            "trial_started", "trial_start_already_used", "trial_unavailable", "trial_confirmation_sent", "trial_answer_as_validate",
            "validate_ok_trial_ref", "license_expired_trial_ref",
        })
        {
            Assert.Contains(name, Vectors.EnvelopeNames().Select(n => (string)n[0]));
        }
        Assert.Equal(10, Vectors.LeaseNames().Count());
        Assert.Contains("lease_trial", Vectors.LeaseNames().Select(n => (string)n[0]));
        Assert.Equal(3, Vectors.HwidExampleIndexes().Count());
    }

    [Fact]
    public void Keys_are_consistent()
    {
        Assert.Equal(Vectors.PublicKey, TestSigner.Primary.PublicKeyBase64);
        Assert.Equal(Vectors.WrongPublicKey, TestSigner.Wrong.PublicKeyBase64);
        Assert.Equal(Vectors.KeyId, PinnedKey.KeyId);

        using var client = new VelsigilClient("https://licenses.example.test", Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { HardwareId = Vectors.TestHwid, Store = new MemoryStore() });
        Assert.Equal(Vectors.KeyId, client.KeyId);
    }

    [Theory]
    [MemberData(nameof(EnvelopeNames))]
    public void Envelope_vector_is_classified_as_expected(string name)
    {
        var vector = Vectors.Envelope(name);
        var body = Encoding.UTF8.GetBytes(vector.GetProperty("envelope").GetRawText());
        var nonce = vector.GetProperty("requestNonce").GetString()!;
        var productId = vector.GetProperty("productId").GetString()!;

        var status = EnvelopeVerifier.Verify(PinnedKey, body, nonce, productId, Vectors.RequestType(vector), Vectors.RequestHwid(vector), out var payload);

        Assert.Equal(vector.GetProperty("expect").GetString(), Describe(status));
        if (status == EnvelopeStatus.Valid)
        {
            Assert.NotNull(payload);
            AssertPayloadMatches(vector.GetProperty("payload"), payload!);
        }
        else
        {
            Assert.Null(payload);
        }
    }

    [Theory]
    [MemberData(nameof(EnvelopeNames))]
    public void Envelope_vector_kid_is_never_used_for_key_selection(string name)
    {
        var vector = Vectors.Envelope(name);
        var envelope = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(vector.GetProperty("envelope").GetRawText())!;
        // Swap in the "wrong" key id: the classification must not change.
        var rewritten = new Dictionary<string, object?>
        {
            ["data"] = envelope["data"].GetString(),
            ["sig"] = envelope.TryGetValue("sig", out var sig) ? sig.GetString() : null,
            ["kid"] = "d3a631fb9ac9df48",
        };
        var body = JsonSerializer.SerializeToUtf8Bytes(rewritten);

        var status = EnvelopeVerifier.Verify(PinnedKey, body, vector.GetProperty("requestNonce").GetString()!,
            vector.GetProperty("productId").GetString()!, Vectors.RequestType(vector), Vectors.RequestHwid(vector), out _);

        Assert.Equal(vector.GetProperty("expect").GetString(), Describe(status));
    }

    [Theory]
    [InlineData("validate_lease_other_device", "test-hwid-0001-abcdef")]
    [InlineData("validate_activation_other_device", "test-hwid-9999-zzzzzz")]
    public void Device_binding_vectors_are_authentic_and_bound_to_their_own_device(string name, string ownerHwid)
    {
        // LIC-4: the signature, nonce and product of these envelopes are fine; only the binding of the
        // signed lease / activation.hwidHash to the requesting hwid rejects them.
        var vector = Vectors.Envelope(name);
        Assert.Equal("hwid_mismatch", vector.GetProperty("expect").GetString());
        var body = Encoding.UTF8.GetBytes(vector.GetProperty("envelope").GetRawText());
        var nonce = vector.GetProperty("requestNonce").GetString()!;

        Assert.Equal(EnvelopeStatus.HwidMismatch, EnvelopeVerifier.Verify(PinnedKey, body, nonce, Vectors.ProductId, "validate", Vectors.RequestHwid(vector), out var rejected));
        Assert.Null(rejected);
        Assert.Equal(EnvelopeStatus.Valid, EnvelopeVerifier.Verify(PinnedKey, body, nonce, Vectors.ProductId, "validate", null, out var unbound));
        Assert.True(unbound!.Ok);
        Assert.Equal(EnvelopeStatus.Valid, EnvelopeVerifier.Verify(PinnedKey, body, nonce, Vectors.ProductId, "validate", ownerHwid, out _));
        Assert.Equal(vector.GetProperty("envelope").GetProperty("sig").GetString(), TestSigner.Primary.SignAscii(vector.GetProperty("envelope").GetProperty("data").GetString()!));
    }

    [Fact]
    public void Type_mismatch_vector_is_authentic_and_rejected_only_by_the_type_check()
    {
        // SDK-1: a signed update-check answer (ok, no license involved) for this request's nonce and
        // product must not pass as the answer to a device-bound validate request.
        var vector = Vectors.Envelope("type_mismatch");
        Assert.Equal("validate", Vectors.RequestType(vector));
        var body = Encoding.UTF8.GetBytes(vector.GetProperty("envelope").GetRawText());
        var nonce = vector.GetProperty("requestNonce").GetString()!;
        var hwid = Vectors.RequestHwid(vector);

        Assert.Equal(EnvelopeStatus.TypeMismatch, EnvelopeVerifier.Verify(PinnedKey, body, nonce, Vectors.ProductId, "validate", hwid, out var rejected));
        Assert.Null(rejected);
        Assert.Equal(EnvelopeStatus.TypeMismatch, EnvelopeVerifier.Verify(PinnedKey, body, nonce, Vectors.ProductId, string.Empty, hwid, out _));
        Assert.Equal(EnvelopeStatus.Valid, EnvelopeVerifier.Verify(PinnedKey, body, nonce, Vectors.ProductId, "update_check", hwid, out var asUpdateCheck));
        AssertPayloadMatches(vector.GetProperty("payload"), asUpdateCheck!);
        Assert.True(asUpdateCheck!.Ok);
    }

    [Theory]
    [MemberData(nameof(EnvelopeNames))]
    public void Envelope_vector_verifies_only_under_its_signing_key(string name)
    {
        var vector = Vectors.Envelope(name);
        var body = Encoding.UTF8.GetBytes(vector.GetProperty("envelope").GetRawText());
        var wrongKey = Ed25519Verifier.FromBase64(Vectors.WrongPublicKey);
        var expectedValidUnderWrongKey = name == "wrong_key";

        var status = EnvelopeVerifier.Verify(wrongKey, body, vector.GetProperty("requestNonce").GetString()!,
            Vectors.ProductId, Vectors.RequestType(vector), null, out _);

        if (expectedValidUnderWrongKey)
        {
            Assert.Equal(EnvelopeStatus.Valid, status);
        }
        else
        {
            Assert.Equal(EnvelopeStatus.InvalidSignature, status);
        }
    }

    [Theory]
    [MemberData(nameof(EnvelopeNames))]
    public void Mock_signer_reproduces_vector_signatures(string name)
    {
        var vector = Vectors.Envelope(name);
        if (vector.GetProperty("expect").GetString() != "valid") return;
        var envelope = vector.GetProperty("envelope");
        Assert.Equal(envelope.GetProperty("sig").GetString(), TestSigner.Primary.SignAscii(envelope.GetProperty("data").GetString()!));
    }

    [Fact]
    public void Mock_signer_reproduces_the_vector_lease_signature()
    {
        var token = Vectors.ValidLeaseToken;
        var dot = token.IndexOf('.');
        Assert.Equal(token.Substring(dot + 1), TestSigner.Primary.SignAscii(token.Substring(0, dot)));
    }

    [Theory]
    [MemberData(nameof(LeaseNames))]
    public void Lease_vector_is_classified_as_expected(string name)
    {
        var vector = Vectors.Lease(name);
        var result = LeaseVerifier.Verify(
            vector.GetProperty("token").GetString(),
            Vectors.PublicKey,
            vector.GetProperty("productId").GetString()!,
            vector.GetProperty("hwid").GetString()!,
            DateTimeOffset.FromUnixTimeSeconds(vector.GetProperty("now").GetInt64()));

        Assert.Equal(vector.GetProperty("expect").GetString(), Describe(result.Status));
        Assert.Equal(result.Status == LeaseStatus.Valid, result.IsValid);

        if (vector.TryGetProperty("payload", out var expected))
        {
            var claims = result.Claims!;
            Assert.Equal(expected.GetProperty("productId").GetString(), claims.ProductId);
            Assert.Equal(expected.GetProperty("licenseId").GetString(), claims.LicenseId);
            Assert.Equal(expected.GetProperty("activationId").GetString(), claims.ActivationId);
            Assert.Equal(expected.GetProperty("hwidHash").GetString(), claims.HwidHash);
            Assert.Equal(expected.GetProperty("plan").GetString(), claims.Plan);
            Assert.Equal(expected.GetProperty("features").EnumerateArray().Select(f => f.GetString()), claims.Features);
            Assert.Equal(expected.GetProperty("licenseExpiresAt").GetInt64(), claims.LicenseExpiresAtUnix);
            Assert.Equal(expected.GetProperty("iat").GetInt64(), claims.IssuedAtUnix);
            Assert.Equal(expected.GetProperty("exp").GetInt64(), claims.ExpiresAtUnix);
            Assert.Equal(expected.TryGetProperty("trial", out var trial) && trial.GetBoolean(), claims.IsTrial);
            Assert.True(claims.HasFeature("pro"));
            Assert.False(claims.HasFeature("PRO"));
        }

        if (result.Status == LeaseStatus.InvalidSignature || result.Status == LeaseStatus.Malformed)
        {
            Assert.Null(result.Claims);
        }
        else
        {
            // MONEY-V1: claims of an expired or mismatched lease are diagnostics; they unlock nothing.
            Assert.NotNull(result.Claims);
            Assert.Equal(result.IsValid, result.Claims!.HasFeature("pro"));
            Assert.Contains("pro", result.Claims.Features);
        }
    }

    [Theory]
    [MemberData(nameof(LeaseNames))]
    public void Lease_vector_through_client_ValidateOffline(string name)
    {
        var vector = Vectors.Lease(name);
        var store = new MemoryStore();
        store.SetLeaseToken(Vectors.ProductId, vector.GetProperty("token").GetString());
        var clock = new FakeClock(vector.GetProperty("now").GetInt64());
        using var client = new VelsigilClient("https://licenses.example.test", vector.GetProperty("productId").GetString()!, Vectors.PublicKey,
            new VelsigilClientOptions { HardwareId = vector.GetProperty("hwid").GetString(), Store = store, Clock = clock.GetNow });

        var result = client.ValidateOffline();

        var expect = vector.GetProperty("expect").GetString();
        var expectedCode = expect switch
        {
            "valid" => ResultCodes.Ok,
            "expired" => ResultCodes.LeaseExpired,
            "invalid_signature" or "product_mismatch" or "hwid_mismatch" or "malformed" => ResultCodes.LeaseInvalid,
            var other => throw new InvalidOperationException("Unknown expectation " + other),
        };
        Assert.Equal(expectedCode, result.Code);
        Assert.Equal(expectedCode == ResultCodes.Ok, result.Ok);
        Assert.True(result.Offline);
        Assert.Equal(expect, Describe(result.LeaseStatus!.Value));
        Assert.Equal(result.Ok, result.HasFeature("pro"));
        Assert.False(result.HasFeature("missing"));
        if (result.Ok)
        {
            Assert.Equal(new[] { "pro", "export" }, result.Features);
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1769817600), result.ExpiresAt);
            Assert.False(result.IsLifetime);
            Assert.Equal(Vectors.LeaseExpiresAt, result.Lease!.ExpiresAtUnix);
            Assert.True(result.Verified);
            Assert.Equal(name == "lease_trial", result.IsTrial);
        }
    }

    [Fact]
    public void Free_trial_vectors_carry_the_optional_trial_field_and_the_new_code()
    {
        // SPEC 9.7: "trial" is an optional, last license field; paid licenses leave it out (old vectors unchanged).
        SignedPayload Open(string name)
        {
            var vector = Vectors.Envelope(name);
            var body = Encoding.UTF8.GetBytes(vector.GetProperty("envelope").GetRawText());
            var status = EnvelopeVerifier.Verify(PinnedKey, body, vector.GetProperty("requestNonce").GetString()!,
                Vectors.ProductId, Vectors.RequestType(vector), Vectors.RequestHwid(vector), out var payload);
            Assert.Equal(EnvelopeStatus.Valid, status);
            return payload!;
        }

        Assert.True(Open("validate_ok_trial").License!.IsTrial);
        Assert.False(Open("validate_ok").License!.IsTrial);
        var used = Open("trial_already_used");
        Assert.False(used.Ok);
        Assert.Equal(ResultCodes.TrialAlreadyUsed, used.Code);
        Assert.True(used.License!.IsTrial);
        // Fields this version does not know are ignored, never an error.
        var unknown = Open("unknown_fields");
        Assert.True(unknown.Ok);
        Assert.False(unknown.License!.IsTrial);

        // The trial conversion reference (SPEC 9.7): on convertible trials, also on license_expired.
        foreach (var name in new[] { "validate_ok_trial_ref", "license_expired_trial_ref" })
        {
            var withRef = Open(name);
            var expected = Vectors.Envelope(name).GetProperty("payload").GetProperty("license").GetProperty("trialRef").GetString();
            Assert.StartsWith("vtr1_", expected, StringComparison.Ordinal);
            Assert.Equal(expected, withRef.License!.TrialRef);
            var result = VelsigilResult.FromPayload(withRef);
            Assert.Equal(expected, result.TrialRef);
            Assert.Equal("https://shop.example.com/buy?velsigil_trial=" + expected, result.WithTrialRef("https://shop.example.com/buy"));
        }
        Assert.Equal(ResultCodes.LicenseExpired, Open("license_expired_trial_ref").Code);
        Assert.Null(Open("validate_ok_trial").License!.TrialRef);
        Assert.Equal("https://shop.example.com/buy", VelsigilResult.FromPayload(Open("validate_ok_trial")).WithTrialRef("https://shop.example.com/buy"));
    }

    [Fact]
    public void Trial_reference_links_and_format()
    {
        var reference = Vectors.Envelope("validate_ok_trial_ref").GetProperty("payload").GetProperty("license").GetProperty("trialRef").GetString()!;
        Assert.Equal("velsigil_trial", TrialReference.Parameter);
        Assert.Equal("https://shop.example.com/buy?plan=pro&velsigil_trial=" + reference + "#top", TrialReference.Append("https://shop.example.com/buy?plan=pro#top", reference));
        Assert.Equal("https://shop.example.com/buy?velsigil_trial=" + reference, TrialReference.Append("https://shop.example.com/buy?", reference));
        Assert.Equal("https://buy.stripe.com/test_abc?client_reference_id=" + reference, TrialReference.Append("https://buy.stripe.com/test_abc", reference));
        Assert.Equal("mailto:sales@example.com", TrialReference.Append("mailto:sales@example.com", reference));
        Assert.Equal("https://shop.example.com/buy", TrialReference.Append("https://shop.example.com/buy", "has space"));
        Assert.Equal("https://shop.example.com/buy", TrialReference.Append("https://shop.example.com/buy", null));
        Assert.True(TrialReference.IsWellFormed(reference));
        foreach (var bad in new[] { "", "has space", new string('x', 201), "ünicode" }) Assert.False(TrialReference.IsWellFormed(bad));
    }

    [Fact]
    public void In_app_trial_vectors_carry_the_key_only_on_the_started_trial()
    {
        // SPEC 9.7 "In-app trials": answers of type "trial"; an ok one carries trial.key as its last key.
        SignedPayload? Open(string name, string? requestType = null)
        {
            var vector = Vectors.Envelope(name);
            var body = Encoding.UTF8.GetBytes(vector.GetProperty("envelope").GetRawText());
            var status = EnvelopeVerifier.Verify(PinnedKey, body, vector.GetProperty("requestNonce").GetString()!,
                Vectors.ProductId, requestType ?? Vectors.RequestType(vector), Vectors.RequestHwid(vector), out var payload);
            return status == EnvelopeStatus.Valid ? payload : null;
        }

        var started = Open("trial_started")!;
        Assert.True(started.Ok);
        Assert.Equal("trial", started.Type);
        Assert.True(started.License!.IsTrial);
        Assert.Equal(Vectors.Envelope("trial_started").GetProperty("payload").GetProperty("trial").GetProperty("key").GetString(), started.TrialKey);
        var result = VelsigilResult.FromPayload(started);
        Assert.Equal(started.TrialKey, result.TrialKey);
        Assert.DoesNotContain(started.TrialKey!, result.ToString(), StringComparison.Ordinal);

        foreach (var (name, code) in new[]
        {
            ("trial_start_already_used", ResultCodes.TrialAlreadyUsed),
            ("trial_unavailable", ResultCodes.TrialUnavailable),
            ("trial_confirmation_sent", ResultCodes.TrialConfirmationSent),
        })
        {
            var failure = Open(name)!;
            Assert.False(failure.Ok);
            Assert.Equal(code, failure.Code);
            Assert.Null(failure.TrialKey);
            Assert.Null(VelsigilResult.FromPayload(failure).TrialKey);
        }

        // A trial answer is no validation and the other way round (type check alone).
        Assert.Null(Open("trial_answer_as_validate"));
        Assert.Null(Open("trial_started", "validate"));
        Assert.Null(Open("validate_ok_trial", "trial"));
    }

    [Fact]
    public void Lease_verification_rejects_lease_signed_with_the_wrong_key_even_with_matching_claims()
    {
        var vector = Vectors.Lease("lease_wrong_key");
        var result = LeaseVerifier.Verify(vector.GetProperty("token").GetString(), Vectors.WrongPublicKey, Vectors.ProductId,
            Vectors.TestHwid, DateTimeOffset.FromUnixTimeSeconds(vector.GetProperty("now").GetInt64()));
        // Under its own (wrong) key the token is authentic - proving the vector really tests key pinning.
        Assert.Equal(LeaseStatus.Valid, result.Status);
    }

    [Theory]
    [MemberData(nameof(HwidExamples))]
    public void Hwid_examples_are_reproduced_exactly(int index)
    {
        var example = Vectors.Root.GetProperty("hwid").GetProperty("examples")[index];
        var raw = example.GetProperty("machineIdRaw").GetString()!;

        Assert.Equal(HardwareId.Prefix, Vectors.Root.GetProperty("hwid").GetProperty("prefix").GetString());
        Assert.Equal(example.GetProperty("machineIdNormalized").GetString(), HardwareId.NormalizeMachineId(raw));
        Assert.Equal(example.GetProperty("hwid").GetString(), HardwareId.FromMachineId(raw));
        Assert.Equal(example.GetProperty("serverHwidHash").GetString(), HardwareId.HashHwid(example.GetProperty("hwid").GetString()!));
    }

    [Fact]
    public void Server_hash_of_test_hwid_matches()
    {
        var expected = Vectors.Root.GetProperty("hwid").GetProperty("serverHashOfTestHwid");
        Assert.Equal(expected.GetProperty("hwidHash").GetString(), HardwareId.HashHwid(expected.GetProperty("hwid").GetString()!));
    }

    private static string Describe(EnvelopeStatus status) => status switch
    {
        EnvelopeStatus.Valid => "valid",
        EnvelopeStatus.InvalidSignature => "invalid_signature",
        EnvelopeStatus.NonceMismatch => "nonce_mismatch",
        EnvelopeStatus.ProductMismatch => "product_mismatch",
        EnvelopeStatus.TypeMismatch => "type_mismatch",
        EnvelopeStatus.HwidMismatch => "hwid_mismatch",
        _ => "malformed",
    };

    private static string Describe(LeaseStatus status) => status switch
    {
        LeaseStatus.Valid => "valid",
        LeaseStatus.Expired => "expired",
        LeaseStatus.InvalidSignature => "invalid_signature",
        LeaseStatus.ProductMismatch => "product_mismatch",
        LeaseStatus.HwidMismatch => "hwid_mismatch",
        _ => "malformed",
    };

    private static void AssertPayloadMatches(JsonElement expected, SignedPayload actual)
    {
        Assert.Equal(expected.GetProperty("type").GetString(), actual.Type);
        Assert.Equal(expected.GetProperty("ok").GetBoolean(), actual.Ok);
        Assert.Equal(expected.GetProperty("code").GetString(), actual.Code);
        Assert.Equal(expected.GetProperty("message").GetString(), actual.Message);
        Assert.Equal(expected.GetProperty("nonce").GetString(), actual.Nonce);
        Assert.Equal(expected.GetProperty("requestId").GetString(), actual.RequestId);
        Assert.Equal(expected.GetProperty("serverTime").GetInt64(), actual.ServerTime);
        Assert.Equal(expected.GetProperty("productId").GetString(), actual.ProductId);

        var license = expected.GetProperty("license");
        if (license.ValueKind == JsonValueKind.Null)
        {
            Assert.Null(actual.License);
        }
        else
        {
            var l = actual.License!;
            Assert.Equal(license.GetProperty("id").GetString(), l.Id);
            Assert.Equal(license.GetProperty("plan").GetString(), l.Plan);
            Assert.Equal(license.GetProperty("status").GetString(), l.Status);
            Assert.Equal(license.GetProperty("features").EnumerateArray().Select(f => f.GetString()), l.Features);
            Assert.Equal(license.GetProperty("expiresAt").GetInt64(), l.ExpiresAtUnix);
            Assert.Equal(license.GetProperty("maxDevices").GetInt32(), l.MaxDevices);
            Assert.Equal(license.GetProperty("devicesUsed").GetInt32(), l.DevicesUsed);
            Assert.Equal(license.GetProperty("createdAt").GetInt64(), l.CreatedAtUnix);
            Assert.Equal(license.TryGetProperty("trial", out var trial) && trial.GetBoolean(), l.IsTrial);
            Assert.Equal(license.TryGetProperty("trialRef", out var trialRef) ? trialRef.GetString() : null, l.TrialRef);
        }

        var activation = expected.GetProperty("activation");
        if (activation.ValueKind == JsonValueKind.Null)
        {
            Assert.Null(actual.Activation);
            Assert.Null(actual.DeviceSecret);
        }
        else
        {
            Assert.Equal(activation.GetProperty("id").GetString(), actual.Activation!.Id);
            Assert.Equal(activation.GetProperty("status").GetString(), actual.Activation.Status);
            Assert.Equal(activation.GetProperty("firstSeenAt").GetInt64(), actual.Activation.FirstSeenAtUnix);
            Assert.Equal(activation.GetProperty("deviceSecret").GetString(), actual.DeviceSecret);
            Assert.True(actual.Activation.DeviceSecretIssued);
        }

        var lease = expected.GetProperty("lease");
        if (lease.ValueKind == JsonValueKind.Null)
        {
            Assert.Null(actual.Lease);
        }
        else
        {
            Assert.Equal(lease.GetProperty("token").GetString(), actual.Lease!.Token);
            Assert.Equal(lease.GetProperty("expiresAt").GetInt64(), actual.Lease.ExpiresAtUnix);
        }

        var update = expected.GetProperty("update");
        if (update.ValueKind == JsonValueKind.Null)
        {
            Assert.Null(actual.Update);
        }
        else
        {
            Assert.Equal(update.GetProperty("latestVersion").GetString(), actual.Update!.LatestVersion);
            Assert.Equal(update.GetProperty("minVersion").GetString(), actual.Update.MinVersion);
            Assert.Equal(update.GetProperty("updateAvailable").GetBoolean(), actual.Update.UpdateAvailable);
            Assert.Equal(update.GetProperty("mandatory").GetBoolean(), actual.Update.Mandatory);
            Assert.Equal(update.GetProperty("changelog").GetString(), actual.Update.Changelog);
        }

        // The key of a started in-app trial: read only from ok answers of type "trial".
        var expectedKey = expected.TryGetProperty("trial", out var startedTrial) && actual.Type == "trial" && actual.Ok
            ? startedTrial.GetProperty("key").GetString()
            : null;
        Assert.Equal(expectedKey, actual.TrialKey);
    }
}
