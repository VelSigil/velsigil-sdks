using System;
using System.Text;
using System.Text.Json;
using Velsigil.Client.Internal;

namespace Velsigil.Client;

/// <summary>Outcome of verifying an offline lease token.</summary>
public enum LeaseStatus
{
    /// <summary>Signature valid, lease well-formed, matches product and device, not expired.</summary>
    Valid,

    /// <summary>The lease is authentic but its expiry has passed.</summary>
    Expired,

    /// <summary>The signature is not valid for the pinned public key.</summary>
    InvalidSignature,

    /// <summary>The lease was issued for another product.</summary>
    ProductMismatch,

    /// <summary>The lease was issued for another device.</summary>
    HwidMismatch,

    /// <summary>Not a lease token (wrong structure, encoding, version or type).</summary>
    Malformed,
}

/// <summary>Result of <see cref="LeaseVerifier.Verify(string?, string, string, string, DateTimeOffset)"/>.</summary>
public sealed class LeaseVerification
{
    internal LeaseVerification(LeaseStatus status, LeaseClaims? claims)
    {
        Status = status;
        Claims = claims;
    }

    /// <summary>The verification outcome.</summary>
    public LeaseStatus Status { get; }

    /// <summary>True only for <see cref="LeaseStatus.Valid"/>.</summary>
    public bool IsValid => Status == LeaseStatus.Valid;

    /// <summary>Authenticated claims (also for expired or mismatched leases); rely on them only when <see cref="IsValid"/>.</summary>
    public LeaseClaims? Claims { get; }
}

/// <summary>Verifies offline lease tokens: signature, <c>typ</c>, product, device and expiry.</summary>
/// <remarks>Offline checks trust the local clock, which is why leases are short-lived.</remarks>
public static class LeaseVerifier
{
    private const int MaxTokenLength = 16 * 1024;

    /// <summary>Verifies <paramref name="token"/> against <paramref name="publicKeyBase64"/>.</summary>
    /// <param name="token">The lease token.</param>
    /// <param name="publicKeyBase64">The product's Ed25519 public key (standard base64).</param>
    /// <param name="productId">The product id the lease must belong to.</param>
    /// <param name="hwid">The raw hardware id of this machine (the SDK hashes it).</param>
    /// <param name="now">The current time.</param>
    /// <exception cref="ArgumentException">The public key is invalid or is a published test-vector key.</exception>
    public static LeaseVerification Verify(string? token, string publicKeyBase64, string productId, string hwid, DateTimeOffset now)
    {
        var key = Ed25519Verifier.FromBase64(publicKeyBase64);
        if (key.IsPublishedTestKey)
        {
            throw new ArgumentException(PublishedTestKeys.RefusalMessage, nameof(publicKeyBase64));
        }
        return Verify(token, key, productId, hwid, now);
    }

    /// <summary>Verifies with a decoded key and accepts the published test keys (SDK tests only).</summary>
    internal static LeaseVerification Verify(string? token, Ed25519Verifier key, string? productId, string? hwid, DateTimeOffset now) =>
        Verify(token, key, productId ?? string.Empty, hwid ?? string.Empty, now.ToUnixTimeSeconds());

    internal static LeaseVerification Verify(string? token, Ed25519Verifier key, string productId, string hwid, long nowUnix)
    {
        if (string.IsNullOrEmpty(token) || token!.Length > MaxTokenLength) return Fail(LeaseStatus.Malformed);

        var dot = token.IndexOf('.');
        if (dot <= 0 || dot != token.LastIndexOf('.') || dot == token.Length - 1) return Fail(LeaseStatus.Malformed);

        var body = token.Substring(0, dot);
        var sigText = token.Substring(dot + 1);
        if (!Base64Url.IsUnpaddedAlphabet(body)) return Fail(LeaseStatus.Malformed);
        if (!Base64Url.TryDecode(sigText, out var signature)) return Fail(LeaseStatus.Malformed);

        // Signature first, over the exact ASCII bytes of the first part.
        if (signature.Length != Ed25519Verifier.SignatureLength || !key.Verify(Encoding.ASCII.GetBytes(body), signature))
        {
            return Fail(LeaseStatus.InvalidSignature);
        }

        if (!Base64Url.TryDecode(body, out var json) || !JsonRead.TryParse(json, out var document) || document is null)
        {
            return Fail(LeaseStatus.Malformed);
        }

        string leaseProductId, licenseId, activationId, hwidHash, plan;
        System.Collections.Generic.IReadOnlyList<string> features;
        long? licenseExpiresAt;
        long issuedAt, expiresAt;
        bool trial;
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return Fail(LeaseStatus.Malformed);
            if (!JsonRead.TryGetInt64(root, "v", out var version) || version != 1) return Fail(LeaseStatus.Malformed);
            if (!JsonRead.TryGetString(root, "typ", out var typ) || !string.Equals(typ, "lease", StringComparison.Ordinal))
            {
                return Fail(LeaseStatus.Malformed);
            }

            if (!JsonRead.TryGetString(root, "productId", out leaseProductId)
                || !JsonRead.TryGetString(root, "licenseId", out licenseId)
                || !JsonRead.TryGetString(root, "activationId", out activationId)
                || !JsonRead.TryGetString(root, "hwidHash", out hwidHash)
                || !JsonRead.TryGetString(root, "plan", out plan)
                || !JsonRead.TryGetStringArray(root, "features", out features)
                || !JsonRead.TryGetOptionalUnixTime(root, "licenseExpiresAt", out licenseExpiresAt)
                || !JsonRead.TryGetUnixTime(root, "iat", out issuedAt)
                || !JsonRead.TryGetUnixTime(root, "exp", out expiresAt)
                // Optional trial flag; a non-boolean is malformed.
                || !JsonRead.TryGetOptionalBoolean(root, "trial", out trial))
            {
                return Fail(LeaseStatus.Malformed);
            }
        }

        LeaseStatus status;
        if (!string.Equals(leaseProductId, productId, StringComparison.OrdinalIgnoreCase)) status = LeaseStatus.ProductMismatch;
        else if (hwid.Length == 0 || !Crypto.HexEquals(hwidHash, HardwareId.HashHwid(hwid))) status = LeaseStatus.HwidMismatch;
        else if (nowUnix >= expiresAt) status = LeaseStatus.Expired;
        else status = LeaseStatus.Valid;

        // Claims of an expired or mismatched lease are diagnostics only: HasFeature is false.
        var claims = new LeaseClaims(leaseProductId, licenseId, activationId, hwidHash, plan, features, licenseExpiresAt, issuedAt, expiresAt, valid: status == LeaseStatus.Valid, isTrial: trial);
        return new LeaseVerification(status, claims);
    }

    private static LeaseVerification Fail(LeaseStatus status) => new LeaseVerification(status, null);
}
