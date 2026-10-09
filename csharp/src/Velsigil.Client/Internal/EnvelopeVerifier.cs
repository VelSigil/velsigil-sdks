using System;
using System.Text;
using System.Text.Json;

namespace Velsigil.Client.Internal;

/// <summary>Outcome of verifying a signed response envelope.</summary>
internal enum EnvelopeStatus
{
    /// <summary>Signature valid, payload well-formed, nonce/product/type match.</summary>
    Valid,

    /// <summary>Not a well-formed envelope or payload.</summary>
    Malformed,

    /// <summary>Signature missing, undecodable or not valid for the pinned public key.</summary>
    InvalidSignature,

    /// <summary>The payload echoes a different nonce than the one sent.</summary>
    NonceMismatch,

    /// <summary>The payload is for a different product.</summary>
    ProductMismatch,

    /// <summary>The payload answers a different kind of request.</summary>
    TypeMismatch,

    /// <summary>The lease or activation belongs to another device than the request.</summary>
    HwidMismatch,
}

/// <summary>Verifies <c>{ data, sig, kid }</c> envelopes over the exact <c>data</c> bytes; <c>kid</c> is ignored.</summary>
internal static class EnvelopeVerifier
{
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Parses the raw HTTP body as an envelope and verifies it.</summary>
    public static EnvelopeStatus Verify(
        Ed25519Verifier key,
        byte[] body,
        string expectedNonce,
        string expectedProductId,
        string expectedType,
        string? expectedHwid,
        out SignedPayload? payload)
    {
        payload = null;
        if (!JsonRead.TryParse(body, out var document) || document is null) return EnvelopeStatus.Malformed;
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return EnvelopeStatus.Malformed;
            if (!root.TryGetProperty("data", out var dataElement) || dataElement.ValueKind != JsonValueKind.String)
            {
                return EnvelopeStatus.Malformed;
            }

            string? sig = null;
            if (root.TryGetProperty("sig", out var sigElement) && sigElement.ValueKind == JsonValueKind.String)
            {
                sig = sigElement.GetString();
            }

            return Verify(key, dataElement.GetString() ?? string.Empty, sig, expectedNonce, expectedProductId, expectedType, expectedHwid, out payload);
        }
    }

    /// <summary>Verifies an already-extracted <paramref name="data"/>/<paramref name="sig"/> pair.</summary>
    public static EnvelopeStatus Verify(
        Ed25519Verifier key,
        string data,
        string? sig,
        string expectedNonce,
        string expectedProductId,
        string expectedType,
        string? expectedHwid,
        out SignedPayload? payload)
    {
        payload = null;

        if (string.IsNullOrEmpty(sig) || !Base64Url.TryDecode(sig, out var signature) || signature.Length != Ed25519Verifier.SignatureLength)
        {
            return EnvelopeStatus.InvalidSignature;
        }

        // The signed string must be pure base64url so its ASCII bytes are unambiguous.
        if (!Base64Url.IsUnpaddedAlphabet(data)) return EnvelopeStatus.Malformed;

        // Verify the exact bytes received before decoding or parsing anything.
        if (!key.Verify(Encoding.ASCII.GetBytes(data), signature)) return EnvelopeStatus.InvalidSignature;

        if (!Base64Url.TryDecode(data, out var json)) return EnvelopeStatus.Malformed;
        try
        {
            StrictUtf8.GetString(json);
        }
        catch (ArgumentException)
        {
            return EnvelopeStatus.Malformed;
        }

        if (!JsonRead.TryParse(json, out var document) || document is null) return EnvelopeStatus.Malformed;
        SignedPayload? parsed;
        using (document)
        {
            parsed = SignedPayload.Parse(document.RootElement);
        }
        if (parsed is null) return EnvelopeStatus.Malformed;

        if (!string.Equals(parsed.Nonce, expectedNonce, StringComparison.Ordinal)) return EnvelopeStatus.NonceMismatch;
        if (!string.Equals(parsed.ProductId, expectedProductId, StringComparison.OrdinalIgnoreCase)) return EnvelopeStatus.ProductMismatch;
        if (string.IsNullOrEmpty(expectedType) || !string.Equals(parsed.Type, expectedType, StringComparison.Ordinal)) return EnvelopeStatus.TypeMismatch;

        // A device-bound answer must describe the requesting device, or the request was rewritten in transit.
        if (expectedHwid != null)
        {
            var binding = CheckDeviceBinding(key, parsed, expectedProductId, expectedHwid);
            if (binding != EnvelopeStatus.Valid) return binding;
        }

        payload = parsed;
        return EnvelopeStatus.Valid;
    }

    /// <summary>Reports device-binding failures only; other lease defects just keep the lease from being stored.</summary>
    private static EnvelopeStatus CheckDeviceBinding(Ed25519Verifier key, SignedPayload payload, string productId, string hwid)
    {
        if (payload.ActivationHwidHash != null && !Crypto.HexEquals(payload.ActivationHwidHash, HardwareId.HashHwid(hwid)))
        {
            return EnvelopeStatus.HwidMismatch;
        }

        if (payload.Lease != null)
        {
            var lease = LeaseVerifier.Verify(payload.Lease.Token, key, productId, hwid, payload.ServerTime);
            if (lease.Status == LeaseStatus.HwidMismatch) return EnvelopeStatus.HwidMismatch;
            if (lease.Status == LeaseStatus.ProductMismatch) return EnvelopeStatus.ProductMismatch;
        }

        return EnvelopeStatus.Valid;
    }
}
