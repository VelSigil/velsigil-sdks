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

    /// <summary>
    /// The signed lease or <c>activation.hwidHash</c> belongs to another device than the one the
    /// (device-bound) request was sent for.
    /// </summary>
    HwidMismatch,
}

/// <summary>
/// Verifies <c>{ data, sig, kid }</c> envelopes (SPEC 10.1). The Ed25519 signature is checked over the
/// exact ASCII bytes of the <c>data</c> string <b>before</b> anything is decoded or parsed. Only the
/// constructor-supplied public key is trusted; <c>kid</c> is ignored for key selection.
/// </summary>
internal static class EnvelopeVerifier
{
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Parses the raw HTTP body as an envelope and verifies it.</summary>
    /// <param name="key">The pinned product key.</param>
    /// <param name="body">The raw HTTP response body.</param>
    /// <param name="expectedNonce">The nonce sent with the request.</param>
    /// <param name="expectedProductId">The configured product id.</param>
    /// <param name="expectedType">
    /// The request type the payload must answer (always checked: the server also signs <c>ok</c> answers
    /// to <c>update_check</c>, which needs no license).
    /// </param>
    /// <param name="expectedHwid">
    /// The hwid sent with a device-bound request (validate, deactivate, download), or null. When set, the
    /// signed lease and the optional <c>activation.hwidHash</c> must belong to this device.
    /// </param>
    /// <param name="payload">The verified payload (only for <see cref="EnvelopeStatus.Valid"/>).</param>
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

        // 1. A missing or undecodable signature can never be valid.
        if (string.IsNullOrEmpty(sig) || !Base64Url.TryDecode(sig, out var signature) || signature.Length != Ed25519Verifier.SignatureLength)
        {
            return EnvelopeStatus.InvalidSignature;
        }

        // 2. The signed string must be pure base64url so that "its ASCII bytes" is unambiguous.
        if (!Base64Url.IsUnpaddedAlphabet(data)) return EnvelopeStatus.Malformed;

        // 3. Verify over the exact bytes received, before decoding or parsing anything.
        if (!key.Verify(Encoding.ASCII.GetBytes(data), signature)) return EnvelopeStatus.InvalidSignature;

        // 4. Only now decode and parse the (authenticated) payload.
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

        // 5. Bind the response to this request and this product.
        if (!string.Equals(parsed.Nonce, expectedNonce, StringComparison.Ordinal)) return EnvelopeStatus.NonceMismatch;
        if (!string.Equals(parsed.ProductId, expectedProductId, StringComparison.OrdinalIgnoreCase)) return EnvelopeStatus.ProductMismatch;
        if (string.IsNullOrEmpty(expectedType) || !string.Equals(parsed.Type, expectedType, StringComparison.Ordinal)) return EnvelopeStatus.TypeMismatch;

        // 6. The signature binds the payload to the request only through nonce, product and type. For a
        //    device-bound request its lease / activation must also describe the requesting device;
        //    otherwise the request (hwid, device secret) was rewritten in transit, e.g. by a
        //    license-sharing proxy, and the answer is about another device.
        if (expectedHwid != null)
        {
            var binding = CheckDeviceBinding(key, parsed, expectedProductId, expectedHwid);
            if (binding != EnvelopeStatus.Valid) return binding;
        }

        payload = parsed;
        return EnvelopeStatus.Valid;
    }

    /// <summary>
    /// Reports device-binding failures only. Other lease defects (expired, ...) are not binding failures;
    /// such a lease is simply never stored.
    /// </summary>
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
