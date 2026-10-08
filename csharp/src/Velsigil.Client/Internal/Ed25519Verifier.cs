using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Velsigil.Client.Internal;

/// <summary>
/// Ed25519 signature verification bound to a single, application-supplied public key
/// (BouncyCastle <see cref="Ed25519Signer"/>; RFC 8032 pure Ed25519). Instances are immutable and
/// thread-safe: a fresh signer is created for every verification.
/// </summary>
internal sealed class Ed25519Verifier
{
    public const int PublicKeyLength = 32;
    public const int SignatureLength = 64;

    private readonly Ed25519PublicKeyParameters _publicKey;

    private Ed25519Verifier(byte[] rawKey, Ed25519PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
        KeyId = Crypto.ToHex(Crypto.Sha256(rawKey)).Substring(0, 16);
    }

    /// <summary>Key id as the server computes it: first 16 hex chars of SHA-256(raw key).</summary>
    public string KeyId { get; }

    /// <summary>
    /// Parses a raw 32-byte Ed25519 public key given as standard base64 (the format shown in the panel).
    /// base64url is accepted as well. Throws <see cref="ArgumentException"/> for anything else.
    /// </summary>
    public static Ed25519Verifier FromBase64(string publicKeyBase64)
    {
        if (string.IsNullOrWhiteSpace(publicKeyBase64))
        {
            throw new ArgumentException("A product public key is required.", nameof(publicKeyBase64));
        }

        var text = publicKeyBase64.Trim();
        byte[]? raw;
        try
        {
            raw = Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            if (!Base64Url.TryDecode(text, out raw))
            {
                throw new ArgumentException("The product public key is not valid base64.", nameof(publicKeyBase64));
            }
        }

        if (raw.Length != PublicKeyLength)
        {
            throw new ArgumentException("The product public key must decode to exactly 32 bytes.", nameof(publicKeyBase64));
        }

        Ed25519PublicKeyParameters parameters;
        try
        {
            parameters = new Ed25519PublicKeyParameters(raw, 0);
        }
        catch (ArgumentException)
        {
            throw new ArgumentException("The product public key is not a valid Ed25519 public key.", nameof(publicKeyBase64));
        }

        return new Ed25519Verifier(raw, parameters);
    }

    /// <summary>Verifies <paramref name="signature"/> over <paramref name="message"/>. Never throws.</summary>
    public bool Verify(byte[] message, byte[] signature)
    {
        if (message is null || signature is null || signature.Length != SignatureLength) return false;
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(false, _publicKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        catch (Exception)
        {
            // Any internal failure is treated as an invalid signature (fail closed).
            return false;
        }
    }
}
