using System;

namespace Velsigil.Client;

/// <summary>Free-trial conversion references for "Buy now" links; the SDK never interprets them.</summary>
public static class TrialReference
{
    /// <summary>URL parameter (and Paddle custom-data key / FastSpring tag) that carries the reference.</summary>
    public const string Parameter = "velsigil_trial";

    private const string StripePaymentLinkHost = "buy.stripe.com";
    private const string StripeReferenceParameter = "client_reference_id";
    private const int MaxLength = 200;

    /// <summary>True for 1-200 characters of <c>[A-Za-z0-9_-]</c> (safe in a URL without encoding).</summary>
    public static bool IsWellFormed(string? value)
    {
        if (value == null || value.Length == 0 || value.Length > MaxLength) return false;
        foreach (var c in value)
        {
            var ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>Appends the reference to <paramref name="url"/> (client_reference_id for Stripe Payment Links); unchanged if invalid.</summary>
    public static string Append(string url, string? reference)
    {
        if (url == null) throw new ArgumentNullException(nameof(url));
        if (!IsWellFormed(reference)) return url;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return url;
        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase) && !string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase)) return url;
        var parameter = string.Equals(uri.Host, StripePaymentLinkHost, StringComparison.OrdinalIgnoreCase) ? StripeReferenceParameter : Parameter;
        var hashAt = url.IndexOf('#');
        var baseUrl = hashAt >= 0 ? url.Substring(0, hashAt) : url;
        var fragment = hashAt >= 0 ? url.Substring(hashAt) : string.Empty;
        string separator;
        if (baseUrl.IndexOf('?') < 0) separator = "?";
        else if (baseUrl.EndsWith("?", StringComparison.Ordinal) || baseUrl.EndsWith("&", StringComparison.Ordinal)) separator = string.Empty;
        else separator = "&";
        return baseUrl + separator + parameter + "=" + reference + fragment;
    }
}
