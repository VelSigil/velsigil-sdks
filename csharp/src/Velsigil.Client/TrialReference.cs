using System;

namespace Velsigil.Client;

/// <summary>
/// Free-trial conversion references (SPEC 9.7, servers since 2026-10-06). The server signs an opaque reference into the
/// license of every free trial a purchase can still convert (<see cref="VelsigilResult.TrialRef"/>). The app adds it to
/// its "Buy now" link; the seller's checkout carries it to the payment provider, and the purchase then turns THIS trial
/// into the paid license (same key) whatever e-mail address the buyer pays with. The SDK never interprets it.
/// </summary>
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

    /// <summary>
    /// <paramref name="url"/> with <c>velsigil_trial=&lt;reference&gt;</c> appended to the query (before any fragment;
    /// the rest of the URL is kept as it is), or <c>client_reference_id=&lt;reference&gt;</c> for a Stripe Payment Link
    /// (<c>https://buy.stripe.com/…</c>). Returns <paramref name="url"/> unchanged when the reference is missing or
    /// malformed, or the URL is not an absolute http(s) URL.
    /// </summary>
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
