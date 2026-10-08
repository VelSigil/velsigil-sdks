using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Velsigil.Client;
using Velsigil.Client.Storage;

namespace ConsoleExample;

/// <summary>
/// Velsigil .NET SDK walkthrough.
///
///   dotnet run --project examples/ConsoleExample -- [validate|offline|update|download &lt;file&gt;|deactivate]
///
/// Set <see cref="ApiUrl"/>, <see cref="ProductId"/> and <see cref="PublicKey"/> below to your product's values and
/// rebuild. While a placeholder (a value in angle brackets) is still in place, the example prints a usage message and
/// exits with code 2.
///
/// Optional environment variables (neither one is a trust anchor):
///   VELSIGIL_LICENSE_KEY   the license key; prompted when missing, never printed
///   VELSIGIL_APP_VERSION   defaults to 1.0.0
///
/// Local testing only: VELSIGIL_URL, VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY override the three constants, and
/// only when the API URL (VELSIGIL_URL, or ApiUrl when VELSIGIL_URL is not set) is loopback: host localhost,
/// 127.0.0.1 or [::1], e.g. a development server on this machine. For any other URL the example refuses to start
/// (exit code 2) instead of trusting a server or public key taken from the environment.
///
/// In a real application the API URL, product id and public key are compiled-in constants: never load the public
/// key from a file, the registry, an environment variable or the network, or an attacker can swap it for their own.
/// </summary>
internal static class Program
{
    // Replace these with the values from the Velsigil panel (Products > your product > Integration). Keep them
    // compiled in: the public key is the trust anchor that makes forged server responses detectable.
    private const string ApiUrl = "<your Velsigil server URL, e.g. https://licenses.example.com>";
    private const string ProductId = "<your product id>";
    private const string PublicKey = "<your product's public key>";

    private const string Usage =
        "usage: dotnet run --project examples/ConsoleExample -- [validate|offline|update|download <file>|deactivate]\n" +
        "Set ApiUrl, ProductId and PublicKey in examples/ConsoleExample/Program.cs to your product's values from the\n" +
        "Velsigil panel (Products > your product > Integration), then rebuild. For a server on this machine only\n" +
        "(localhost, 127.0.0.1 or [::1]), VELSIGIL_URL, VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY can override them.";

    private static async Task<int> Main(string[] args)
    {
        var command = args.Length > 0 ? args[0].ToLowerInvariant() : "validate";
        var appVersion = Environment.GetEnvironmentVariable("VELSIGIL_APP_VERSION") ?? "1.0.0";

        if (!TryResolveConfiguration(out var apiUrl, out var productId, out var publicKey))
        {
            Console.Error.WriteLine(Usage);
            return 2;
        }

        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancel.Cancel();
        };

        using var client = CreateClient(apiUrl, productId, publicKey);
        if (client is null) return 2;

        Console.WriteLine("Hardware id : " + client.HardwareId);
        Console.WriteLine("Key id      : " + client.KeyId);

        try
        {
            switch (command)
            {
                case "validate":
                    return await ValidateAsync(client, appVersion, cancel.Token);
                case "offline":
                    Print(client.ValidateOffline());
                    return 0;
                case "update":
                    return await CheckUpdateAsync(client, appVersion, cancel.Token);
                case "download":
                    if (args.Length < 2)
                    {
                        Console.Error.WriteLine("usage: download <destination-file>");
                        return 2;
                    }
                    return await DownloadAsync(client, args[1], cancel.Token);
                case "deactivate":
                    var result = await client.DeactivateAsync(ReadLicenseKey(), cancel.Token);
                    Print(result);
                    return result.Ok ? 0 : 1;
                default:
                    Console.Error.WriteLine("Unknown command. Use validate, offline, update, download <file> or deactivate.");
                    return 2;
            }
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Cancelled.");
            return 130;
        }
    }

    // The compiled-in constants, or (local testing only) the environment override, which is honoured only when the
    // API URL is loopback. False when the example cannot run: a placeholder is still in place, or an override was
    // given for a non-loopback URL (reported here; the caller prints the usage message).
    private static bool TryResolveConfiguration(out string apiUrl, out string productId, out string publicKey)
    {
        var urlOverride = EnvironmentOverride("VELSIGIL_URL");
        var productIdOverride = EnvironmentOverride("VELSIGIL_PRODUCT_ID");
        var publicKeyOverride = EnvironmentOverride("VELSIGIL_PUBLIC_KEY");

        apiUrl = urlOverride ?? ApiUrl;
        productId = productIdOverride ?? ProductId;
        publicKey = publicKeyOverride ?? PublicKey;

        if ((urlOverride != null || productIdOverride != null || publicKeyOverride != null) && !IsLoopbackUrl(apiUrl))
        {
            Console.Error.WriteLine("VELSIGIL_URL, VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY are for local testing and are honoured only " +
                "when the API URL is loopback (localhost, 127.0.0.1 or [::1]).");
            return false;
        }

        return !IsPlaceholder(apiUrl) && !IsPlaceholder(productId) && !IsPlaceholder(publicKey);
    }

    private static string? EnvironmentOverride(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    // The placeholders above are in angle brackets; no real URL, product id or base64 key contains '<'.
    private static bool IsPlaceholder(string value) => string.IsNullOrWhiteSpace(value) || value.IndexOf('<') >= 0;

    // The same loopback set as the SDK's plain-http and test-key rules: localhost, 127.0.0.1 and ::1, over http or https.
    private static bool IsLoopbackUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return false;
        if (string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)) return true;
        return IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address)
            && (address.Equals(IPAddress.Loopback) || address.Equals(IPAddress.IPv6Loopback));
    }

    private static VelsigilClient? CreateClient(string apiUrl, string productId, string publicKey)
    {
        try
        {
            // One long-lived client per product. The FileStore keeps the device secret and offline lease in a
            // per-user directory with owner-only permissions.
            return new VelsigilClient(apiUrl, productId, publicKey, new VelsigilClientOptions
            {
                Store = FileStore.CreateDefault("ConsoleExample"),
                Timeout = TimeSpan.FromSeconds(15),
                StoreErrorHandler = error => Console.Error.WriteLine("warning: license state could not be saved (" + error.GetType().Name + ")"),
            });
        }
        catch (ArgumentException error)
        {
            // A malformed URL, product id or key, or a public key of the SDK test vectors with a non-localhost URL.
            Console.Error.WriteLine("Invalid configuration: " + error.Message);
            return null;
        }
    }

    private static async Task<int> ValidateAsync(VelsigilClient client, string appVersion, CancellationToken cancellationToken)
    {
        var result = await client.ValidateWithOfflineFallbackAsync(
            ReadLicenseKey(),
            new ValidateOptions { Version = appVersion, DeviceName = Environment.MachineName },
            cancellationToken);
        Print(result);

        if (!result.Ok)
        {
            // Business failures are results, not exceptions: show a helpful message and stop.
            switch (result.Code)
            {
                case ResultCodes.ClockSkew:
                    Console.WriteLine("Please correct your system clock.");
                    break;
                case ResultCodes.NetworkError:
                case ResultCodes.NoLease:
                case ResultCodes.LeaseExpired:
                    Console.WriteLine("The license server is unreachable; connect to the internet and try again.");
                    break;
                case ResultCodes.InternalError:
                    // An unsigned 5xx (the server is temporarily unavailable) and no offline lease is stored.
                    Console.WriteLine("The license server is temporarily unavailable; try again later.");
                    break;
                case ResultCodes.InvalidResponse:
                    Console.WriteLine("The server response could not be verified (proxy or tampering?).");
                    break;
            }
            return 1;
        }

        // Gate features on the verified result - never on a value the user could edit.
        Console.WriteLine(result.HasFeature("pro") ? "Pro features enabled." : "Running the standard edition.");
        if (result.Update is { UpdateAvailable: true } update)
        {
            Console.WriteLine("Update " + update.LatestVersion + " available" + (update.Mandatory ? " (mandatory)." : "."));
        }
        return 0;
    }

    private static async Task<int> CheckUpdateAsync(VelsigilClient client, string appVersion, CancellationToken cancellationToken)
    {
        var result = await client.CheckUpdateAsync(appVersion, cancellationToken);
        Print(result);
        if (result.Update is { } update)
        {
            Console.WriteLine("Latest      : " + update.LatestVersion + (update.UpdateAvailable ? " (newer than " + appVersion + ")" : " (up to date)"));
            Console.WriteLine("Changelog   : " + update.Changelog);
        }
        return result.Ok || result.Code == ResultCodes.NoRelease ? 0 : 1;
    }

    private static async Task<int> DownloadAsync(VelsigilClient client, string destination, CancellationToken cancellationToken)
    {
        var grant = await client.GetDownloadAsync(ReadLicenseKey(), version: null, cancellationToken);
        Print(grant);
        var download = grant.Download;
        if (!grant.Ok || download is null) return 1;

        // The SDK writes to a temporary file and only moves it into place after the size and SHA-256
        // match the signed values.
        var progress = new Progress<long>(bytes =>
            Console.Write("\rDownloaded  : " + (bytes * 100 / Math.Max(1, download.Size)).ToString(CultureInfo.InvariantCulture) + "%"));
        var file = await client.DownloadFileAsync(download, destination, progress, cancellationToken);
        Console.WriteLine();
        Print(file);
        if (file.Ok) Console.WriteLine("Saved " + download.FileName + " (" + download.Version + ") to " + Path.GetFullPath(destination));
        return file.Ok ? 0 : 1;
    }

    private static string ReadLicenseKey()
    {
        var key = Environment.GetEnvironmentVariable("VELSIGIL_LICENSE_KEY");
        if (!string.IsNullOrWhiteSpace(key)) return key;
        Console.Write("License key: ");
        return Console.ReadLine() ?? string.Empty;
    }

    // Prints only non-secret fields: never log license keys, device secrets or lease tokens.
    private static void Print(VelsigilResult result)
    {
        Console.WriteLine("Result      : " + (result.Ok ? "OK" : "FAILED") + " [" + result.Code + "]" + (result.Offline ? " (offline lease)" : string.Empty));
        Console.WriteLine("Message     : " + result.Message);
        if (result.License is { } license)
        {
            Console.WriteLine("Plan        : " + license.Plan + " (" + license.Status + ")");
            Console.WriteLine("Devices     : " + license.DevicesUsed.ToString(CultureInfo.InvariantCulture) + "/" + license.MaxDevices.ToString(CultureInfo.InvariantCulture));
        }
        if (result.License != null || result.LeaseClaims != null)
        {
            Console.WriteLine("Expires     : " + (result.IsLifetime ? "never" : result.ExpiresAt?.ToString("u", CultureInfo.InvariantCulture) + " (" + result.DaysRemaining?.ToString(CultureInfo.InvariantCulture) + " days)"));
            Console.WriteLine("Features    : " + string.Join(", ", result.Features));
        }
        if (result.RetryAfter is { } retry) Console.WriteLine("Retry after : " + retry.TotalSeconds.ToString(CultureInfo.InvariantCulture) + " s");
        if (result.RequestId != null) Console.WriteLine("Request id  : " + result.RequestId);
    }
}
