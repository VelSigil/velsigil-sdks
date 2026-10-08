using System;
using System.Globalization;
using System.IO;
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
/// Configuration (environment variables, for this demo only):
///   VELSIGIL_URL           https://licenses.example.com   (http only for localhost)
///   VELSIGIL_PRODUCT_ID    product UUID from the panel
///   VELSIGIL_PUBLIC_KEY    product public key (base64) from the panel's Integration tab
///   VELSIGIL_LICENSE_KEY   optional; prompted when missing
///   VELSIGIL_APP_VERSION   optional, defaults to 1.0.0
///
/// In a real application the product id and public key are compiled-in constants: never load the
/// public key from a file, the registry or the network, or an attacker can swap it for their own.
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var command = args.Length > 0 ? args[0].ToLowerInvariant() : "validate";
        var apiUrl = Environment.GetEnvironmentVariable("VELSIGIL_URL");
        var productId = Environment.GetEnvironmentVariable("VELSIGIL_PRODUCT_ID");
        var publicKey = Environment.GetEnvironmentVariable("VELSIGIL_PUBLIC_KEY");
        var appVersion = Environment.GetEnvironmentVariable("VELSIGIL_APP_VERSION") ?? "1.0.0";

        if (string.IsNullOrEmpty(apiUrl) || string.IsNullOrEmpty(productId) || string.IsNullOrEmpty(publicKey))
        {
            Console.Error.WriteLine("Set VELSIGIL_URL, VELSIGIL_PRODUCT_ID and VELSIGIL_PUBLIC_KEY (see Program.cs).");
            return 2;
        }

        using var cancel = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cancel.Cancel();
        };

        // One long-lived client per product. The FileStore keeps the device secret and offline lease in a
        // per-user directory with owner-only permissions.
        using var client = new VelsigilClient(apiUrl, productId, publicKey, new VelsigilClientOptions
        {
            Store = FileStore.CreateDefault("ConsoleExample"),
            Timeout = TimeSpan.FromSeconds(15),
            StoreErrorHandler = error => Console.Error.WriteLine("warning: license state could not be saved (" + error.GetType().Name + ")"),
        });

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
