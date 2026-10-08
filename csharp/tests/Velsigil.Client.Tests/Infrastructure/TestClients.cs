using System;
using System.IO;
using System.Net.Http;
using Velsigil.Client.Storage;

namespace Velsigil.Client.Tests.Infrastructure;

internal static class TestClients
{
    public const string ApiUrl = "https://licenses.example.test";
    public const string LicenseKey = "VSG-ABCDE-FGHJK-LMNPQ-RSTVW-XYZ23";

    // All temporary directories of one test run live under this folder, removed when the process exits.
    private static readonly string RunDirectory = CreateRunDirectory();

    public static VelsigilClient Create(
        MockServer server,
        IVelsigilStore? store = null,
        FakeClock? clock = null,
        TimeSpan? timeout = null,
        Action<Exception>? storeErrorHandler = null,
        string apiUrl = ApiUrl,
        string publicKey = "")
    {
        return new VelsigilClient(apiUrl, Vectors.ProductId, publicKey.Length == 0 ? Vectors.PublicKey : publicKey, new VelsigilClientOptions
        {
            HttpClient = new HttpClient(server),
            Store = store ?? new MemoryStore(),
            HardwareId = Vectors.TestHwid,
            Clock = (clock ?? new FakeClock(Payloads.ServerTime)).GetNow,
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
            StoreErrorHandler = storeErrorHandler,
        });
    }

    /// <summary>A fresh, empty directory for one test.</summary>
    public static string TempDirectory()
    {
        var path = Path.Combine(RunDirectory, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static string CreateRunDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "velsigil-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try
            {
                Directory.Delete(path, recursive: true);
            }
            catch (IOException)
            {
                // Best effort.
            }
            catch (UnauthorizedAccessException)
            {
                // Best effort.
            }
        };
        return path;
    }
}
