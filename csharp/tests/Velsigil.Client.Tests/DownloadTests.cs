using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

public class DownloadTests
{
    private const string Key = TestClients.LicenseKey;
    private static readonly byte[] FileBytes = Encoding.UTF8.GetBytes("Velsigil release payload v1.4.0 " + new string('x', 200_000));

    private static MockServer CreateServer(string url, byte[] served, long? advertisedSize = null, string? advertisedSha = null)
    {
        var server = new MockServer();
        server.Respond(r =>
        {
            if (r.Method == HttpMethod.Get)
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(served) };
            }

            var payload = Payloads.Base(r, true, "ok", "Download ready.");
            payload["download"] = new JsonObject
            {
                ["url"] = url,
                ["expiresAt"] = Payloads.ServerTime + 600,
                ["fileName"] = "app-1.4.0.zip",
                ["size"] = advertisedSize ?? FileBytes.Length,
                ["sha256"] = advertisedSha ?? Convert.ToHexString(SHA256.HashData(FileBytes)),
                ["version"] = "1.4.0",
            };
            return Responses.Signed(payload);
        });
        return server;
    }

    [Fact]
    public async Task Get_download_returns_the_signed_grant()
    {
        var server = CreateServer("/api/download/abc", FileBytes);
        using var client = TestClients.Create(server);

        var result = await client.GetDownloadAsync(Key, "1.4.0");

        Assert.True(result.Ok);
        var download = result.Download!;
        Assert.Equal("/api/download/abc", download.Url);
        Assert.Equal("app-1.4.0.zip", download.FileName);
        Assert.Equal(FileBytes.Length, download.Size);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(FileBytes)).ToLowerInvariant(), download.Sha256);
        Assert.Equal("1.4.0", download.Version);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(Payloads.ServerTime + 600), download.ExpiresAt);
        Assert.DoesNotContain("abc", download.ToString(), StringComparison.Ordinal);

        var request = server.Requests.Single();
        Assert.Equal("/api/client/v1/download", request.Path);
        Assert.Equal(
            new[] { "hwid", "licenseKey", "nonce", "productId", "timestamp", "version" },
            request.Json!.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public async Task Download_file_is_verified_and_written_atomically()
    {
        var server = CreateServer("/api/download/abc", FileBytes);
        using var client = TestClients.Create(server);
        var directory = TestClients.TempDirectory();
        var destination = Path.Combine(directory, "app.zip");
        var grant = (await client.GetDownloadAsync(Key)).Download!;
        var progress = new List<long>();

        var result = await client.DownloadFileAsync(grant, destination, new SyncProgress(progress.Add));

        Assert.True(result.Ok, result.Message);
        Assert.True(result.Verified);
        Assert.Equal(FileBytes, File.ReadAllBytes(destination));
        Assert.Equal(FileBytes.Length, progress.Last());
        Assert.Equal(new[] { "app.zip" }, Directory.GetFiles(directory).Select(Path.GetFileName));
        Assert.Equal(TestClients.ApiUrl + "/api/download/abc", server.Requests.Last().Uri.ToString());
    }

    [Theory]
    [InlineData("content")]
    [InlineData("size")]
    [InlineData("truncated")]
    public async Task Download_integrity_failures_are_rejected_and_discarded(string tamper)
    {
        var served = tamper switch
        {
            "content" => FileBytes.Select((b, i) => i == 1000 ? (byte)(b ^ 0xFF) : b).ToArray(),
            "truncated" => FileBytes.Take(FileBytes.Length - 1).ToArray(),
            _ => FileBytes.Concat(new byte[] { 0x00 }).ToArray(),
        };
        var server = CreateServer("https://cdn.example.test/releases/abc", served);
        using var client = TestClients.Create(server);
        var directory = TestClients.TempDirectory();
        var destination = Path.Combine(directory, "app.zip");
        var grant = (await client.GetDownloadAsync(Key)).Download!;

        var result = await client.DownloadFileAsync(grant, destination);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.IntegrityMismatch, result.Code);
        Assert.Empty(Directory.GetFiles(directory));
    }

    [Theory]
    [InlineData("http://cdn.example.test/releases/abc")]
    [InlineData("//evil.example/abc")]
    [InlineData("ftp://cdn.example.test/abc")]
    [InlineData("https://user:pass@cdn.example.test/abc")]
    public async Task Insecure_download_urls_are_rejected_at_grant_time(string url)
    {
        var server = CreateServer(url, FileBytes);
        using var client = TestClients.Create(server);

        var result = await client.GetDownloadAsync(Key);

        // Like the other Velsigil SDKs: a grant that could never be fetched under the https policy is an
        // invalid response, not a usable result.
        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.InvalidResponse, result.Code);
        Assert.Null(result.Download);
        Assert.Single(server.Requests); // never fetched
    }

    [Theory]
    [InlineData("http://cdn.example.test/releases/abc")]
    [InlineData("//evil.example/abc")]
    [InlineData("ftp://cdn.example.test/abc")]
    public async Task Download_file_still_refuses_insecure_urls(string url)
    {
        var server = CreateServer("/api/download/abc", FileBytes);
        using var client = TestClients.Create(server);
        var grant = new DownloadInfo(url, Payloads.ServerTime + 600, "app.zip", FileBytes.Length,
            Convert.ToHexString(SHA256.HashData(FileBytes)).ToLowerInvariant(), "1.4.0");

        var result = await client.DownloadFileAsync(grant, Path.Combine(TestClients.TempDirectory(), "app.zip"));

        Assert.Equal(ResultCodes.DownloadFailed, result.Code);
        Assert.Empty(server.Requests); // never fetched
    }

    [Fact]
    public async Task Plain_http_download_url_is_accepted_for_loopback()
    {
        var server = CreateServer("http://localhost:8080/api/download/abc", FileBytes);
        using var client = TestClients.Create(server, apiUrl: "http://127.0.0.1:8080");

        var result = await client.GetDownloadAsync(Key);

        Assert.True(result.Ok, result.Message);
        Assert.Equal("http://localhost:8080/api/download/abc", result.Download!.Url);
    }

    [Fact]
    public async Task Download_redirect_followed_by_an_injected_http_client_is_rejected()
    {
        // SDK-2: an injected HttpClient follows redirects by default; the file must not be accepted.
        using var cdn = new LocalHttpServer(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(FileBytes) });
        using var panel = new LocalHttpServer(_ =>
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.Found);
            response.Headers.Location = new Uri(cdn.BaseUrl + "/releases/app.zip");
            return response;
        });
        using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, UseCookies = false });
        using var client = new VelsigilClient(panel.BaseUrl, Vectors.ProductId, Vectors.PublicKey,
            new VelsigilClientOptions { HttpClient = http, Store = new Storage.MemoryStore(), HardwareId = Vectors.TestHwid });
        var grant = new DownloadInfo("/api/download/abc", Payloads.ServerTime + 600, "app.zip", FileBytes.Length,
            Convert.ToHexString(SHA256.HashData(FileBytes)).ToLowerInvariant(), "1.4.0");
        var directory = TestClients.TempDirectory();

        var result = await client.DownloadFileAsync(grant, Path.Combine(directory, "app.zip"));

        Assert.Single(cdn.Requests); // the handler did follow the redirect...
        Assert.False(result.Ok); // ...but the (intact) file is not accepted
        Assert.Equal(ResultCodes.DownloadFailed, result.Code);
        Assert.Empty(Directory.GetFiles(directory));

        // Control: the same injected client downloads when nothing redirects.
        var direct = new DownloadInfo(cdn.BaseUrl + "/releases/app.zip", grant.ExpiresAtUnix, grant.FileName, grant.Size, grant.Sha256, grant.Version);
        Assert.True((await client.DownloadFileAsync(direct, Path.Combine(directory, "app.zip"))).Ok);
    }

    [Fact]
    public async Task Expired_download_link_is_reported()
    {
        var server = CreateServer("/api/download/abc", FileBytes);
        using var client = TestClients.Create(server);
        var grant = (await client.GetDownloadAsync(Key)).Download!;
        server.Respond(_ => Responses.Error(410, "not_found"));

        var result = await client.DownloadFileAsync(grant, Path.Combine(TestClients.TempDirectory(), "app.zip"));

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.DownloadFailed, result.Code);
        Assert.Equal(410, result.HttpStatus);
    }

    [Fact]
    public async Task Download_requires_activation_server_side()
    {
        var server = new MockServer();
        server.Respond(r => Responses.Signed(Payloads.Base(r, false, "device_not_activated", "Activate first.")));
        using var client = TestClients.Create(server);

        var result = await client.GetDownloadAsync(Key);

        Assert.False(result.Ok);
        Assert.Equal(ResultCodes.DeviceNotActivated, result.Code);
        Assert.Null(result.Download);
    }

    /// <summary>Synchronous IProgress (Progress&lt;T&gt; posts asynchronously).</summary>
    private sealed class SyncProgress : IProgress<long>
    {
        private readonly Action<long> _report;

        public SyncProgress(Action<long> report) => _report = report;

        public void Report(long value) => _report(value);
    }
}
