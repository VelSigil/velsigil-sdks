using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Velsigil.Client.Tests.Infrastructure;

/// <summary>Minimal HTTP/1.1 server on 127.0.0.1 for tests over real sockets; one request per connection.</summary>
internal sealed class LocalHttpServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new CancellationTokenSource();
    private readonly Func<MockRequest, HttpResponseMessage> _handler;
    private readonly List<MockRequest> _requests = new List<MockRequest>();

    public LocalHttpServer(Func<MockRequest, HttpResponseMessage> handler)
    {
        _handler = handler;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoopAsync();
    }

    public int Port { get; }

    public string BaseUrl => "http://127.0.0.1:" + Port.ToString(CultureInfo.InvariantCulture);

    public IReadOnlyList<MockRequest> Requests
    {
        get
        {
            lock (_requests)
            {
                return _requests.ToArray();
            }
        }
    }

    /// <summary>A loopback port that nothing listens on (for connection-refused tests).</summary>
    public static int GetClosedPort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        _stop.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception)
            {
                return;
            }
            _ = Task.Run(() => HandleAsync(client));
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var head = await ReadHeadAsync(stream);
                if (head is null) return;

                var lines = head.Split("\r\n");
                var requestLine = lines[0].Split(' ');
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (var i = 1; i < lines.Length; i++)
                {
                    var colon = lines[i].IndexOf(':');
                    if (colon > 0) headers[lines[i].Substring(0, colon).Trim()] = lines[i].Substring(colon + 1).Trim();
                }

                var length = headers.TryGetValue("Content-Length", out var cl) ? int.Parse(cl, CultureInfo.InvariantCulture) : 0;
                var body = new byte[length];
                var read = 0;
                while (read < length)
                {
                    var n = await stream.ReadAsync(body.AsMemory(read, length - read));
                    if (n == 0) break;
                    read += n;
                }

                var request = new MockRequest(
                    new HttpMethod(requestLine[0]),
                    new Uri(BaseUrl + requestLine[1]),
                    Encoding.UTF8.GetString(body, 0, read),
                    headers);
                lock (_requests)
                {
                    _requests.Add(request);
                }

                using var response = _handler(request);
                var payload = response.Content is null ? Array.Empty<byte>() : await response.Content.ReadAsByteArrayAsync();
                var builder = new StringBuilder();
                builder.Append("HTTP/1.1 ").Append((int)response.StatusCode).Append(' ').Append(response.ReasonPhrase ?? "Status").Append("\r\n");
                foreach (var header in response.Headers) builder.Append(header.Key).Append(": ").Append(string.Join(",", header.Value)).Append("\r\n");
                if (response.Content != null)
                {
                    foreach (var header in response.Content.Headers)
                    {
                        if (string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                        builder.Append(header.Key).Append(": ").Append(string.Join(",", header.Value)).Append("\r\n");
                    }
                }
                builder.Append("Content-Length: ").Append(payload.Length).Append("\r\n");
                builder.Append("Connection: close\r\n\r\n");
                var headBytes = Encoding.ASCII.GetBytes(builder.ToString());
                await stream.WriteAsync(headBytes);
                await stream.WriteAsync(payload);
                await stream.FlushAsync();
            }
            catch (IOException)
            {
                // Client went away.
            }
        }
    }

    private static async Task<string?> ReadHeadAsync(NetworkStream stream)
    {
        var buffer = new List<byte>(1024);
        var one = new byte[1];
        while (buffer.Count < 64 * 1024)
        {
            var n = await stream.ReadAsync(one.AsMemory(0, 1));
            if (n == 0) return null;
            buffer.Add(one[0]);
            var count = buffer.Count;
            if (count >= 4 && buffer[count - 4] == '\r' && buffer[count - 3] == '\n' && buffer[count - 2] == '\r' && buffer[count - 1] == '\n')
            {
                return Encoding.ASCII.GetString(buffer.ToArray(), 0, count - 4);
            }
        }
        return null;
    }
}
