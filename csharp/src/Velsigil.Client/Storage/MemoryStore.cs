using System;
using System.Collections.Generic;

namespace Velsigil.Client.Storage;

/// <summary>In-memory store; state is lost on exit, so prefer <see cref="FileStore"/> for applications.</summary>
public sealed class MemoryStore : IVelsigilStore
{
    private readonly object _gate = new object();
    private readonly Dictionary<string, string> _secrets = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _leases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public string? GetDeviceSecret(string productId) => Get(_secrets, productId);

    /// <inheritdoc />
    public void SetDeviceSecret(string productId, string? deviceSecret) => Set(_secrets, productId, deviceSecret);

    /// <inheritdoc />
    public string? GetLeaseToken(string productId) => Get(_leases, productId);

    /// <inheritdoc />
    public void SetLeaseToken(string productId, string? leaseToken) => Set(_leases, productId, leaseToken);

    private string? Get(Dictionary<string, string> map, string productId)
    {
        if (productId is null) throw new ArgumentNullException(nameof(productId));
        lock (_gate)
        {
            return map.TryGetValue(productId, out var value) ? value : null;
        }
    }

    private void Set(Dictionary<string, string> map, string productId, string? value)
    {
        if (productId is null) throw new ArgumentNullException(nameof(productId));
        lock (_gate)
        {
            if (value is null)
            {
                map.Remove(productId);
            }
            else
            {
                map[productId] = value;
            }
        }
    }
}
