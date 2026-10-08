namespace Velsigil.Client.Storage;

/// <summary>
/// Persistence for per-product client state: the device secret issued by the server and the latest
/// offline lease token. Implementations must be thread-safe; the client may call them concurrently.
/// </summary>
/// <remarks>
/// The device secret is a credential that proves this device's identity to the server. Store it where
/// only the current OS user can read it (the built-in <see cref="FileStore"/> does this), or wrap it with
/// DPAPI / Keychain / libsecret in a custom implementation. Methods should not throw for a missing
/// entry; exceptions thrown by an implementation are caught by the client and reported through
/// <see cref="VelsigilClientOptions.StoreErrorHandler"/>.
/// </remarks>
public interface IVelsigilStore
{
    /// <summary>Returns the stored device secret for <paramref name="productId"/>, or null.</summary>
    string? GetDeviceSecret(string productId);

    /// <summary>Stores the device secret for <paramref name="productId"/>; null removes it.</summary>
    void SetDeviceSecret(string productId, string? deviceSecret);

    /// <summary>Returns the stored offline lease token for <paramref name="productId"/>, or null.</summary>
    string? GetLeaseToken(string productId);

    /// <summary>Stores the offline lease token for <paramref name="productId"/>; null removes it.</summary>
    void SetLeaseToken(string productId, string? leaseToken);
}
