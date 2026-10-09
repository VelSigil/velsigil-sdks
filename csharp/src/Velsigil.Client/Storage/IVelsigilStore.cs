namespace Velsigil.Client.Storage;

/// <summary>Per-product store for the device secret and offline lease token; must be thread-safe.</summary>
/// <remarks>
/// The device secret is a credential: keep it readable only by the current OS user.
/// Exceptions are caught and reported through <see cref="VelsigilClientOptions.StoreErrorHandler"/>.
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
