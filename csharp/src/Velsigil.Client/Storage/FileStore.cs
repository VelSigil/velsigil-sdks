using System;
using System.IO;
using System.Text.Json;
using Velsigil.Client.Internal;
#if NET8_0_OR_GREATER
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
#endif

namespace Velsigil.Client.Storage;

/// <summary>
/// File-backed <see cref="IVelsigilStore"/>: one small JSON file per product
/// (<c>&lt;directory&gt;/&lt;productId&gt;.json</c>) holding the device secret and the latest lease token.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Writes are atomic: data goes to a uniquely named temporary file in the same directory, is flushed
/// to disk, then renamed over the target, so a crash never leaves a torn file.</item>
/// <item>Permissions (net8.0 build): on Windows the directory (when created by the store) and every file
/// get a protected ACL granting access to the current user only; on Linux/macOS the directory is created
/// with mode 0700 and files with 0600. The netstandard2.0 build (.NET Framework, Unity) cannot set
/// permissions and relies on the per-user location of the directory.</item>
/// <item>Thread-safe within a process. Across processes, the last writer wins; files are never torn.</item>
/// <item>A corrupt or oversized file is treated as empty and replaced on the next write.</item>
/// <item>With a legacy directory (the default store has one), a product whose file does not exist yet is
/// read from the legacy directory instead; the next write goes to <see cref="DirectoryPath"/>.</item>
/// </list>
/// </remarks>
public sealed class FileStore : IVelsigilStore
{
    private const int MaxFileBytes = 64 * 1024;

    // Default folder name used by SDK versions released under the former product name (Veltrix). Read-only
    // fallback so an installed app keeps its device secret and offline lease after updating the SDK.
    private const string LegacyDefaultFolderName = "Veltrix";

    // Process-wide so that several FileStore instances over the same directory cannot interleave a
    // read-modify-write cycle.
    private static readonly object FileLock = new object();

    /// <summary>Creates a store rooted at <paramref name="directory"/> (created lazily on first write).</summary>
    /// <exception cref="ArgumentException">The directory is null or empty.</exception>
    public FileStore(string directory)
        : this(directory, null)
    {
    }

    /// <summary>
    /// Creates a store rooted at <paramref name="directory"/> that migrates state from
    /// <paramref name="legacyDirectory"/>: when a product has no file in <paramref name="directory"/> yet, its
    /// file in <paramref name="legacyDirectory"/> is read instead, and the next write goes to
    /// <paramref name="directory"/>. Use it when you move the store so the device keeps its device secret and
    /// offline lease. The legacy file is never written; it is deleted only when the product's state is cleared
    /// (for example after a deactivation), so the cleared state cannot reappear.
    /// </summary>
    /// <exception cref="ArgumentException">The directory is null or empty.</exception>
    public FileStore(string directory, string? legacyDirectory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("A directory is required.", nameof(directory));
        }
        DirectoryPath = Path.GetFullPath(directory);
        if (!string.IsNullOrWhiteSpace(legacyDirectory))
        {
            var legacy = Path.GetFullPath(legacyDirectory);
            if (!string.Equals(legacy, DirectoryPath, StringComparison.Ordinal)) LegacyDirectoryPath = legacy;
        }
    }

    /// <summary>Absolute path of the directory holding the state files.</summary>
    public string DirectoryPath { get; }

    /// <summary>
    /// Absolute path of the read-only legacy directory consulted for products without a file in
    /// <see cref="DirectoryPath"/>, or null. <see cref="CreateDefault"/> sets it to the default directory of
    /// earlier SDK versions.
    /// </summary>
    public string? LegacyDirectoryPath { get; }

    /// <summary>
    /// The default per-user directory: <c>%LOCALAPPDATA%\Velsigil</c> on Windows, <c>~/.local/share/Velsigil</c>
    /// on Linux (XDG data home), the per-user application-support folder on macOS; optionally with an
    /// <paramref name="applicationName"/> sub-folder.
    /// </summary>
    /// <exception cref="InvalidOperationException">The OS reports no per-user data directory.</exception>
    /// <exception cref="ArgumentException"><paramref name="applicationName"/> is not a simple folder name.</exception>
    public static string GetDefaultDirectory(string? applicationName = null) => DefaultDirectory("Velsigil", applicationName);

    /// <summary>
    /// Creates a store in <see cref="GetDefaultDirectory"/>. State written by earlier SDK versions in their
    /// default directory (<c>%LOCALAPPDATA%\Veltrix</c>, <c>~/.local/share/Veltrix</c>, ... with the same
    /// <paramref name="applicationName"/>) is still read until the product's first write (see
    /// <see cref="LegacyDirectoryPath"/>).
    /// </summary>
    /// <exception cref="InvalidOperationException">The OS reports no per-user data directory.</exception>
    /// <exception cref="ArgumentException"><paramref name="applicationName"/> is not a simple folder name.</exception>
    public static FileStore CreateDefault(string? applicationName = null) =>
        new FileStore(GetDefaultDirectory(applicationName), DefaultDirectory(LegacyDefaultFolderName, applicationName));

    private static string DefaultDirectory(string folderName, string? applicationName)
    {
        var baseDirectory = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        if (string.IsNullOrEmpty(baseDirectory))
        {
            throw new InvalidOperationException("No per-user application data directory is available; pass an explicit directory to FileStore.");
        }

        var directory = Path.Combine(baseDirectory, folderName);
        if (applicationName != null)
        {
            ValidateFolderName(applicationName, nameof(applicationName));
            directory = Path.Combine(directory, applicationName);
        }
        return directory;
    }

    /// <summary>Path of the state file used for <paramref name="productId"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="productId"/> is not a UUID.</exception>
    public string GetFilePath(string productId) => Path.Combine(DirectoryPath, NormalizeProductId(productId) + ".json");

    /// <inheritdoc />
    public string? GetDeviceSecret(string productId)
    {
        lock (FileLock)
        {
            return Load(productId).DeviceSecret;
        }
    }

    /// <inheritdoc />
    public void SetDeviceSecret(string productId, string? deviceSecret)
    {
        lock (FileLock)
        {
            var state = Load(productId);
            if (string.Equals(state.DeviceSecret, deviceSecret, StringComparison.Ordinal)) return;
            state.DeviceSecret = deviceSecret;
            Save(productId, state);
        }
    }

    /// <inheritdoc />
    public string? GetLeaseToken(string productId)
    {
        lock (FileLock)
        {
            return Load(productId).LeaseToken;
        }
    }

    /// <inheritdoc />
    public void SetLeaseToken(string productId, string? leaseToken)
    {
        lock (FileLock)
        {
            var state = Load(productId);
            if (string.Equals(state.LeaseToken, leaseToken, StringComparison.Ordinal)) return;
            state.LeaseToken = leaseToken;
            Save(productId, state);
        }
    }

    private sealed class State
    {
        public string? DeviceSecret;
        public string? LeaseToken;
    }

    private string? GetLegacyFilePath(string productId) =>
        LegacyDirectoryPath is null ? null : Path.Combine(LegacyDirectoryPath, NormalizeProductId(productId) + ".json");

    private State Load(string productId)
    {
        var state = ReadFile(GetFilePath(productId));
        if (state != null) return state;

        // Migration: no file here yet, so use what an earlier SDK version stored in the legacy directory.
        // The next write goes to DirectoryPath; from then on the legacy file is no longer read.
        var legacyPath = GetLegacyFilePath(productId);
        return (legacyPath is null ? null : ReadFile(legacyPath)) ?? new State();
    }

    /// <summary>Reads one state file; null when it does not exist, empty state when it is unreadable.</summary>
    private static State? ReadFile(string path)
    {
        byte[] bytes;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > MaxFileBytes) return new State();
            bytes = new byte[stream.Length];
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = stream.Read(bytes, offset, bytes.Length - offset);
                if (read == 0) break;
                offset += read;
            }
            if (offset != bytes.Length) return new State();
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }

        try
        {
            if (!JsonRead.TryParse(bytes, out var document) || document is null) return new State();
            using (document)
            {
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) return new State();
                if (!JsonRead.TryGetOptionalString(root, "deviceSecret", out var secret)
                    || !JsonRead.TryGetOptionalString(root, "leaseToken", out var lease))
                {
                    return new State();
                }
                return new State { DeviceSecret = secret, LeaseToken = lease };
            }
        }
        finally
        {
            Array.Clear(bytes, 0, bytes.Length);
        }
    }

    private void Save(string productId, State state)
    {
        var path = GetFilePath(productId);
        if (state.DeviceSecret is null && state.LeaseToken is null)
        {
            if (File.Exists(path)) File.Delete(path);
            // A cleared state must not come back from the legacy fallback on the next read.
            var legacyPath = GetLegacyFilePath(productId);
            if (legacyPath != null && File.Exists(legacyPath)) File.Delete(legacyPath);
            return;
        }

        EnsureDirectory();
        var json = Serialize(state);
        var temp = Path.Combine(DirectoryPath, "." + Path.GetFileName(path) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = CreateRestrictedFile(temp))
            {
                stream.Write(json, 0, json.Length);
                stream.Flush(flushToDisk: true);
            }
            FileUtil.ReplaceFile(temp, path);
        }
        finally
        {
            Array.Clear(json, 0, json.Length);
            FileUtil.TryDelete(temp);
        }
    }

    private static byte[] Serialize(State state)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("v", 1);
            if (state.DeviceSecret != null) writer.WriteString("deviceSecret", state.DeviceSecret);
            if (state.LeaseToken != null) writer.WriteString("leaseToken", state.LeaseToken);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    private void EnsureDirectory()
    {
        if (Directory.Exists(DirectoryPath)) return;
#if NET8_0_OR_GREATER
        if (OperatingSystem.IsWindows())
        {
            CreateWindowsDirectory(DirectoryPath);
            return;
        }
        Directory.CreateDirectory(DirectoryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
#else
        Directory.CreateDirectory(DirectoryPath);
#endif
    }

    private static FileStream CreateRestrictedFile(string path)
    {
#if NET8_0_OR_GREATER
        if (OperatingSystem.IsWindows()) return CreateWindowsFile(path);
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        });
#else
        return new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
#endif
    }

#if NET8_0_OR_GREATER
    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier CurrentUserSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User ?? throw new InvalidOperationException("Cannot determine the current Windows user.");
    }

    [SupportedOSPlatform("windows")]
    private static void CreateWindowsDirectory(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            CurrentUserSid(),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.CreateDirectory(path);
    }

    [SupportedOSPlatform("windows")]
    private static FileStream CreateWindowsFile(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(CurrentUserSid(), FileSystemRights.FullControl, AccessControlType.Allow));
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security);
    }
#endif

    private static string NormalizeProductId(string productId)
    {
        if (productId is null || !Guid.TryParseExact(productId.Trim(), "D", out var id))
        {
            throw new ArgumentException("The product id must be a UUID.", nameof(productId));
        }
        return id.ToString("D");
    }

    private static void ValidateFolderName(string name, string parameterName)
    {
        var valid = name.Length > 0 && name.Length <= 64 && name != "." && name != "..";
        foreach (var c in name)
        {
            var allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == ' ';
            if (!allowed) valid = false;
        }
        if (!valid)
        {
            throw new ArgumentException("The application name may only contain letters, digits, '.', '_', '-' and spaces.", parameterName);
        }
    }
}
