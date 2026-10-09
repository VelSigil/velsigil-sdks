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

/// <summary>File-backed store: one JSON file per product holding the device secret and lease token.</summary>
/// <remarks>
/// Writes are atomic and owner-only (the netstandard2.0 build cannot set permissions and relies on the
/// per-user directory). A corrupt file reads as empty; across processes the last writer wins.
/// </remarks>
public sealed class FileStore : IVelsigilStore
{
    private const int MaxFileBytes = 64 * 1024;

    // Default folder of the SDK under its former name; read-only fallback.
    private const string LegacyDefaultFolderName = "Veltrix";

    // Process-wide, so several instances over one directory cannot interleave read-modify-write.
    private static readonly object FileLock = new object();

    /// <summary>Creates a store rooted at <paramref name="directory"/> (created lazily on first write).</summary>
    /// <exception cref="ArgumentException">The directory is null or empty.</exception>
    public FileStore(string directory)
        : this(directory, null)
    {
    }

    /// <summary>
    /// Creates a store that falls back to <paramref name="legacyDirectory"/> for products without a file yet.
    /// The legacy file is never written; clearing a product's state deletes it.
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

    /// <summary>Read-only legacy directory for products without a file in <see cref="DirectoryPath"/>, or null.</summary>
    public string? LegacyDirectoryPath { get; }

    /// <summary>The default per-user directory (for example <c>%LOCALAPPDATA%\Velsigil</c>), optionally with an app sub-folder.</summary>
    /// <exception cref="InvalidOperationException">The OS reports no per-user data directory.</exception>
    /// <exception cref="ArgumentException"><paramref name="applicationName"/> is not a simple folder name.</exception>
    public static string GetDefaultDirectory(string? applicationName = null) => DefaultDirectory("Velsigil", applicationName);

    /// <summary>Creates a store in <see cref="GetDefaultDirectory"/> that still reads state written by earlier SDK versions.</summary>
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

        // Fall back to the legacy directory until the first write here.
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
