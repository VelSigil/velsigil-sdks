using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Velsigil.Client.Internal;
#if NET8_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace Velsigil.Client;

/// <summary>
/// Hardware id derivation shared by every Velsigil SDK (SPEC 10.6):
/// <c>hwid = lowercase hex SHA-256("vx-hwid-v1:" + machineId)</c> where <c>machineId</c> is trimmed and
/// lowercased. Sources: Windows <c>HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid</c> (64-bit registry
/// view), Linux <c>/etc/machine-id</c> then <c>/var/lib/dbus/machine-id</c> (an empty file or systemd's placeholder
/// <c>uninitialized</c> is skipped), macOS <c>IOPlatformUUID</c>.
/// </summary>
/// <remarks>
/// Hardware ids are spoofable and are not a security boundary on their own; the server pairs them with a
/// per-device secret. The raw machine id never leaves the machine - only its salted hash does.
/// </remarks>
public static class HardwareId
{
    /// <summary>Domain-separation prefix hashed in front of the machine id.</summary>
    public const string Prefix = "vx-hwid-v1:";

    private static readonly object CacheLock = new object();
    private static string? _cached;

    /// <summary>
    /// Returns this machine's hardware id (cached after the first successful read).
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// No machine id is available on this platform (for example a minimal container). Supply
    /// <see cref="VelsigilClientOptions.HardwareId"/> instead.
    /// </exception>
    public static string Get()
    {
        if (TryGet(out var hwid)) return hwid;
        throw new PlatformNotSupportedException(
            "Could not read a machine identifier on this platform. Set VelsigilClientOptions.HardwareId to a stable per-device value.");
    }

    /// <summary>Tries to compute this machine's hardware id without throwing.</summary>
    public static bool TryGet(out string hwid)
    {
        lock (CacheLock)
        {
            if (_cached != null)
            {
                hwid = _cached;
                return true;
            }

            var machineId = ReadMachineId();
            if (machineId != null && NormalizeMachineId(machineId).Length > 0)
            {
                _cached = FromMachineId(machineId);
                hwid = _cached;
                return true;
            }
        }

        hwid = string.Empty;
        return false;
    }

    /// <summary>Normalises a raw machine id: trimmed and lowercased (invariant culture).</summary>
    public static string NormalizeMachineId(string machineId)
    {
        if (machineId is null) throw new ArgumentNullException(nameof(machineId));
        return machineId.Trim().ToLowerInvariant();
    }

    /// <summary>Derives the hardware id from a raw machine id (normalised first).</summary>
    /// <exception cref="ArgumentException">The machine id is empty after normalisation.</exception>
    public static string FromMachineId(string machineId)
    {
        var normalized = NormalizeMachineId(machineId);
        if (normalized.Length == 0) throw new ArgumentException("The machine id is empty.", nameof(machineId));
        return Crypto.Sha256Hex(Prefix + normalized);
    }

    /// <summary>
    /// The hash the server stores for a hardware id (lowercase hex SHA-256 of the hwid string). Offline
    /// leases carry this value as <c>hwidHash</c>.
    /// </summary>
    public static string HashHwid(string hwid)
    {
        if (hwid is null) throw new ArgumentNullException(nameof(hwid));
        return Crypto.Sha256Hex(hwid);
    }

    /// <summary>Reads the raw (un-normalised) platform machine id, or null when unavailable.</summary>
    public static string? ReadMachineId()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return ReadWindowsMachineGuid();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return ReadMacPlatformUuid();
            return ReadLinuxMachineId();
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException
            || ex is InvalidOperationException || ex is PlatformNotSupportedException || ex is System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

#if NET8_0_OR_GREATER
    [SupportedOSPlatform("windows")]
#endif
    private static string? ReadWindowsMachineGuid()
    {
        // Always the 64-bit view so 32-bit and 64-bit processes agree on the same value.
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", writable: false);
        return NonEmpty(key?.GetValue("MachineGuid") as string);
    }

    private static readonly string[] LinuxMachineIdPaths = { "/etc/machine-id", "/var/lib/dbus/machine-id" };

    private static string? ReadLinuxMachineId() => ReadLinuxMachineId(LinuxMachineIdPaths);

    /// <summary>
    /// The first usable machine id among <paramref name="paths"/>. A file that is missing, larger than 4 KiB, empty or
    /// holds systemd's placeholder <c>uninitialized</c> (any case; written before the first boot commits an id, and left
    /// in images systemd never booted, where every copy would share one hwid) is skipped, as in every Velsigil SDK.
    /// </summary>
    internal static string? ReadLinuxMachineId(string[] paths)
    {
        foreach (var path in paths)
        {
            if (!File.Exists(path)) continue;
            var info = new FileInfo(path);
            if (info.Length > 4096) continue;
            var value = NonEmpty(File.ReadAllText(path));
            if (value != null && !string.Equals(NormalizeMachineId(value), "uninitialized", StringComparison.Ordinal)) return value;
        }
        return null;
    }

#if NET8_0_OR_GREATER
    [SupportedOSPlatform("macos")]
#endif
    private static string? ReadMacPlatformUuid()
    {
        // Absolute path, no shell, constant arguments: nothing user-controlled reaches the process.
        const string ioreg = "/usr/sbin/ioreg";
        if (!File.Exists(ioreg)) return null;

        var startInfo = new ProcessStartInfo(ioreg, "-rd1 -c IOPlatformExpertDevice")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(startInfo);
        if (process is null) return null;
        var outputTask = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(5000))
        {
            try
            {
                process.Kill();
            }
            catch (InvalidOperationException)
            {
                // Already exited.
            }
            return null;
        }
        if (!outputTask.Wait(5000)) return null;
        return ParseIoregPlatformUuid(outputTask.Result);
    }

    /// <summary>Extracts the value of <c>"IOPlatformUUID" = "…"</c> from <c>ioreg</c> output.</summary>
    internal static string? ParseIoregPlatformUuid(string output)
    {
        const string marker = "\"IOPlatformUUID\"";
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            var index = line.IndexOf(marker, StringComparison.Ordinal);
            if (index < 0) continue;
            var equals = line.IndexOf('=', index + marker.Length);
            if (equals < 0) continue;
            var open = line.IndexOf('"', equals + 1);
            var close = open < 0 ? -1 : line.IndexOf('"', open + 1);
            if (open < 0 || close <= open + 1) continue;
            return NonEmpty(line.Substring(open + 1, close - open - 1));
        }
        return null;
    }

    private static string? NonEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
