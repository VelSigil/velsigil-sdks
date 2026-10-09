using System;
using System.IO;
using System.Threading;

namespace Velsigil.Client.Internal;

/// <summary>Atomic file replacement shared by the file store and verified downloads.</summary>
internal static class FileUtil
{
    private const int ReplaceAttempts = 5;

    /// <summary>Atomic replace, retrying briefly on transient Windows sharing violations.</summary>
    public static void ReplaceFile(string source, string destination)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
#if NET8_0_OR_GREATER
                File.Move(source, destination, overwrite: true);
#else
                if (File.Exists(destination))
                {
                    File.Replace(source, destination, destinationBackupFileName: null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(source, destination);
                }
#endif
                return;
            }
            catch (Exception ex) when ((ex is IOException || ex is UnauthorizedAccessException) && attempt < ReplaceAttempts)
            {
                Thread.Sleep(15 * attempt);
            }
        }
    }

    /// <summary>Deletes <paramref name="path"/> if it exists; never throws for I/O or permission errors.</summary>
    public static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException)
        {
            // Best effort cleanup.
        }
        catch (UnauthorizedAccessException)
        {
            // Best effort cleanup.
        }
    }
}
