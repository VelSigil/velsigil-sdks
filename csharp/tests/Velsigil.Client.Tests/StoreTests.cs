using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Tasks;
using Velsigil.Client.Storage;
using Velsigil.Client.Tests.Infrastructure;
using Xunit;

namespace Velsigil.Client.Tests;

public class StoreTests
{
    private const string OtherProduct = "7c3e9a10-1b2c-4d5e-8f90-a1b2c3d4e5f6";

    [Fact]
    public void Memory_store_round_trip_and_removal()
    {
        var store = new MemoryStore();
        store.SetDeviceSecret(Vectors.ProductId, "secret-a");
        store.SetLeaseToken(Vectors.ProductId, "lease-a");
        store.SetDeviceSecret(OtherProduct, "secret-b");

        Assert.Equal("secret-a", store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal("lease-a", store.GetLeaseToken(Vectors.ProductId));
        Assert.Equal("secret-b", store.GetDeviceSecret(OtherProduct));
        Assert.Null(store.GetLeaseToken(OtherProduct));

        store.SetDeviceSecret(Vectors.ProductId, null);
        store.SetLeaseToken(Vectors.ProductId, null);
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
    }

    [Fact]
    public void File_store_persists_per_product_across_instances()
    {
        var directory = Path.Combine(TestClients.TempDirectory(), "nested", "state");
        var store = new FileStore(directory);
        store.SetDeviceSecret(Vectors.ProductId, "secret-a");
        store.SetLeaseToken(Vectors.ProductId, "lease-a");
        store.SetDeviceSecret(OtherProduct, "secret-b");

        var reopened = new FileStore(directory);
        Assert.Equal("secret-a", reopened.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal("lease-a", reopened.GetLeaseToken(Vectors.ProductId));
        Assert.Equal("secret-b", reopened.GetDeviceSecret(OtherProduct));
        Assert.Null(reopened.GetLeaseToken(OtherProduct));

        // One JSON file per product, no temporary files left behind.
        var files = Directory.GetFiles(directory).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { Vectors.ProductId + ".json", OtherProduct + ".json" }.OrderBy(n => n, StringComparer.Ordinal), files);
        using var json = JsonDocument.Parse(File.ReadAllBytes(reopened.GetFilePath(Vectors.ProductId)));
        Assert.Equal(1, json.RootElement.GetProperty("v").GetInt32());
        Assert.Equal("secret-a", json.RootElement.GetProperty("deviceSecret").GetString());
    }

    [Fact]
    public void File_store_deletes_the_file_when_everything_is_cleared()
    {
        var store = new FileStore(TestClients.TempDirectory());
        store.SetDeviceSecret(Vectors.ProductId, "secret");
        store.SetLeaseToken(Vectors.ProductId, "lease");
        var path = store.GetFilePath(Vectors.ProductId);
        Assert.True(File.Exists(path));

        store.SetLeaseToken(Vectors.ProductId, null);
        Assert.True(File.Exists(path));
        store.SetDeviceSecret(Vectors.ProductId, null);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void File_store_tolerates_a_corrupt_file()
    {
        var store = new FileStore(TestClients.TempDirectory());
        store.SetDeviceSecret(Vectors.ProductId, "secret");
        File.WriteAllText(store.GetFilePath(Vectors.ProductId), "{ not json");

        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        store.SetLeaseToken(Vectors.ProductId, "lease");
        Assert.Equal("lease", store.GetLeaseToken(Vectors.ProductId));
    }

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("not-a-uuid")]
    [InlineData("")]
    public void File_store_rejects_non_uuid_product_ids(string productId)
    {
        var store = new FileStore(TestClients.TempDirectory());
        Assert.Throws<ArgumentException>(() => store.SetDeviceSecret(productId, "x"));
        Assert.Throws<ArgumentException>(() => store.GetLeaseToken(productId));
    }

    [Theory]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    public void Default_directory_rejects_unsafe_application_names(string name)
    {
        Assert.Throws<ArgumentException>(() => FileStore.GetDefaultDirectory(name));
    }

    [Fact]
    public void Default_directory_is_per_user()
    {
        var directory = FileStore.GetDefaultDirectory("MyApp");
        Assert.EndsWith(Path.Combine("Velsigil", "MyApp"), directory, StringComparison.Ordinal);
        Assert.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify), directory, StringComparison.Ordinal);
    }

    [Fact]
    public void Default_store_falls_back_to_the_pre_rename_directory()
    {
        // Pre-rename SDK versions stored state in <LocalApplicationData>/Veltrix.
        var store = FileStore.CreateDefault("MyApp");
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        Assert.Equal(Path.GetFullPath(FileStore.GetDefaultDirectory("MyApp")), store.DirectoryPath);
        Assert.Equal(Path.GetFullPath(Path.Combine(localAppData, "Veltrix", "MyApp")), store.LegacyDirectoryPath);
        Assert.Null(new FileStore(TestClients.TempDirectory()).LegacyDirectoryPath);
    }

    [Fact]
    public void File_store_reads_the_legacy_directory_until_the_first_write()
    {
        var root = TestClients.TempDirectory();
        var legacyDirectory = Path.Combine(root, "Veltrix", "MyApp");
        var directory = Path.Combine(root, "Velsigil", "MyApp");
        var legacy = new FileStore(legacyDirectory);
        legacy.SetDeviceSecret(Vectors.ProductId, "legacy-secret");
        legacy.SetLeaseToken(Vectors.ProductId, "legacy-lease");
        var legacyBytes = File.ReadAllBytes(legacy.GetFilePath(Vectors.ProductId));

        // An updated app keeps its device secret and offline lease without writing anything.
        var store = new FileStore(directory, legacyDirectory);
        Assert.Equal("legacy-secret", store.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal("legacy-lease", store.GetLeaseToken(Vectors.ProductId));
        Assert.Null(store.GetDeviceSecret(OtherProduct));
        Assert.False(Directory.Exists(directory));

        // The next write migrates the whole state to the new directory; the legacy file is left untouched.
        store.SetLeaseToken(Vectors.ProductId, "new-lease");
        Assert.True(File.Exists(store.GetFilePath(Vectors.ProductId)));
        Assert.Equal(legacyBytes, File.ReadAllBytes(legacy.GetFilePath(Vectors.ProductId)));
        var reopened = new FileStore(directory);
        Assert.Equal("legacy-secret", reopened.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal("new-lease", reopened.GetLeaseToken(Vectors.ProductId));

        // From then on the new file wins over the legacy one.
        store.SetDeviceSecret(Vectors.ProductId, "new-secret");
        var again = new FileStore(directory, legacyDirectory);
        Assert.Equal("new-secret", again.GetDeviceSecret(Vectors.ProductId));
        Assert.Equal("new-lease", again.GetLeaseToken(Vectors.ProductId));
    }

    [Fact]
    public void File_store_clearing_migrated_state_also_removes_the_legacy_file()
    {
        var root = TestClients.TempDirectory();
        var legacyDirectory = Path.Combine(root, "legacy");
        var legacy = new FileStore(legacyDirectory);
        legacy.SetDeviceSecret(Vectors.ProductId, "legacy-secret");
        legacy.SetLeaseToken(Vectors.ProductId, "legacy-lease");

        var store = new FileStore(Path.Combine(root, "current"), legacyDirectory);
        store.SetLeaseToken(Vectors.ProductId, null);
        store.SetDeviceSecret(Vectors.ProductId, null);

        // A deactivated device must not get its old secret and lease back from the legacy fallback.
        Assert.False(File.Exists(store.GetFilePath(Vectors.ProductId)));
        Assert.False(File.Exists(legacy.GetFilePath(Vectors.ProductId)));
        Assert.Null(store.GetDeviceSecret(Vectors.ProductId));
        Assert.Null(store.GetLeaseToken(Vectors.ProductId));
    }

    [Fact]
    public async Task File_store_is_safe_under_concurrent_writes()
    {
        var directory = TestClients.TempDirectory();
        var store = new FileStore(directory);

        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
        {
            if (i % 2 == 0)
            {
                store.SetDeviceSecret(Vectors.ProductId, "secret-" + i);
            }
            else
            {
                new FileStore(directory).SetLeaseToken(Vectors.ProductId, "lease-" + i);
            }
        })));

        Assert.StartsWith("secret-", store.GetDeviceSecret(Vectors.ProductId), StringComparison.Ordinal);
        Assert.StartsWith("lease-", store.GetLeaseToken(Vectors.ProductId), StringComparison.Ordinal);
        Assert.Single(Directory.GetFiles(directory));
    }

    [Fact]
    public void File_store_files_are_private_to_the_current_user()
    {
        var directory = Path.Combine(TestClients.TempDirectory(), "private");
        var store = new FileStore(directory);
        store.SetDeviceSecret(Vectors.ProductId, "secret");
        var path = store.GetFilePath(Vectors.ProductId);

#if VELSIGIL_NETSTANDARD
        // The netstandard2.0 build cannot set ACLs / unix modes; it relies on the per-user directory.
        Assert.True(File.Exists(path));
#else
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsOwnerOnly(path, directory);
        }
        else
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(directory));
        }
#endif
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsOwnerOnly(string path, string directory)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User;

        var fileSecurity = new FileInfo(path).GetAccessControl();
        Assert.True(fileSecurity.AreAccessRulesProtected);
        var fileRules = fileSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
        Assert.Single(fileRules);
        Assert.Equal(user, fileRules[0].IdentityReference);
        Assert.Equal(AccessControlType.Allow, fileRules[0].AccessControlType);

        var directorySecurity = new DirectoryInfo(directory).GetAccessControl();
        Assert.True(directorySecurity.AreAccessRulesProtected);
        foreach (FileSystemAccessRule rule in directorySecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            Assert.Equal(user, rule.IdentityReference);
        }
    }
}
