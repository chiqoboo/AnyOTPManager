using System.Security.Cryptography;
using AnyOTPManager.Core;
using AnyOTPManager.Windows;

namespace AnyOTPManager.Tests;

public sealed class LocalImportTests
{
    [Fact]
    public async Task LocalRegistryImportPreservesSourceExportsAndReopens()
    {
        using var folder = new TestFolder();
        var registry = new WindowsRegistryStore(@"Software\AnyOTPManager.Tests\" + Guid.NewGuid().ToString("N"));
        using var source = LocalProfile();
        source.Values.Add(new() { Name = "SharedKey", Kind = OtpRegistryValueKind.Binary, Binary = Fixtures.Seed() });
        registry.Write(source);
        try
        {
            var disks = new FakeDisks();
            var data = Path.Combine(folder.Path, "vault");
            var now = DateTimeOffset.FromUnixTimeSeconds(OtpEngine.Epoch + 60);
            var expected = OtpEngine.Generate(Fixtures.Seed(), new(60, 6), now);
            using (var manager = new OtpManager(data, disks, registry, () => throw new InvalidOperationException("Read-only import must not require vendor shutdown.")))
            {
                await manager.InitializeAsync();
                await manager.ImportFromComputerAsync("Local", disks.List()[0], Fixtures.Pin);
                var entry = Assert.Single((await manager.ViewAsync(now)).Entries);
                Assert.Equal(expected, entry.Otp);
                var output = await manager.ExportAsync(entry.Id, folder.Path);
                Assert.Equal(Fixtures.OtherDisk, ProfileFiles.ParseDisk(File.ReadAllBytes(Path.Combine(output, "device.txt"))));
                var exported = ProfileFiles.ParseRegistry(File.ReadAllBytes(Path.Combine(output, "otp.reg")));
                try
                {
                    Assert.DoesNotContain(exported, v => v.Name.Equals("SharedKey", StringComparison.OrdinalIgnoreCase));
                    Assert.Equal(source.Values.Single(v => v.Name == "EnvInfo").Binary, exported.Single(v => v.Name == "EnvInfo").Binary);
                    var recovered = OtpEngine.Unlock(exported, Fixtures.OtherDisk, Fixtures.Pin);
                    try { Assert.Equal(Fixtures.Seed(), recovered); }
                    finally { CryptographicOperations.ZeroMemory(recovered); }
                }
                finally { SecretBuffers.Clear(exported); }
            }
            using var reopened = new OtpManager(data, disks, registry);
            await reopened.InitializeAsync();
            Assert.Equal(expected, Assert.Single((await reopened.ViewAsync(now)).Entries).Otp);
            using var after = registry.Read();
            Assert.True(RegistrySnapshot.Equal(source, after));
        }
        finally { registry.Write(new() { Exists = false }); }
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task MissingOrEmptyLocalRegistrationDoesNotCreateVault(bool exists)
    {
        using var folder = new TestFolder();
        var registry = new MemoryRegistry { State = new() { Exists = exists } };
        var disks = new FakeDisks();
        using var manager = new OtpManager(folder.Path, disks, registry);
        await manager.InitializeAsync();
        var error = await Assert.ThrowsAsync<OtpException>(() => manager.ImportFromComputerAsync("Local", disks.List()[0], Fixtures.Pin));
        Assert.Contains("AnyOTP kaydı bulunamadı", error.Message);
        Assert.False(File.Exists(Path.Combine(folder.Path, "profiles.dpapi")));
        Assert.Empty((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries);
        Assert.Equal(0, registry.Writes);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task WrongPinOrDiskLeavesExistingVaultAndSourceUnchanged(bool wrongDisk)
    {
        using var folder = new TestFolder();
        using var source = LocalProfile();
        var registry = new MemoryRegistry { State = source };
        var disks = new FakeDisks { Identity = wrongDisk ? Fixtures.Disk : Fixtures.OtherDisk };
        using var before = source.Clone();
        using var manager = new OtpManager(folder.Path, disks, registry);
        await manager.InitializeAsync();
        var files = Fixtures.Files(folder.Path, 1);
        await manager.ImportAsync("Existing", files.Txt, files.Reg, Fixtures.Pin);
        var vaultBefore = File.ReadAllBytes(Path.Combine(folder.Path, "profiles.dpapi"));
        await Assert.ThrowsAsync<OtpException>(() => manager.ImportFromComputerAsync("Local", disks.List()[0], wrongDisk ? Fixtures.Pin : "000000"));
        Assert.Equal(vaultBefore, File.ReadAllBytes(Path.Combine(folder.Path, "profiles.dpapi")));
        Assert.Single((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries);
        Assert.True(RegistrySnapshot.Equal(before, source));
        Assert.Equal(0, registry.Writes);
    }

    [Theory]
    [InlineData("EnvInfo")] [InlineData("VMData")]
    public async Task IncompleteLocalRegistrationIsRejected(string missingValue)
    {
        using var folder = new TestFolder();
        using var source = LocalProfile();
        var missing = source.Values.Single(v => v.Name == missingValue);
        source.Values.Remove(missing); SecretBuffers.Clear([missing]);
        var registry = new MemoryRegistry { State = source };
        var disks = new FakeDisks();
        using var manager = new OtpManager(folder.Path, disks, registry);
        await manager.InitializeAsync();
        await Assert.ThrowsAsync<OtpException>(() => manager.ImportFromComputerAsync("Local", disks.List()[0], Fixtures.Pin));
        Assert.False(File.Exists(Path.Combine(folder.Path, "profiles.dpapi")));
        Assert.Equal(0, registry.Writes);
    }

    [Fact]
    public async Task DuplicateLocalSeedAndAliasLeaveVaultUnchanged()
    {
        using var folder = new TestFolder();
        using var source = LocalProfile();
        var registry = new MemoryRegistry { State = source };
        var disks = new FakeDisks();
        using var manager = new OtpManager(folder.Path, disks, registry);
        await manager.InitializeAsync();
        var files = Fixtures.Files(folder.Path);
        await manager.ImportAsync("Existing", files.Txt, files.Reg, Fixtures.Pin);
        var vaultBefore = File.ReadAllBytes(Path.Combine(folder.Path, "profiles.dpapi"));
        var sameSeed = await Assert.ThrowsAsync<OtpException>(() => manager.ImportFromComputerAsync("Local", disks.List()[0], Fixtures.Pin));
        Assert.Contains("Bu OTP zaten listede", sameSeed.Message);
        var sameAlias = await Assert.ThrowsAsync<OtpException>(() => manager.ImportFromComputerAsync("existing", disks.List()[0], Fixtures.Pin));
        Assert.Contains("Bu kayıt adı zaten kullanılıyor", sameAlias.Message);
        Assert.Equal(vaultBefore, File.ReadAllBytes(Path.Combine(folder.Path, "profiles.dpapi")));
        Assert.Equal(0, registry.Writes);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task CancellationBeforeOrDuringDiskReadDoesNotSave(bool cancelDuringRead)
    {
        using var folder = new TestFolder();
        using var source = LocalProfile();
        var registry = new MemoryRegistry { State = source };
        using var cancellation = new CancellationTokenSource();
        var disks = new InterruptibleDisks(() => cancellation.Cancel());
        using var manager = new OtpManager(folder.Path, disks, registry);
        await manager.InitializeAsync();
        if (!cancelDuringRead) cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => manager.ImportFromComputerAsync("Local", disks.List()[0], Fixtures.Pin, cancellation.Token));
        Assert.False(File.Exists(Path.Combine(folder.Path, "profiles.dpapi")));
        Assert.Empty((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries);
        Assert.Equal(0, registry.Writes);
    }

    [Fact]
    public async Task RemovedDiskDoesNotSave()
    {
        using var folder = new TestFolder();
        using var source = LocalProfile();
        var registry = new MemoryRegistry { State = source };
        var disks = new InterruptibleDisks(() => throw new OtpException("Seçilen disk artık bağlı değil."));
        using var manager = new OtpManager(folder.Path, disks, registry);
        await manager.InitializeAsync();
        await Assert.ThrowsAsync<OtpException>(() => manager.ImportFromComputerAsync("Local", disks.List()[0], Fixtures.Pin));
        Assert.False(File.Exists(Path.Combine(folder.Path, "profiles.dpapi")));
        Assert.Equal(0, registry.Writes);
    }

    private static RegistrySnapshot LocalProfile() => new()
    {
        Exists = true,
        Values = Fixtures.Registry(disk: Fixtures.OtherDisk, digitField: "6 ")
    };

    private sealed class InterruptibleDisks(Action onRead) : IDiskSource
    {
        public IReadOnlyList<DiskChoice> List() => [new(0, "Synthetic disk")];
        public DiskIdentity Read(int index) { onRead(); return Fixtures.OtherDisk; }
    }
}
