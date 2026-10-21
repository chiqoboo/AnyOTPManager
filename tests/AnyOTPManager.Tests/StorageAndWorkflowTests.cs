using System.Security.Cryptography;
using System.Text;
using AnyOTPManager.Core;
using AnyOTPManager.Windows;

namespace AnyOTPManager.Tests;

public sealed class StorageAndWorkflowTests
{
    [Fact]
    public async Task SpacePaddedProfileImportsChangesPinExportsAndReopens()
    {
        using var folder = new TestFolder();
        var files = Fixtures.Files(folder.Path);
        var registry = Fixtures.Registry(digitField: "6 ");
        try
        {
            File.WriteAllBytes(files.Reg, ProfileWriter.RegistryFile(registry));
            var originalFile = File.ReadAllBytes(files.Reg);
            var originalEnv = registry.Single(v => v.Name == "EnvInfo").Binary!;
            var data = Path.Combine(folder.Path, "vault");
            var now = DateTimeOffset.FromUnixTimeSeconds(OtpEngine.Epoch + 60);
            var expected = OtpEngine.Generate(Fixtures.Seed(), new(60, 6), now);
            using (var manager = new OtpManager(data, new FakeDisks(), new MemoryRegistry(), () => { }))
            {
                await manager.InitializeAsync();
                await Assert.ThrowsAsync<OtpException>(() => manager.ImportAsync("Padded", files.Txt, files.Reg, "000000"));
                Assert.Empty((await manager.ViewAsync(now)).Entries);
                await manager.ImportAsync("Padded", files.Txt, files.Reg, Fixtures.Pin);
                var entry = Assert.Single((await manager.ViewAsync(now)).Entries);
                Assert.Equal(expected, entry.Otp);
                await manager.ChangePinAsync(entry.Id, Defaults.Pin);
                var destination = await manager.ExportAsync(entry.Id, folder.Path);
                var exported = ProfileFiles.ParseRegistry(File.ReadAllBytes(Path.Combine(destination, "otp.reg")));
                try
                {
                    Assert.Equal(originalEnv, exported.Single(v => v.Name == "EnvInfo").Binary);
                    var recovered = OtpEngine.Unlock(exported, Fixtures.Disk, Defaults.Pin);
                    try { Assert.Equal(Fixtures.Seed(), recovered); }
                    finally { CryptographicOperations.ZeroMemory(recovered); }
                    Assert.Throws<OtpException>(() => OtpEngine.Unlock(exported, Fixtures.Disk, Fixtures.Pin));
                }
                finally { SecretBuffers.Clear(exported); }
                Assert.Equal(originalFile, File.ReadAllBytes(files.Reg));
            }
            using var reopened = new OtpManager(data, new FakeDisks(), new MemoryRegistry(), () => { });
            await reopened.InitializeAsync();
            Assert.Equal(expected, Assert.Single((await reopened.ViewAsync(now)).Entries).Otp);
        }
        finally { SecretBuffers.Clear(registry); }
    }

    [Fact]
    public async Task ImportedPlainSharedKeyIsNotExportedAndSourceIsPreserved()
    {
        using var folder = new TestFolder(); var files = Fixtures.Files(folder.Path);
        var values = Fixtures.Registry();
        values.Add(new() { Name = "SharedKey", Kind = OtpRegistryValueKind.Binary, Binary = Fixtures.Seed() });
        File.WriteAllBytes(files.Reg, ProfileWriter.RegistryFile(values));
        var source = File.ReadAllBytes(files.Reg);
        using var manager = new OtpManager(Path.Combine(folder.Path, "vault"), new FakeDisks(), new MemoryRegistry(), () => { });
        await manager.InitializeAsync(); await manager.ImportAsync("A", files.Txt, files.Reg, Fixtures.Pin);
        var id = (await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries[0].Id;
        var destination = await manager.ExportAsync(id, folder.Path);
        var exported = ProfileFiles.ParseRegistry(File.ReadAllBytes(Path.Combine(destination, "otp.reg")));
        Assert.DoesNotContain(exported, v => v.Name.Equals("SharedKey", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(Fixtures.Seed(), OtpEngine.Unlock(exported, Fixtures.Disk, Fixtures.Pin));
        Assert.Equal(source, File.ReadAllBytes(files.Reg));
    }
    [Fact]
    public async Task RepeatedExportsUseDistinctFoldersAndDoNotOverwriteEarlierFiles()
    {
        using var folder = new TestFolder(); var files = Fixtures.Files(folder.Path);
        using var manager = new OtpManager(Path.Combine(folder.Path, "vault"), new FakeDisks(), new MemoryRegistry(), () => { });
        await manager.InitializeAsync(); await manager.ImportAsync("A", files.Txt, files.Reg, Fixtures.Pin);
        var id = (await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries[0].Id;
        var first = await manager.ExportAsync(id, folder.Path);
        var original = File.ReadAllBytes(Path.Combine(first, "otp.reg"));
        await manager.ChangePinAsync(id, Defaults.Pin);
        var second = await manager.ExportAsync(id, folder.Path);
        Assert.NotEqual(first, second);
        Assert.Equal(original, File.ReadAllBytes(Path.Combine(first, "otp.reg")));
        Assert.NotEqual(original, File.ReadAllBytes(Path.Combine(second, "otp.reg")));
    }
    [Fact]
    public void VaultIsProtectedAndReopensWithNoPinPrompt()
    {
        using var folder = new TestFolder();
        var vault = new VaultStore(folder.Path);
        using var entry = Fixtures.Entry();
        vault.Save([entry]);
        var bytes = File.ReadAllBytes(vault.FilePath);
        var text = Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain(entry.Alias, text); Assert.DoesNotContain(Fixtures.Pin, text);
        Assert.False(bytes.AsSpan().IndexOf(entry.Seed) >= 0);
        var loaded = vault.Load();
        try { Assert.Single(loaded); Assert.Equal(entry.Seed, loaded[0].Seed); }
        finally { foreach (var e in loaded) e.Dispose(); }
    }
    [Fact]
    public void PreviousRevisionIsAlsoProtected()
    {
        using var folder = new TestFolder(); var vault = new VaultStore(folder.Path);
        using var a = Fixtures.Entry(); using var b = Fixtures.Entry(1);
        vault.Save([a]); vault.Save([a, b]);
        Assert.True(File.Exists(vault.FilePath + ".previous"));
        var previous = ProtectedFile.Read<VaultDocument>(vault.FilePath + ".previous");
        Assert.Single(previous.Entries);
        foreach (var entry in previous.Entries) entry.Dispose();
    }
    [Fact]
    public void CorruptVaultIsNotSilentlyReplaced()
    {
        using var folder = new TestFolder(); var vault = new VaultStore(folder.Path);
        using var entry = Fixtures.Entry(); vault.Save([entry]);
        var broken = File.ReadAllBytes(vault.FilePath); broken[^5] ^= 0x33; File.WriteAllBytes(vault.FilePath, broken);
        Assert.Throws<OtpException>(() => vault.Load()); Assert.Equal(broken, File.ReadAllBytes(vault.FilePath));
    }
    [Fact]
    public void UnknownSchemaAndMismatchedSeedAreRejected()
    {
        using var folder = new TestFolder(); var vault = new VaultStore(folder.Path);
        ProtectedFile.Write(vault.FilePath, new VaultDocument { Version = 99 });
        Assert.Throws<OtpException>(() => vault.Load());
        using var e = Fixtures.Entry(); e.Seed[0] ^= 1;
        Assert.Throws<OtpException>(() => vault.Save([e]));
    }
    [Fact]
    public async Task FullMultiProfileLifecyclePersistsAcrossRestart()
    {
        using var folder = new TestFolder();
        var sources = Path.Combine(folder.Path, "source");
        var a = Fixtures.Files(sources); var b = Fixtures.Files(sources, 1);
        var sourceA = File.ReadAllBytes(a.Reg);
        var data = Path.Combine(folder.Path, "vault");
        using (var manager = new OtpManager(data, new FakeDisks(), new MemoryRegistry(), () => { }))
        {
            await manager.InitializeAsync();
            await manager.ImportAsync("Personal", a.Txt, a.Reg, Fixtures.Pin);
            await manager.ImportAsync("Work", b.Txt, b.Reg, Fixtures.Pin);
            var view = await manager.ViewAsync(DateTimeOffset.UtcNow); Assert.Equal(2, view.Entries.Count);
            var id = view.Entries.Single(e => e.Alias == "Personal").Id;
            await manager.RenameAsync(id, "Renamed");
            await manager.ChangePinAsync(id, Defaults.Pin);
            var export = await manager.ExportAsync(id, folder.Path);
            var parsed = ProfileFiles.ParseRegistry(File.ReadAllBytes(Path.Combine(export, "otp.reg")));
            var disk = ProfileFiles.ParseDisk(File.ReadAllBytes(Path.Combine(export, "device.txt")));
            Assert.Equal(Fixtures.Seed(), OtpEngine.Unlock(parsed, disk, Defaults.Pin));
            Assert.Throws<OtpException>(() => OtpEngine.Unlock(parsed, disk, Fixtures.Pin));
            Assert.Equal(sourceA, File.ReadAllBytes(a.Reg));
        }
        using var reopened = new OtpManager(data, new FakeDisks(), new MemoryRegistry(), () => { });
        await reopened.InitializeAsync();
        var saved = await reopened.ViewAsync(DateTimeOffset.UtcNow);
        Assert.Equal(2, saved.Entries.Count); Assert.Contains(saved.Entries, e => e.Alias == "Renamed");
        await reopened.DeleteAsync(saved.Entries.Single(e => e.Alias == "Work").Id);
        Assert.Single((await reopened.ViewAsync(DateTimeOffset.UtcNow)).Entries);
    }
    [Fact]
    public async Task WrongPinDuplicateSeedAndDuplicateAliasLeaveVaultUnchanged()
    {
        using var folder = new TestFolder(); var a = Fixtures.Files(folder.Path); var b = Fixtures.Files(folder.Path, 1);
        var data = Path.Combine(folder.Path, "vault");
        using var manager = new OtpManager(data, new FakeDisks(), new MemoryRegistry(), () => { });
        await manager.InitializeAsync();
        await Assert.ThrowsAsync<OtpException>(() => manager.ImportAsync("A", a.Txt, a.Reg, "000000"));
        Assert.False(File.Exists(Path.Combine(data, "profiles.dpapi")));
        await manager.ImportAsync("A", a.Txt, a.Reg, Fixtures.Pin);
        var before = File.ReadAllBytes(Path.Combine(data, "profiles.dpapi"));
        await Assert.ThrowsAsync<OtpException>(() => manager.ImportAsync("B", a.Txt, a.Reg, Fixtures.Pin));
        await Assert.ThrowsAsync<OtpException>(() => manager.ImportAsync("a", b.Txt, b.Reg, Fixtures.Pin));
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(data, "profiles.dpapi")));
    }
    [Fact]
    public async Task ConcurrentImportsDoNotLoseRecords()
    {
        using var folder = new TestFolder();
        var a = Fixtures.Files(folder.Path); var b = Fixtures.Files(folder.Path, 1);
        using var manager = new OtpManager(Path.Combine(folder.Path, "vault"), new FakeDisks(), new MemoryRegistry(), () => { });
        await manager.InitializeAsync();
        await Task.WhenAll(manager.ImportAsync("A", a.Txt, a.Reg, Fixtures.Pin), manager.ImportAsync("B", b.Txt, b.Reg, Fixtures.Pin));
        Assert.Equal(2, (await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries.Count);
    }
    [Fact]
    public async Task CancelledImportDoesNotSave()
    {
        using var folder = new TestFolder(); var files = Fixtures.Files(folder.Path);
        using var manager = new OtpManager(Path.Combine(folder.Path, "vault"), new FakeDisks(), new MemoryRegistry(), () => { });
        await manager.InitializeAsync();
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => manager.ImportAsync("A", files.Txt, files.Reg, Fixtures.Pin, cancelled.Token));
        Assert.Empty((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries);
    }
    [Fact]
    public async Task TransferRebindsToSelectedDiskWithoutChangingSourceProfile()
    {
        using var folder = new TestFolder(); var files = Fixtures.Files(folder.Path);
        var registry = new MemoryRegistry(); var disks = new FakeDisks();
        using var manager = new OtpManager(Path.Combine(folder.Path, "vault"), disks, registry, () => { });
        await manager.InitializeAsync(); await manager.ImportAsync("A", files.Txt, files.Reg, Fixtures.Pin);
        var id = (await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries[0].Id;
        using var plan = await manager.PrepareTransferAsync(id, disks.List()[0], Defaults.Pin);
        await manager.ApplyTransferAsync(plan);
        Assert.Equal(Fixtures.Seed(), OtpEngine.Unlock(registry.State.Values, Fixtures.OtherDisk, Defaults.Pin));
        Assert.Throws<OtpException>(() => OtpEngine.Unlock(registry.State.Values, Fixtures.Disk, Defaults.Pin));
        await manager.RestoreTransferAsync(); Assert.False(registry.State.Exists);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task ChangedDiskOrEntryInvalidatesPreparedTransfer(bool changeDisk)
    {
        using var folder = new TestFolder(); var files = Fixtures.Files(folder.Path);
        var registry = new MemoryRegistry(); var disks = new FakeDisks();
        using var manager = new OtpManager(Path.Combine(folder.Path, "vault"), disks, registry, () => { });
        await manager.InitializeAsync(); await manager.ImportAsync("A", files.Txt, files.Reg, Fixtures.Pin);
        var id = (await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries[0].Id;
        using var plan = await manager.PrepareTransferAsync(id, disks.List()[0], Defaults.Pin);
        if (changeDisk) disks.Identity = Fixtures.Disk; else await manager.ChangePinAsync(id, "517294");
        await Assert.ThrowsAsync<OtpException>(() => manager.ApplyTransferAsync(plan));
        Assert.Equal(0, registry.Writes);
    }
}
