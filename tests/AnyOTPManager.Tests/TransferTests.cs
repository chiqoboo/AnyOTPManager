using AnyOTPManager.Core;
using AnyOTPManager.Windows;

namespace AnyOTPManager.Tests;

public sealed class TransferTests
{
    private static RegistrySnapshot Target(int index = 0) => new() { Exists = true, Values = Fixtures.Registry(index) };

    [Fact]
    public void RealWindowsRegistryRoundTripInIsolatedTestKey()
    {
        var path = @"Software\AnyOTPManager.Tests\" + Guid.NewGuid().ToString("N");
        var store = new WindowsRegistryStore(path);
        try
        {
            using var empty = store.Read(); Assert.False(empty.Exists);
            using var target = Target(); store.Write(target);
            using var observed = store.Read(); Assert.True(RegistrySnapshot.Equal(target, observed));
            store.Write(empty); using var removed = store.Read(); Assert.False(removed.Exists);
        }
        finally { store.Write(new()); }
    }
    [Fact]
    public void TransferAndExplicitUndoRestoreExactPreviousValues()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry { State = Target(1) };
        using var before = store.Read(); using var after = Target();
        var transfer = new RegistryTransfer(store, folder.Path);
        transfer.Apply(before, after);
        Assert.True(RegistrySnapshot.Equal(after, store.State)); Assert.True(transfer.CanRestore); Assert.False(transfer.HasPending);
        transfer.Restore(); Assert.True(RegistrySnapshot.Equal(before, store.State)); Assert.False(transfer.CanRestore);
    }
    [Fact]
    public void PartialFailureRollsBackAndIsNotRetried()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry { State = Target(1), FailOnWrite = 1 };
        using var before = store.Read(); using var after = Target(); var transfer = new RegistryTransfer(store, folder.Path);
        Assert.Throws<OtpException>(() => transfer.Apply(before, after));
        Assert.Equal(2, store.Writes); Assert.True(RegistrySnapshot.Equal(before, store.State)); Assert.False(transfer.HasPending);
    }
    [Fact]
    public void FailedRollbackRemainsVisibleAndCanBeRecovered()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry { State = Target(1), FailAllWrites = true };
        using var before = store.Read(); using var after = Target(); var transfer = new RegistryTransfer(store, folder.Path);
        Assert.Throws<OtpException>(() => transfer.Apply(before, after)); Assert.True(transfer.HasPending);
        var writes = store.Writes;
        Assert.Throws<OtpException>(() => transfer.Apply(before, after)); Assert.Equal(writes, store.Writes);
        store.FailAllWrites = false; transfer.Restore(); Assert.True(RegistrySnapshot.Equal(before, store.State)); Assert.False(transfer.HasPending);
    }
    [Fact]
    public void ExternalChangeBlocksPreparedTransferAndUndo()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry();
        using var before = store.Read(); using var target = Target();
        var transfer = new RegistryTransfer(store, folder.Path);
        store.State = Target(1);
        Assert.Throws<OtpException>(() => transfer.Apply(before, target)); Assert.Equal(0, store.Writes);
        using var expected = store.Read(); transfer.Apply(expected, target);
        store.State = Target(2); var writes = store.Writes;
        Assert.Throws<OtpException>(() => transfer.Restore()); Assert.Equal(writes, store.Writes);
    }
    [Fact]
    public void CrashJournalAllowsExplicitRecoveryAfterRestart()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry { State = Target() };
        using var before = Target(1); using var after = store.Read();
        ProtectedFile.Write(Path.Combine(folder.Path, "pending-transfer.dpapi"), new TransferJournal { Before = before, After = after });
        var reopened = new RegistryTransfer(store, folder.Path); Assert.True(reopened.HasPending);
        reopened.Restore(); Assert.True(RegistrySnapshot.Equal(before, store.State));
    }
    [Fact]
    public void CancellationBeforeMutationDoesNotWriteRegistry()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry(); var transfer = new RegistryTransfer(store, folder.Path);
        using var token = new CancellationTokenSource(); token.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => transfer.Apply(new(), Target(), token.Token));
        Assert.Equal(0, store.Writes); Assert.False(transfer.HasPending);
    }
    [Fact]
    public void ReadbackFailureCannotBeReportedAsSuccess()
    {
        using var folder = new TestFolder(); var store = new MemoryRegistry { State = Target(1), CorruptReadAfterWrite = true };
        using var before = store.Read(); var transfer = new RegistryTransfer(store, folder.Path);
        Assert.Throws<OtpException>(() => transfer.Apply(before, Target()));
        Assert.True(RegistrySnapshot.Equal(before, store.State));
    }
}
