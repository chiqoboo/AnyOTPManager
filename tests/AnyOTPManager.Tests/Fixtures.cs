using System.Security.Cryptography;
using System.Text;
using AnyOTPManager.Core;
using AnyOTPManager.Windows;

namespace AnyOTPManager.Tests;

internal static class Fixtures
{
    public static DiskIdentity Disk => new("SYNTHETIC\\DISK-IDENTITY-00000001", 0);
    public static DiskIdentity OtherDisk => new("SYNTHETIC\\DISK-IDENTITY-00000002", 0xABCD1234);
    public static byte[] Seed(int index = 0) => SHA1.HashData(Encoding.ASCII.GetBytes("AnyOTPManager fictional fixture " + index));
    public const string Pin = "482619";
    public static List<OtpRegistryValue> Registry(int index = 0, char step = '0', int digits = 6, DiskIdentity? disk = null, string? pin = null, string? digitField = null)
    {
        var env = Encoding.ASCII.GetBytes("FICTIONAL00000000000000000");
        Array.Resize(ref env, 26);
        env[12] = (byte)step; env[14] = (byte)'0'; env[15] = (byte)('0' + digits);
        if (digitField is not null) Encoding.ASCII.GetBytes(digitField).CopyTo(env, 14);
        var source = new List<OtpRegistryValue>
        {
            new() { Name = "EnvInfo", Kind = OtpRegistryValueKind.Binary, Binary = env },
            new() { Name = "VMData", Kind = OtpRegistryValueKind.Binary, Binary = new byte[48] },
            new() { Name = "Label", Kind = OtpRegistryValueKind.String, Text = "Synthetic only" },
            new() { Name = "Flags", Kind = OtpRegistryValueKind.Dword, Dword = 0xAABBCCDD }
        };
        var seed = Seed(index);
        try { return OtpEngine.Rewrap(seed, source, disk ?? Disk, pin ?? Pin); }
        finally { CryptographicOperations.ZeroMemory(seed); SecretBuffers.Clear(source); }
    }
    public static SavedEntry Entry(int index = 0) => new() { Alias = "Fixture " + index, Seed = Seed(index), Pin = Pin, Disk = Disk, Registry = Registry(index) };
    public static (string Txt, string Reg) Files(string directory, int index = 0)
    {
        Directory.CreateDirectory(directory);
        var txt = Path.Combine(directory, $"fixture-{index}.txt"); var reg = Path.Combine(directory, $"fixture-{index}.reg");
        File.WriteAllBytes(txt, ProfileWriter.DiskFile(Disk));
        var values = Registry(index);
        try { File.WriteAllBytes(reg, ProfileWriter.RegistryFile(values)); }
        finally { SecretBuffers.Clear(values); }
        return (txt, reg);
    }
}

public sealed class TestFolder : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AnyOTPManager-tests", Guid.NewGuid().ToString("N"));
    public TestFolder() => Directory.CreateDirectory(Path);
    public void Dispose()
    {
        var root = System.IO.Path.GetFullPath(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "AnyOTPManager-tests")) + System.IO.Path.DirectorySeparatorChar;
        if (!System.IO.Path.GetFullPath(Path).StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException();
        Directory.Delete(Path, true);
    }
}

internal sealed class FakeDisks : IDiskSource
{
    public DiskIdentity Identity { get; set; } = Fixtures.OtherDisk;
    public IReadOnlyList<DiskChoice> List() => [new(0, "Synthetic disk")];
    public DiskIdentity Read(int index) => Identity;
}

internal sealed class MemoryRegistry : IRegistryStore
{
    public RegistrySnapshot State { get; set; } = new();
    public int Writes { get; private set; }
    public int FailOnWrite { get; set; }
    public bool FailAllWrites { get; set; }
    public bool CorruptReadAfterWrite { get; set; }
    public RegistrySnapshot Read() => CorruptReadAfterWrite && Writes == 1 ? new() : State.Clone();
    public void Write(RegistrySnapshot snapshot)
    {
        Writes++;
        if (FailAllWrites || Writes == FailOnWrite)
        {
            State.Dispose(); State = new() { Exists = true, Values = snapshot.Values.Take(1).Select(v => v.Clone()).ToList() };
            throw new IOException("Synthetic failure");
        }
        State.Dispose(); State = snapshot.Clone();
    }
}
