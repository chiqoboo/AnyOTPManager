using System.Security.Cryptography;

namespace AnyOTPManager.Core;

public static class Defaults
{
    // User-selected default for import, PIN-change and transfer forms; not an application password.
    public const string Pin = "290785";
}

public sealed class OtpException(string safeMessage) : Exception(safeMessage);
public enum OtpRegistryValueKind { Binary, String, Dword }

public sealed class OtpRegistryValue
{
    public string Name { get; init; } = "";
    public OtpRegistryValueKind Kind { get; init; }
    public byte[]? Binary { get; init; }
    public string? Text { get; init; }
    public uint? Dword { get; init; }
    public OtpRegistryValue Clone() => new() { Name = Name, Kind = Kind, Binary = Binary?.ToArray(), Text = Text, Dword = Dword };
    public override string ToString() => "Registry value [protected]";
}

public sealed record DiskIdentity(string DiskId, uint Signature)
{
    public override string ToString() => "Disk identity [protected]";
}

public sealed record OtpParameters(int StepSeconds, int Digits);
public sealed record CodeState(string Code, int SecondsRemaining, double RemainingFraction, long Counter)
{
    public override string ToString() => "OTP [protected]";
}

// Serialized only inside Windows CurrentUser protection. Never log or display this model.
public sealed class SavedEntry : IDisposable
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public required string Alias { get; set; }
    public DateTimeOffset AddedAt { get; init; } = DateTimeOffset.UtcNow;
    public required byte[] Seed { get; init; }
    public required DiskIdentity Disk { get; set; }
    public required string Pin { get; set; }
    public required List<OtpRegistryValue> Registry { get; set; }

    public SavedEntry Clone() => new() { Id = Id, Alias = Alias, AddedAt = AddedAt, Seed = Seed.ToArray(),
        Disk = Disk, Pin = Pin, Registry = Registry.Select(v => v.Clone()).ToList() };
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Seed);
        SecretBuffers.Clear(Registry);
        Pin = "";
    }
    public override string ToString() => "OTP entry [protected]";
}

public static class SecretBuffers
{
    public static void Clear(IEnumerable<OtpRegistryValue> values)
    {
        foreach (var v in values) if (v.Binary is not null) CryptographicOperations.ZeroMemory(v.Binary);
    }
}
