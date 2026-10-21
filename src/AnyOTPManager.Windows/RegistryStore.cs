using Microsoft.Win32;
using AnyOTPManager.Core;

namespace AnyOTPManager.Windows;

public sealed class RegistrySnapshot : IDisposable
{
    public bool Exists { get; init; }
    public List<OtpRegistryValue> Values { get; init; } = [];
    public RegistrySnapshot Clone() => new() { Exists = Exists, Values = Values.Select(v => v.Clone()).ToList() };
    public void Dispose() => SecretBuffers.Clear(Values);
    public override string ToString() => "Registry snapshot [protected]";

    public static bool Equal(RegistrySnapshot a, RegistrySnapshot b) =>
        a.Exists == b.Exists && a.Values.Count == b.Values.Count &&
        a.Values.All(v => b.Values.Any(w => SameValue(v, w)));

    public static bool SameValue(OtpRegistryValue a, OtpRegistryValue b) =>
        string.Equals(a.Name, b.Name, StringComparison.OrdinalIgnoreCase) && a.Kind == b.Kind &&
        a.Text == b.Text && a.Dword == b.Dword &&
        (a.Binary is null ? b.Binary is null : b.Binary is not null && a.Binary.AsSpan().SequenceEqual(b.Binary));

    // Used only for recovering a partial write made by this operation; unrelated edits block rollback.
    public static bool IsOwnedIntermediate(RegistrySnapshot current, RegistrySnapshot before, RegistrySnapshot after) =>
        current.Values.All(v => before.Values.Concat(after.Values).Any(w => SameValue(v, w)));
}

public interface IRegistryStore
{
    RegistrySnapshot Read();
    void Write(RegistrySnapshot snapshot);
}

public sealed class WindowsRegistryStore : IRegistryStore
{
    private readonly string _subkey;
    public WindowsRegistryStore(string subkey = @"Software\AnyOTP")
    {
        if (subkey != @"Software\AnyOTP" && !subkey.StartsWith(@"Software\AnyOTPManager.Tests\", StringComparison.Ordinal))
            throw new ArgumentException("Unsupported registry scope.");
        _subkey = subkey;
    }

    public RegistrySnapshot Read()
    {
        using var user = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry32);
        using var key = user.OpenSubKey(_subkey, false);
        if (key is null) return new();
        if (key.SubKeyCount != 0 || key.ValueCount > 64) throw Unsupported();
        var values = new List<OtpRegistryValue>();
        try
        {
            foreach (var name in key.GetValueNames())
            {
                if (name.Length is 0 or > 128 || name.Any(char.IsControl)) throw Unsupported();
                var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                values.Add(key.GetValueKind(name) switch
                {
                    RegistryValueKind.Binary when value is byte[] bytes && bytes.Length <= 65536 =>
                        new() { Name = name, Kind = OtpRegistryValueKind.Binary, Binary = bytes },
                    RegistryValueKind.String when value is string text && text.Length <= 65536 && !text.Any(char.IsControl) =>
                        new() { Name = name, Kind = OtpRegistryValueKind.String, Text = text },
                    RegistryValueKind.DWord when value is int number =>
                        new() { Name = name, Kind = OtpRegistryValueKind.Dword, Dword = unchecked((uint)number) },
                    _ => throw Unsupported()
                });
            }
            return new() { Exists = true, Values = values };
        }
        catch { SecretBuffers.Clear(values); throw; }
    }

    public void Write(RegistrySnapshot snapshot)
    {
        using var user = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry32);
        using (var check = user.OpenSubKey(_subkey, false))
            if (check is not null && check.SubKeyCount != 0) throw Unsupported();
        if (!snapshot.Exists) { user.DeleteSubKey(_subkey, false); return; }
        using var key = user.CreateSubKey(_subkey, true);
        foreach (var value in snapshot.Values)
        {
            switch (value.Kind)
            {
                case OtpRegistryValueKind.Binary: key.SetValue(value.Name, value.Binary!, RegistryValueKind.Binary); break;
                case OtpRegistryValueKind.String: key.SetValue(value.Name, value.Text!, RegistryValueKind.String); break;
                case OtpRegistryValueKind.Dword: key.SetValue(value.Name, unchecked((int)value.Dword!.Value), RegistryValueKind.DWord); break;
                default: throw Unsupported();
            }
        }
        foreach (var name in key.GetValueNames())
            if (!snapshot.Values.Any(v => v.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) key.DeleteValue(name, false);
        key.Flush();
    }

    private static OtpException Unsupported() => new("Mevcut AnyOTP kaydının biçimi desteklenmiyor; üzerine yazılmadı.");
}
