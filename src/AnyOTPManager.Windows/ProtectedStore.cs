using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AnyOTPManager.Core;

namespace AnyOTPManager.Windows;

public static class ProtectedFile
{
    private const int MaximumBytes = 16 * 1024 * 1024;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AnyOTPManager/protected-storage/v1");

    public static T Read<T>(string path)
    {
        var bytes = ReadBounded(path, MaximumBytes);
        byte[]? clear = null;
        try
        {
            clear = ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser);
            return JsonSerializer.Deserialize<T>(clear) ?? throw new OtpException("Kayıt dosyası boş.");
        }
        catch (Exception e) when (e is CryptographicException or JsonException or NotSupportedException)
        { throw new OtpException("Kayıt açılamadı. Aynı Windows hesabını kullanın; mevcut dosyalar korunuyor."); }
        finally { CryptographicOperations.ZeroMemory(bytes); if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
    }

    public static void Write<T>(string path, T value)
    {
        var clear = JsonSerializer.SerializeToUtf8Bytes(value);
        byte[]? cipher = null;
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            if (clear.Length > MaximumBytes - 4096) throw new OtpException("Kayıt alanı sınırı aşıldı.");
            cipher = ProtectedData.Protect(clear, Entropy, DataProtectionScope.CurrentUser);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { stream.Write(cipher); stream.Flush(true); }
            var stored = ReadBounded(temporary, MaximumBytes);
            var recovered = ProtectedData.Unprotect(stored, Entropy, DataProtectionScope.CurrentUser);
            try { if (!CryptographicOperations.FixedTimeEquals(clear, recovered)) throw new OtpException("Kaydedilen bilgi doğrulanamadı."); }
            finally { CryptographicOperations.ZeroMemory(stored); CryptographicOperations.ZeroMemory(recovered); }
            if (File.Exists(path)) File.Replace(temporary, path, path + ".previous", ignoreMetadataErrors: false);
            else File.Move(temporary, path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
            if (cipher is not null) CryptographicOperations.ZeroMemory(cipher);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public static byte[] ReadBounded(string path, int limit)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length <= 0 || stream.Length > limit) throw new OtpException("Dosya boş veya desteklenen boyutu aşıyor.");
        var bytes = new byte[checked((int)stream.Length)];
        try { stream.ReadExactly(bytes); return bytes; }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }
}

public sealed class VaultDocument
{
    public int Version { get; init; } = 1;
    public List<SavedEntry> Entries { get; init; } = [];
}

public sealed class VaultStore(string directory)
{
    public string DirectoryPath { get; } = Path.GetFullPath(directory);
    public string FilePath => Path.Combine(DirectoryPath, "profiles.dpapi");

    public List<SavedEntry> Load()
    {
        if (!File.Exists(FilePath))
        {
            if (File.Exists(FilePath + ".previous")) throw new OtpException("Ana kayıt bulunamadı. Yedek dosya korunuyor; boş kayıt oluşturulmadı.");
            return [];
        }
        var document = ProtectedFile.Read<VaultDocument>(FilePath);
        try { Validate(document); return document.Entries; }
        catch { foreach (var entry in document.Entries ?? []) entry?.Dispose(); throw; }
    }

    public void Save(List<SavedEntry> entries)
    {
        var document = new VaultDocument { Entries = entries };
        Validate(document);
        ProtectedFile.Write(FilePath, document);
    }

    private static void Validate(VaultDocument document)
    {
        if (document.Version != 1 || document.Entries is null || document.Entries.Count > 500)
            throw new OtpException("Kayıt sürümü veya kayıt sayısı desteklenmiyor.");
        var ids = new HashSet<Guid>();
        var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in document.Entries)
        {
            if (entry is null || entry.Id == Guid.Empty || !ids.Add(entry.Id) ||
                !aliases.Add(OtpEngine.ValidateAlias(entry.Alias)) || entry.Seed is not { Length: 20 } ||
                entry.Disk is null || entry.Registry is null || entry.Pin is null)
                throw new OtpException("Kaydedilmiş OTP bilgisi geçersiz; dosya korunuyor.");
            var encoded = ProfileWriter.RegistryFile(entry.Registry);
            CryptographicOperations.ZeroMemory(encoded);
            var seed = OtpEngine.Unlock(entry.Registry, entry.Disk, entry.Pin);
            try { if (!CryptographicOperations.FixedTimeEquals(seed, entry.Seed)) throw new OtpException("Kaydın anahtar eşleşmesi geçersiz."); }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
    }
}
