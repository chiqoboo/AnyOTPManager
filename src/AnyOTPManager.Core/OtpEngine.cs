using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AnyOTPManager.Core;

/// <summary>AnyOTP PC 1.18.0.78 compatibility. This is not standard TOTP.</summary>
public static class OtpEngine
{
    public const long Epoch = 946652400;

    public static void ValidatePin(string pin)
    {
        if (pin is null || pin.Length != 6 || pin.Any(c => c is < '0' or > '9'))
            throw new OtpException("PIN tam olarak 6 rakam olmalı.");
    }

    public static string ValidateAlias(string alias)
    {
        alias = alias?.Trim() ?? "";
        if (alias.Length is < 1 or > 64 || alias.Any(char.IsControl))
            throw new OtpException("Kayıt adı 1–64 karakter olmalı.");
        return alias;
    }

    public static string DiskKey(DiskIdentity disk)
    {
        if (disk.DiskId is null || disk.DiskId.Length is < 16 or > 256 ||
            disk.DiskId.Any(c => c < 32 || c > 126) || disk.DiskId.Trim() != disk.DiskId)
            throw new OtpException("Disk bilgisi desteklenmiyor.");
        var prefix = disk.Signature == 0 ? "0000" : disk.Signature.ToString("X", CultureInfo.InvariantCulture);
        if (prefix.Length > 4) prefix = prefix[..4];
        var key = prefix + disk.DiskId[^16..];
        // Do not guess padding for short nonzero signatures: the vendor reads exactly 20 bytes.
        if (key.Length != 20) throw new OtpException("Bu disk imzasının biçimi desteklenmiyor; başka disk seçin.");
        return key;
    }

    public static (byte[] Key, byte[] Iv) Derive(string pin, DiskIdentity disk)
    {
        ValidatePin(pin);
        var material = Encoding.ASCII.GetBytes(pin + DiskKey(disk));
        var digest = SHA1.HashData(material);
        var second = SHA1.HashData(digest.AsSpan(16, 4));
        try { return (digest[..16], second[..16]); }
        finally { CryptographicOperations.ZeroMemory(material); CryptographicOperations.ZeroMemory(digest); CryptographicOperations.ZeroMemory(second); }
    }

    public static OtpParameters Parameters(IReadOnlyList<OtpRegistryValue> registry)
    {
        var env = Binary(registry, "EnvInfo", 26);
        // The two-byte ASCII field can be zero- or space-padded ("06", "6 ", " 6").
        // Parse without changing EnvInfo: its original bytes are authenticated by VMData.
        var digits = Encoding.ASCII.GetString(env, 14, 2).Trim(' ') switch
        {
            "6" or "06" => 6,
            "7" or "07" => 7,
            "8" or "08" => 8,
            _ => throw new OtpException("Bu kaydın OTP hane sayısı desteklenmiyor.")
        };
        return new(env[12] switch { (byte)'1' => 30, (byte)'2' => 15, _ => 60 }, digits);
    }

    public static byte[] Unlock(IReadOnlyList<OtpRegistryValue> registry, DiskIdentity disk, string pin)
    {
        ValidatePin(pin);
        _ = Parameters(registry);
        var env = Binary(registry, "EnvInfo", 26);
        var cipher = Binary(registry, "VMData", 48);
        var (key, iv) = Derive(pin, disk);
        byte[]? plain = null;
        var pinBytes = Encoding.ASCII.GetBytes(pin);
        var envHash = SHA1.HashData(env.AsSpan(0, 26));
        try
        {
            using var aes = Aes.Create();
            aes.Key = key;
            plain = aes.DecryptCbc(cipher.AsSpan(0, 48), iv, PaddingMode.PKCS7);
            if (plain.Length != 46 || !CryptographicOperations.FixedTimeEquals(plain.AsSpan(0, 6), pinBytes) ||
                !CryptographicOperations.FixedTimeEquals(plain.AsSpan(26, 20), envHash))
                throw InvalidCredentials();
            return plain.AsSpan(6, 20).ToArray();
        }
        catch (CryptographicException) { throw InvalidCredentials(); }
        finally
        {
            foreach (var bytes in new[] { key, iv, pinBytes, envHash }) CryptographicOperations.ZeroMemory(bytes);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static List<OtpRegistryValue> Rewrap(byte[] seed, IReadOnlyList<OtpRegistryValue> registry, DiskIdentity disk, string pin)
    {
        if (seed.Length != 20) throw new OtpException("OTP anahtarı 20 bayt olmalı.");
        ValidatePin(pin);
        _ = Parameters(registry);
        var env = Binary(registry, "EnvInfo", 26);
        var oldVm = Binary(registry, "VMData", 48);
        var (key, iv) = Derive(pin, disk);
        var plain = new byte[46];
        var pinBytes = Encoding.ASCII.GetBytes(pin);
        var envHash = SHA1.HashData(env.AsSpan(0, 26));
        try
        {
            pinBytes.CopyTo(plain, 0); seed.CopyTo(plain, 6); envHash.CopyTo(plain, 26);
            using var aes = Aes.Create(); aes.Key = key;
            var encrypted = aes.EncryptCbc(plain, iv, PaddingMode.PKCS7);
            var vm = oldVm.ToArray();
            encrypted.CopyTo(vm, 0);
            CryptographicOperations.ZeroMemory(encrypted);
            var result = registry.Where(v => !v.Name.Equals("SharedKey", StringComparison.OrdinalIgnoreCase))
                .Select(v => v.Name.Equals("VMData", StringComparison.OrdinalIgnoreCase)
                    ? new OtpRegistryValue { Name = v.Name, Kind = OtpRegistryValueKind.Binary, Binary = vm } : v.Clone()).ToList();
            // Validate the exact stored representation, rather than treating encryption as acceptance.
            try
            {
                var recovered = Unlock(result, disk, pin);
                try { if (!CryptographicOperations.FixedTimeEquals(recovered, seed)) throw new OtpException("Kayıt doğrulanamadı."); }
                finally { CryptographicOperations.ZeroMemory(recovered); }
                return result;
            }
            catch { SecretBuffers.Clear(result); throw; }
        }
        finally { foreach (var bytes in new[] { key, iv, plain, pinBytes, envHash }) CryptographicOperations.ZeroMemory(bytes); }
    }

    public static CodeState Generate(byte[] seed, OtpParameters parameters, DateTimeOffset now)
    {
        if (parameters.StepSeconds is not (15 or 30 or 60) || parameters.Digits is not (6 or 7 or 8))
            throw new OtpException("OTP zaman ayarları geçersiz.");
        var elapsed = now.ToUnixTimeSeconds() - Epoch;
        if (elapsed < 0 || elapsed / parameters.StepSeconds > uint.MaxValue)
            throw new OtpException("Bilgisayarın tarih ve saatini kontrol edin.");
        var counter = checked((uint)(elapsed / parameters.StepSeconds));
        var remaining = parameters.StepSeconds - (int)(elapsed % parameters.StepSeconds);
        return new(GenerateCounter(seed, counter, parameters.Digits), remaining, (double)remaining / parameters.StepSeconds, counter);
    }

    public static string GenerateCounter(byte[] seed, uint counter, int digits)
    {
        if (seed.Length != 20 || digits is not (6 or 7 or 8)) throw new OtpException("OTP bilgisi geçersiz.");
        Span<byte> message = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(message, counter);
        var hash = HMACSHA1.HashData(seed, message);
        try
        {
            var offset = hash[19] & 15;
            var number = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(offset, 4)) & 0x7fffffff;
            return (number % (digits switch { 6 => 1_000_000u, 7 => 10_000_000u, _ => 100_000_000u }))
                .ToString("D" + digits, CultureInfo.InvariantCulture);
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    private static byte[] Binary(IReadOnlyList<OtpRegistryValue> values, string name, int minimum)
    {
        var matches = values.Where(v => v.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length != 1 || matches[0].Kind != OtpRegistryValueKind.Binary || matches[0].Binary is not { } data ||
            data.Length < minimum || data.Length > 65536)
            throw new OtpException("Kayıtta gerekli AnyOTP bilgileri bulunamadı.");
        return data;
    }
    private static OtpException InvalidCredentials() => new("PIN veya cihaz bilgisi bu OTP kaydıyla eşleşmiyor. Kaynak PIN'i ve seçilen dosyaları veya diski kontrol edin.");
}
