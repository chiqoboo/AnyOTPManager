using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AnyOTPManager.Core;

public static class ProfileWriter
{
    public static byte[] DiskFile(DiskIdentity disk)
    {
        _ = OtpEngine.DiskKey(disk);
        return new UTF8Encoding(false, true).GetBytes(disk.DiskId + "\r\n" + disk.Signature.ToString(CultureInfo.InvariantCulture) + "\r\n0\r\n");
    }
    public static byte[] RegistryFile(IReadOnlyList<OtpRegistryValue> values)
    {
        var text = new StringBuilder("Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\AnyOTP]\r\n");
        foreach (var value in values.OrderBy(v => v.Name, StringComparer.Ordinal))
        {
            text.Append('"').Append(Escape(value.Name)).Append("\"=");
            switch (value.Kind)
            {
                case OtpRegistryValueKind.Binary when value.Binary is not null && value.Text is null && value.Dword is null:
                    text.Append("hex:");
                    for (var i = 0; i < value.Binary.Length; i++)
                    {
                        if (i > 0) text.Append(i % 24 == 0 ? ",\\\r\n  " : ",");
                        text.Append(value.Binary[i].ToString("x2", CultureInfo.InvariantCulture));
                    }
                    break;
                case OtpRegistryValueKind.String when value.Text is not null && value.Binary is null && value.Dword is null:
                    text.Append('"').Append(Escape(value.Text)).Append('"'); break;
                case OtpRegistryValueKind.Dword when value.Dword is not null && value.Binary is null && value.Text is null:
                    text.Append("dword:").Append(value.Dword.Value.ToString("x8", CultureInfo.InvariantCulture)); break;
                default: throw new OtpException("Kayıt biçimi desteklenmiyor.");
            }
            text.Append("\r\n");
            if (text.Length * 2L + 2 > ProfileFiles.MaxRegistryBytes) throw new OtpException("REG dosyası çok büyük.");
        }
        var data = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(text.ToString())).ToArray();
        try { var parsed = ProfileFiles.ParseRegistry(data); SecretBuffers.Clear(parsed); return data; }
        catch { CryptographicOperations.ZeroMemory(data); throw; }
    }
    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
