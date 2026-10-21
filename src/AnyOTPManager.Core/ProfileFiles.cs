using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace AnyOTPManager.Core;

/// <summary>Strict parsing only. Does not execute a registry file or change the computer.</summary>
public static partial class ProfileFiles
{
    public const int MaxRegistryBytes = 256 * 1024;
    public const int MaxSpoofBytes = 4096;
    public const string RegistrySubKey = @"Software\AnyOTP";

    public static DiskIdentity ParseDisk(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is 0 or > MaxSpoofBytes) throw InvalidSpoof();
        var lines = Decode(bytes).Replace("\r\n", "\n").Split('\n').ToList();
        while (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[^1])) lines.RemoveAt(lines.Count - 1);
        if (lines.Count is < 2 or > 3) throw InvalidSpoof();
        // The exact suffix participates in the public component key: never silently normalize it.
        var diskId = lines[0];
        if (diskId.Length is < 16 or > 256 || diskId.Any(char.IsControl)
            || char.IsWhiteSpace(diskId[0]) || char.IsWhiteSpace(diskId[^1])) throw InvalidSpoof();
        if (!uint.TryParse(lines[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var signature))
            throw InvalidSpoof();
        // Legacy optional patch flag is deliberately neither returned nor acted upon.
        if (lines.Count == 3 && (lines[2].Length > 128 || lines[2].Any(char.IsControl))) throw InvalidSpoof();
        return new DiskIdentity(diskId, signature);
    }

    public static IReadOnlyList<OtpRegistryValue> ParseRegistry(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length is 0 or > MaxRegistryBytes) throw InvalidRegistry();
        var lines = Decode(bytes).Replace("\r\n", "\n").Split('\n');
        if (lines.Length == 0 || lines[0].Trim() != "Windows Registry Editor Version 5.00") throw InvalidRegistry();
        var values = new List<OtpRegistryValue>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sawKey = false;
        for (var index = 1; index < lines.Length; index++)
        {
            var line = lines[index].Trim();
            if (line.Length == 0 || line.StartsWith(';')) continue;
            if (line.StartsWith('['))
            {
                if (sawKey || !(line.Equals(@"[HKEY_CURRENT_USER\Software\AnyOTP]", StringComparison.OrdinalIgnoreCase)
                    || line.Equals(@"[HKCU\Software\AnyOTP]", StringComparison.OrdinalIgnoreCase))) throw InvalidRegistry();
                sawKey = true;
                continue;
            }
            if (!sawKey || values.Count >= 128) throw InvalidRegistry();
            var match = Assignment().Match(line);
            if (!match.Success) throw InvalidRegistry();
            var name = Unescape(match.Groups[1].Value);
            if (name.Length is 0 or > 128 || name.Any(char.IsControl) || !names.Add(name)) throw InvalidRegistry();
            var raw = match.Groups[2].Value;
            if (raw.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
            {
                var data = raw[4..];
                while (data.EndsWith('\\'))
                {
                    if (!data.EndsWith(",\\", StringComparison.Ordinal) || ++index >= lines.Length) throw InvalidRegistry();
                    data = data[..^1] + lines[index].Trim();
                    if (data.Length > 196608) throw InvalidRegistry();
                }
                var pieces = data.Length == 0 ? Array.Empty<string>() : data.Split(',');
                if (pieces.Length > 65536) throw InvalidRegistry();
                var binary = new byte[pieces.Length];
                for (var i = 0; i < pieces.Length; i++)
                {
                    if (pieces[i].Length != 2 || !byte.TryParse(pieces[i], NumberStyles.AllowHexSpecifier,
                        CultureInfo.InvariantCulture, out binary[i])) throw InvalidRegistry();
                }
                values.Add(new OtpRegistryValue { Name = name, Kind = OtpRegistryValueKind.Binary, Binary = binary });
            }
            else if (raw.StartsWith("dword:", StringComparison.OrdinalIgnoreCase))
            {
                var digits = raw[6..];
                if (digits.Length != 8 || !uint.TryParse(digits, NumberStyles.AllowHexSpecifier,
                    CultureInfo.InvariantCulture, out var dword)) throw InvalidRegistry();
                values.Add(new OtpRegistryValue { Name = name, Kind = OtpRegistryValueKind.Dword, Dword = dword });
            }
            else
            {
                var textMatch = QuotedString().Match(raw);
                if (!textMatch.Success) throw InvalidRegistry();
                var text = Unescape(textMatch.Groups[1].Value);
                if (text.Length > 65536 || text.Any(char.IsControl)) throw InvalidRegistry();
                values.Add(new OtpRegistryValue { Name = name, Kind = OtpRegistryValueKind.String, Text = text });
            }
        }
        if (!sawKey || values.Count == 0) throw InvalidRegistry();
        return values.AsReadOnly();
    }

    private static string Decode(byte[] bytes)
    {
        try
        {
            string text;
            if (bytes.AsSpan().StartsWith(new byte[] { 0xff, 0xfe }))
                text = new UnicodeEncoding(false, false, true).GetString(bytes, 2, bytes.Length - 2);
            else if (bytes.AsSpan().StartsWith(new byte[] { 0xfe, 0xff }))
                text = new UnicodeEncoding(true, false, true).GetString(bytes, 2, bytes.Length - 2);
            else
            {
                var offset = bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
                text = new UTF8Encoding(false, true).GetString(bytes, offset, bytes.Length - offset);
            }
            if (text.Contains('\0') || text.Replace("\r\n", "\n").Contains('\r')) throw new InvalidDataException("OTP profil metni geçersiz.");
            return text;
        }
        catch (DecoderFallbackException) { throw new InvalidDataException("OTP profil metin kodlaması desteklenmiyor."); }
    }

    private static string Unescape(string source)
    {
        var result = new StringBuilder(source.Length);
        for (var i = 0; i < source.Length; i++)
        {
            if (source[i] == '\\')
            {
                if (++i == source.Length || source[i] is not ('\\' or '"')) throw InvalidRegistry();
            }
            result.Append(source[i]);
        }
        return result.ToString();
    }

    private static InvalidDataException InvalidRegistry() => new("Kayıt dosyası yalnızca HKCU\\Software\\AnyOTP anahtarında desteklenen değerleri içerebilir.");
    private static InvalidDataException InvalidSpoof() => new("Cihaz bilgisi dosyası geçersiz; disk kimliği ve sayısal imza bekleniyor.");

    [GeneratedRegex("^\"((?:[^\"\\\\]|\\\\[\"\\\\])*)\"=(.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex Assignment();
    [GeneratedRegex("^\"((?:[^\"\\\\]|\\\\[\"\\\\])*)\"$", RegexOptions.CultureInvariant)]
    private static partial Regex QuotedString();
}
