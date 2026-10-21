using System.Diagnostics;
using System.Globalization;
using System.Management;
using AnyOTPManager.Core;

namespace AnyOTPManager.Windows;

public sealed record DiskChoice(int Index, string Label);

public interface IDiskSource
{
    IReadOnlyList<DiskChoice> List();
    DiskIdentity Read(int index);
}

public sealed class DiskService : IDiskSource
{
    public IReadOnlyList<DiskChoice> List()
    {
        try
        {
            using var query = Query("SELECT Index, Model FROM Win32_DiskDrive");
            using var rows = query.Get();
            var disks = new List<DiskChoice>();
            foreach (ManagementObject row in rows)
            {
                using (row)
                {
                    var index = Convert.ToInt32(row["Index"], CultureInfo.InvariantCulture);
                    var model = Convert.ToString(row["Model"], CultureInfo.InvariantCulture)?.Trim() ?? "Disk";
                    if (model.Length > 128 || model.Any(char.IsControl)) model = "Disk";
                    disks.Add(new(index, $"Disk {index} · {model}"));
                }
            }
            if (disks.Count == 0 || disks.Any(d => d.Index < 0) || disks.Select(d => d.Index).Distinct().Count() != disks.Count)
                throw new OtpException("Yerel diskler okunamadı.");
            return disks.OrderBy(d => d.Index).ToArray();
        }
        catch (OtpException) { throw; }
        catch { throw new OtpException("Disk listesi okunamadı. Windows WMI hizmetini kontrol edin."); }
    }

    public DiskIdentity Read(int index)
    {
        if (index < 0) throw new OtpException("Aktarılacak diski seçin.");
        try
        {
            using var query = Query("SELECT Index, PNPDeviceID, Signature FROM Win32_DiskDrive WHERE Index = " + index.ToString(CultureInfo.InvariantCulture));
            using var rows = query.Get();
            DiskIdentity? result = null;
            foreach (ManagementObject row in rows)
            {
                using (row)
                {
                    if (result is not null) throw new OtpException("Disk seçimi belirsiz.");
                    var pnp = row["PNPDeviceID"] as string ?? throw new OtpException("Disk kimliği okunamadı.");
                    var signature = row["Signature"];
                    result = new(pnp, signature is null or DBNull ? 0 : Convert.ToUInt32(signature, CultureInfo.InvariantCulture));
                    _ = OtpEngine.DiskKey(result);
                }
            }
            return result ?? throw new OtpException("Seçilen disk artık bağlı değil.");
        }
        catch (OtpException) { throw; }
        catch { throw new OtpException("Seçilen diskin bilgileri okunamadı."); }
    }

    private static ManagementObjectSearcher Query(string text) => new(
        new ManagementScope(@"\\.\root\CIMV2"), new ObjectQuery(text),
        new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(5), ReturnImmediately = false });

    public static void RequireVendorClosed()
    {
        foreach (var name in new[] { "AnyOTP", "AnyOTPClient" })
        {
            var running = Process.GetProcessesByName(name);
            try { if (running.Length > 0) throw new OtpException("Aktarmadan önce AnyOTP uygulamasını kapatın."); }
            finally { foreach (var process in running) process.Dispose(); }
        }
    }
}
