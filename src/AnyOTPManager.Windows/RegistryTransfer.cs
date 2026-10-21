using AnyOTPManager.Core;

namespace AnyOTPManager.Windows;

public sealed class TransferJournal : IDisposable
{
    public int Version { get; init; } = 1;
    public Guid OperationId { get; init; } = Guid.NewGuid();
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public required RegistrySnapshot Before { get; init; }
    public required RegistrySnapshot After { get; init; }
    public void Dispose() { Before.Dispose(); After.Dispose(); }
    public override string ToString() => "Transfer journal [protected]";
}

/// <summary>One mutation, durable backup, readback and explicit recovery. No automatic retry.</summary>
public sealed class RegistryTransfer(IRegistryStore registry, string directory)
{
    private string Pending => Path.Combine(directory, "pending-transfer.dpapi");
    private string Last => Path.Combine(directory, "last-transfer.dpapi");
    public bool HasPending => File.Exists(Pending);
    public bool CanRestore => HasPending || File.Exists(Last);

    public void Apply(RegistrySnapshot expected, RegistrySnapshot target, CancellationToken cancellationToken = default)
    {
        if (HasPending) throw new OtpException("Tamamlanmamış aktarımı önce geri alın.");
        ApplyCore(expected, target, keepUndo: true, cancellationToken);
    }

    private void ApplyCore(RegistrySnapshot expected, RegistrySnapshot target, bool keepUndo, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using (var current = registry.Read())
            if (!RegistrySnapshot.Equal(current, expected)) throw new OtpException("Yerel AnyOTP kaydı değişti. Aktarımı yeniden hazırlayın.");
        using var journal = new TransferJournal { Before = expected.Clone(), After = target.Clone() };
        ProtectedFile.Write(Pending, journal);
        var started = false;
        try
        {
            token.ThrowIfCancellationRequested();
            using (var current = registry.Read())
                if (!RegistrySnapshot.Equal(current, expected)) throw new OtpException("Yerel kayıt hazırlık sırasında değişti; aktarılmadı.");
            // Cancellation is checked before the first write. Once started, finish verification/rollback.
            started = true;
            registry.Write(target);
            using (var observed = registry.Read())
                if (!RegistrySnapshot.Equal(observed, target)) throw new OtpException("Aktarımın kayıt doğrulaması başarısız.");
            if (keepUndo) ProtectedFile.Write(Last, journal);
            else if (File.Exists(Last)) File.Delete(Last);
            File.Delete(Pending);
        }
        catch
        {
            if (!started) { File.Delete(Pending); throw; }
            try
            {
                using var current = registry.Read();
                if (!RegistrySnapshot.IsOwnedIntermediate(current, expected, target)) throw new IOException();
                registry.Write(expected);
                using var restored = registry.Read();
                if (!RegistrySnapshot.Equal(restored, expected)) throw new IOException();
                File.Delete(Pending);
            }
            catch { throw new OtpException("Aktarım tamamlanamadı ve geri alma doğrulanamadı. Korunan yedek hazır; 'Aktarımı geri al' seçeneğini kullanın."); }
            throw new OtpException("Aktarım tamamlanamadı. Önceki AnyOTP kaydı geri yüklendi.");
        }
    }

    public void Restore(CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var pending = HasPending;
        var path = pending ? Pending : Last;
        if (!File.Exists(path)) throw new OtpException("Geri alınabilecek aktarım bulunamadı.");
        using var journal = ProtectedFile.Read<TransferJournal>(path);
        if (journal.Version != 1 || journal.Before is null || journal.After is null) throw new OtpException("Aktarım yedeğinin biçimi desteklenmiyor.");
        using var current = registry.Read();
        if (pending)
        {
            if (!RegistrySnapshot.Equal(current, journal.Before) &&
                !RegistrySnapshot.IsOwnedIntermediate(current, journal.Before, journal.After))
                throw new OtpException("Yerel kayıt başka bir uygulama tarafından değişmiş. Üzerine yazılmadı; yedek korunuyor.");
            // Keep the original pending journal until restoration has been verified.
            registry.Write(journal.Before);
            using var restored = registry.Read();
            if (!RegistrySnapshot.Equal(restored, journal.Before)) throw new OtpException("Geri alma doğrulanamadı; yedek korunuyor.");
            File.Delete(Pending);
        }
        else
        {
            if (!RegistrySnapshot.Equal(current, journal.After))
                throw new OtpException("Yerel AnyOTP kaydı sonradan değişmiş. Geri alma uygulanmadı; yedek korunuyor.");
            ApplyCore(current, journal.Before, keepUndo: false, token);
        }
    }
}
