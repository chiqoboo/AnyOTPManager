using System.Security.Cryptography;
using AnyOTPManager.Core;

namespace AnyOTPManager.Windows;

public sealed record EntryView(Guid Id, string Alias, DateTimeOffset AddedAt, int StepSeconds, int Digits, CodeState Otp);
public sealed record ManagerView(IReadOnlyList<EntryView> Entries, bool CanRestore, bool HasPending);

public sealed class TransferPlan : IDisposable
{
    internal long Revision { get; init; }
    internal TransferPlan() { }
    internal DiskIdentity Disk { get; init; } = null!;
    internal RegistrySnapshot Before { get; init; } = null!;
    internal RegistrySnapshot Target { get; init; } = null!;
    public required Guid EntryId { get; init; }
    public required string Alias { get; init; }
    public required DiskChoice DiskChoice { get; init; }
    public bool ReplacesExisting => Before.Exists;
    public void Dispose() { Before.Dispose(); Target.Dispose(); }
    public override string ToString() => "Transfer plan [protected]";
}

/// <summary>Owns all profile and transfer mutations. Views only issue commands and display snapshots.</summary>
public sealed class OtpManager : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly VaultStore _vault;
    private readonly IDiskSource _disks;
    private readonly IRegistryStore _registry;
    private readonly RegistryTransfer _transfer;
    private readonly Action _vendorClosed;
    private List<SavedEntry> _entries = [];
    private long _revision;
    private bool _initialized, _disposed;

    public OtpManager(string directory, IDiskSource? disks = null, IRegistryStore? registry = null, Action? vendorClosed = null)
    {
        _vault = new(directory); _disks = disks ?? new DiskService(); _registry = registry ?? new WindowsRegistryStore();
        _vendorClosed = vendorClosed ?? DiskService.RequireVendorClosed;
        _transfer = new(_registry, Path.Combine(directory, "backups"));
    }
    public string DataDirectory => _vault.DirectoryPath;

    public Task InitializeAsync(CancellationToken ct = default) => Run(() =>
    {
        if (_initialized) return;
        _entries = _vault.Load(); _initialized = true;
    }, ct, requireInitialized: false);

    public Task<ManagerView> ViewAsync(DateTimeOffset now, CancellationToken ct = default) => Run(() =>
        new ManagerView(_entries.Select(e =>
        {
            var settings = OtpEngine.Parameters(e.Registry);
            return new EntryView(e.Id, e.Alias, e.AddedAt, settings.StepSeconds, settings.Digits, OtpEngine.Generate(e.Seed, settings, now));
        }).OrderBy(e => e.Alias, StringComparer.CurrentCultureIgnoreCase).ToArray(), _transfer.CanRestore, _transfer.HasPending), ct);

    public Task ImportAsync(string alias, string txtPath, string regPath, string pin, CancellationToken ct = default) => Run(() =>
    {
        alias = ValidateImport(alias, pin);
        var diskBytes = ProtectedFile.ReadBounded(txtPath, ProfileFiles.MaxSpoofBytes);
        byte[]? regBytes = null;
        List<OtpRegistryValue>? registry = null;
        try
        {
            regBytes = ProtectedFile.ReadBounded(regPath, ProfileFiles.MaxRegistryBytes);
            var disk = ProfileFiles.ParseDisk(diskBytes);
            registry = ProfileFiles.ParseRegistry(regBytes).ToList();
            ImportProfile(alias, disk, registry, pin, ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(diskBytes);
            if (regBytes is not null) CryptographicOperations.ZeroMemory(regBytes);
            if (registry is not null) SecretBuffers.Clear(registry);
        }
    }, ct);

    public Task ImportFromComputerAsync(string alias, DiskChoice choice, string pin, CancellationToken ct = default) => Run(() =>
    {
        alias = ValidateImport(alias, pin);
        if (choice is null || choice.Index < 0) throw new OtpException("AnyOTP'nin kullandığı yerel diski seçin.");
        using var registry = _registry.Read();
        if (!registry.Exists || registry.Values.Count == 0)
            throw new OtpException("Bu Windows hesabında AnyOTP kaydı bulunamadı. AnyOTP kurulumu olan bilgisayarda bu seçeneği kullanın veya TXT ve REG dosyalarından ekleyin.");
        var disk = _disks.Read(choice.Index);
        ImportProfile(alias, disk, registry.Values, pin, ct);
    }, ct);

    private string ValidateImport(string alias, string pin)
    {
        alias = OtpEngine.ValidateAlias(alias); OtpEngine.ValidatePin(pin);
        if (_entries.Count >= 500) throw new OtpException("En fazla 500 OTP kaydı saklanabilir.");
        EnsureAlias(alias);
        return alias;
    }

    private void ImportProfile(string alias, DiskIdentity disk, IReadOnlyList<OtpRegistryValue> registry, string pin, CancellationToken ct)
    {
        if (registry.Count > 64) throw new OtpException("OTP kaydı desteklenen değer sayısını aşıyor.");
        byte[]? seed = null;
        List<OtpRegistryValue>? wrapped = null;
        try
        {
            seed = OtpEngine.Unlock(registry, disk, pin);
            if (_entries.Any(e => CryptographicOperations.FixedTimeEquals(e.Seed, seed)))
                throw new OtpException("Bu OTP zaten listede. Mevcut kaydın adını değiştirebilirsiniz.");
            // Keep a validated PIN-protected copy without SharedKey. Never write to the source.
            wrapped = OtpEngine.Rewrap(seed, registry, disk, pin);
            var candidate = CopyEntries();
            candidate.Add(new SavedEntry { Alias = alias, Disk = disk, Registry = wrapped, Seed = seed, Pin = pin });
            wrapped = null; seed = null;
            Commit(candidate, ct);
        }
        finally
        {
            if (seed is not null) CryptographicOperations.ZeroMemory(seed);
            if (wrapped is not null) SecretBuffers.Clear(wrapped);
        }
    }

    public Task RenameAsync(Guid id, string alias, CancellationToken ct = default) => Run(() =>
    {
        alias = OtpEngine.ValidateAlias(alias); EnsureAlias(alias, id);
        _ = Find(id);
        var candidate = CopyEntries(); candidate.Single(e => e.Id == id).Alias = alias; Commit(candidate, ct);
    }, ct);

    public Task DeleteAsync(Guid id, CancellationToken ct = default) => Run(() =>
    {
        _ = Find(id);
        var candidate = _entries.Where(e => e.Id != id).Select(e => e.Clone()).ToList(); Commit(candidate, ct);
    }, ct);

    public Task ChangePinAsync(Guid id, string pin, CancellationToken ct = default) => Run(() =>
    {
        OtpEngine.ValidatePin(pin); _ = Find(id);
        var candidate = CopyEntries();
        try
        {
            var entry = candidate.Single(e => e.Id == id);
            var replacement = OtpEngine.Rewrap(entry.Seed, entry.Registry, entry.Disk, pin);
            SecretBuffers.Clear(entry.Registry); entry.Registry = replacement; entry.Pin = pin;
        }
        catch { DisposeEntries(candidate); throw; }
        Commit(candidate, ct);
    }, ct);

    public Task<string> ExportAsync(Guid id, string folder, CancellationToken ct = default) => Run(() =>
    {
        var entry = Find(id);
        if (!Directory.Exists(folder)) throw new OtpException("Geçerli bir hedef klasör seçin.");
        var safeName = string.Concat(entry.Alias.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c)).TrimEnd('.', ' ');
        if (safeName.Length == 0) safeName = "OTP";
        var output = Path.Combine(Path.GetFullPath(folder), safeName + "-" + Guid.NewGuid().ToString("N"));
        var createdFiles = new List<string>();
        var txt = ProfileWriter.DiskFile(entry.Disk);
        var reg = ProfileWriter.RegistryFile(entry.Registry);
        try
        {
            ct.ThrowIfCancellationRequested();
            if (Directory.Exists(output)) throw new OtpException("Hedef klasör zaten var; mevcut dosyalara dokunulmadı.");
            Directory.CreateDirectory(output);
            foreach (var (name, bytes) in new[] { ("device.txt", txt), ("otp.reg", reg) })
            {
                var path = Path.Combine(output, name);
                using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                createdFiles.Add(path);
                stream.Write(bytes); stream.Flush(true);
            }
            return output;
        }
        catch
        {
            // Only the two files in this newly generated directory belong to this operation.
            foreach (var path in createdFiles) if (File.Exists(path)) File.Delete(path);
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(txt); CryptographicOperations.ZeroMemory(reg); }
    }, ct);

    public Task<IReadOnlyList<DiskChoice>> DisksAsync(CancellationToken ct = default) => Run(() => _disks.List(), ct);

    public Task<TransferPlan> PrepareTransferAsync(Guid id, DiskChoice choice, string pin, CancellationToken ct = default) => Run(() =>
    {
        var entry = Find(id); OtpEngine.ValidatePin(pin); _vendorClosed();
        var disk = _disks.Read(choice.Index);
        var values = OtpEngine.Rewrap(entry.Seed, entry.Registry, disk, pin);
        RegistrySnapshot? before = null;
        try
        {
            before = _registry.Read();
            return new TransferPlan { EntryId = id, Alias = entry.Alias, DiskChoice = choice, Disk = disk,
                Before = before, Target = new() { Exists = true, Values = values }, Revision = _revision };
        }
        catch { before?.Dispose(); SecretBuffers.Clear(values); throw; }
    }, ct);

    public Task ApplyTransferAsync(TransferPlan plan, CancellationToken ct = default) => Run(() =>
    {
        if (plan.Revision != _revision || !_entries.Any(e => e.Id == plan.EntryId))
            throw new OtpException("Seçilen kayıt değişti. Aktarımı yeniden hazırlayın.");
        _vendorClosed();
        if (_disks.Read(plan.DiskChoice.Index) != plan.Disk) throw new OtpException("Disk bilgisi değişti. Aktarımı yeniden hazırlayın.");
        _transfer.Apply(plan.Before, plan.Target, ct);
    }, ct);

    public Task RestoreTransferAsync(CancellationToken ct = default) => Run(() => { _vendorClosed(); _transfer.Restore(ct); }, ct);

    private SavedEntry Find(Guid id) => _entries.SingleOrDefault(e => e.Id == id) ?? throw new OtpException("Kayıt artık listede değil.");
    private void EnsureAlias(string alias, Guid? except = null)
    {
        if (_entries.Any(e => e.Id != except && e.Alias.Equals(alias, StringComparison.OrdinalIgnoreCase)))
            throw new OtpException("Bu kayıt adı zaten kullanılıyor. Farklı bir ad seçin.");
    }
    private List<SavedEntry> CopyEntries() => _entries.Select(e => e.Clone()).ToList();
    private void Commit(List<SavedEntry> candidate, CancellationToken ct)
    {
        try { ct.ThrowIfCancellationRequested(); _vault.Save(candidate); }
        catch { DisposeEntries(candidate); throw; }
        DisposeEntries(_entries); _entries = candidate; _revision++;
    }
    private static void DisposeEntries(IEnumerable<SavedEntry> entries) { foreach (var e in entries) e.Dispose(); }

    private Task Run(Action action, CancellationToken ct, bool requireInitialized = true) =>
        Run(() => { action(); return true; }, ct, requireInitialized);
    private async Task<T> Run<T>(Func<T> action, CancellationToken ct, bool requireInitialized = true)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (requireInitialized && !_initialized) throw new OtpException("Kayıtlar henüz açılmadı.");
            return await Task.Run(() => { ct.ThrowIfCancellationRequested(); return action(); }, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
    public void Dispose()
    {
        _gate.Wait();
        try { if (!_disposed) { _disposed = true; DisposeEntries(_entries); _entries.Clear(); } }
        finally { _gate.Release(); }
    }
}
