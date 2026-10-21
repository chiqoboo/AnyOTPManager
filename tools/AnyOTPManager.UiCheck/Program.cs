using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using AnyOTPManager.App;
using AnyOTPManager.Core;
using AnyOTPManager.Windows;

internal static class Program
{
    private static int _passed;
    private static string _stage = "startup";
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 1) return 2;
        var output = Path.GetFullPath(args[0]); Directory.CreateDirectory(output);
        System.Windows.Media.RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
        var temporary = Path.Combine(Path.GetTempPath(), "AnyOTPManager-ui", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/AnyOTPManager;component/Theme.xaml", UriKind.Relative) });
        var binding = new BindingListener();
        PresentationTraceSources.DataBindingSource.Listeners.Add(binding);
        var result = 1;
        app.DispatcherUnhandledException += (_, e) =>
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "FAILED", stage = _stage, type = e.Exception.GetType().Name }));
            e.Handled = true; app.Shutdown(1);
        };
        app.Startup += async (_, _) =>
        {
            var fakeRegistry = new MemoryRegistry();
            using var manager = new OtpManager(Path.Combine(temporary, "vault"), new FakeDisks(), fakeRegistry, () => { });
            MainWindow? main = null;
            try
            {
                await manager.InitializeAsync();
                string? copied = null;
                main = new MainWindow(manager, s => copied = s) {
                    ShowActivated = false, ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual,
                    Left = -16000, Top = 20
                };
                app.MainWindow = main; main.Show();
                await Task.Delay(150); await main.RefreshAsync();
                Check(((ListBox)main.FindName("Cards")).Items.Count == 0, "empty_list");
                var localButton = (Button)main.FindName("SidebarLocalAddButton");
                var fileButton = (Button)main.FindName("SidebarAddButton");
                Check(localButton.IsEnabled && localButton.TranslatePoint(new Point(), main).Y < fileButton.TranslatePoint(new Point(), main).Y, "local_import_above_file_import");
                Screenshot(main, Path.Combine(output, "01-empty.png"));

                _stage = "import_dialog";
                var files = FixtureFiles(temporary, 0);
                var import = new ImportDialog(manager) { Owner = main, ShowActivated = false };
                Dialog(import, async () =>
                {
                    ((TextBox)import.FindName("AliasInput")).Text = "Örnek · Kişisel";
                    ((TextBox)import.FindName("TxtPath")).Text = files.Txt;
                    ((TextBox)import.FindName("RegPath")).Text = files.Reg;
                    var pin = (PasswordBox)import.FindName("PinInput");
                    Check(pin.Password == Defaults.Pin, "default_import_pin");
                    pin.Password = "000000"; Click(import, "SubmitButton");
                    await WaitFor(() => ((TextBlock)import.FindName("ErrorText")).Text.Length > 0);
                    Check((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries.Count == 0, "wrong_pin_no_profile");
                    pin.Password = "482619";
                    Screenshot(import, Path.Combine(output, "02-import.png"));
                    Click(import, "SubmitButton"); await WaitFor(() => !import.IsVisible);
                });
                Check(import.DialogResult == true, "import_dialog_saved");
                await main.RefreshAsync();
                await WaitFor(() => ((ListBox)main.FindName("Cards")).Items.Count == 1);
                Check(((ListBox)main.FindName("Cards")).Items.Count == 1, "first_card_visible");

                foreach (var (index, alias) in new[] { (1, "Örnek · İş hesabı"), (2, "Örnek · Yedek"), (3, "Örnek · İkinci hesap") })
                { var f = FixtureFiles(temporary, index); await manager.ImportAsync(alias, f.Txt, f.Reg, "482619"); }
                await main.RefreshAsync(); main.UpdateLayout();
                await WaitFor(() => ((ListBox)main.FindName("Cards")).Items.Count == 4);
                Check(((ListBox)main.FindName("Cards")).Items.Count == 4, "four_cards");
                Screenshot(main, Path.Combine(output, "03-main.png"));

                _stage = "search_and_copy";
                var search = (TextBox)main.FindName("SearchBox"); search.Text = "İş hesabı";
                Check(((ListBox)main.FindName("Cards")).Items.Count == 1, "search_match");
                search.Text = "no such fixture"; Check(((ListBox)main.FindName("Cards")).Items.Count == 0, "search_empty");
                search.Text = ""; await main.RefreshAsync();
                var cards = (ListBox)main.FindName("Cards"); cards.SelectedIndex = 0;
                Click(main, "CopyButton"); await WaitFor(() => copied is not null);
                Check(copied!.Length == 6 && copied.All(char.IsDigit), "copy_fresh_code");
                var selected = (EntryCard)cards.SelectedItem;

                _stage = "pin_dialog";
                var editPin = new PinDialog(manager, selected.Id, selected.Alias) { Owner = main, ShowActivated = false };
                Dialog(editPin, async () =>
                {
                    ((PasswordBox)editPin.FindName("NewPin")).Password = "517294";
                    ((PasswordBox)editPin.FindName("RepeatPin")).Password = "000000";
                    Click(editPin, "SubmitButton");
                    await WaitFor(() => ((TextBlock)editPin.FindName("ErrorText")).Text.Length > 0);
                    ((PasswordBox)editPin.FindName("RepeatPin")).Password = "517294";
                    Screenshot(editPin, Path.Combine(output, "04-pin.png"));
                    Click(editPin, "SubmitButton"); await WaitFor(() => !editPin.IsVisible);
                });
                Check(editPin.DialogResult == true, "pin_dialog_saved");
                var export = await manager.ExportAsync(selected.Id, temporary);
                var exported = ProfileFiles.ParseRegistry(File.ReadAllBytes(Path.Combine(export, "otp.reg")));
                Check(OtpEngine.Unlock(exported, FakeDisks.Source, "517294").Length == 20, "pin_dialog_actual_rewrap");

                _stage = "rename_dialog";
                var rename = new RenameDialog(manager, selected.Id, selected.Alias) { Owner = main, ShowActivated = false };
                Dialog(rename, async () =>
                { ((TextBox)rename.FindName("AliasInput")).Text = "Örnek · Yenilenen ad"; Click(rename, "SubmitButton"); await WaitFor(() => !rename.IsVisible); });
                await main.RefreshAsync();
                Check((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries.Any(e => e.Alias == "Örnek · Yenilenen ad"), "rename_persisted");

                _stage = "transfer_dialog";
                var transfer = new TransferDialog(manager, selected.Id, "Örnek · Yenilenen ad") { Owner = main, ShowActivated = false };
                Dialog(transfer, async () =>
                {
                    await WaitFor(() => ((ComboBox)transfer.FindName("DiskInput")).Items.Count == 1);
                    Check(((PasswordBox)transfer.FindName("PinInput")).Password == Defaults.Pin, "default_transfer_pin");
                    Screenshot(transfer, Path.Combine(output, "05-transfer.png"));
                    Click(transfer, "SubmitButton"); await WaitFor(() => !transfer.IsVisible);
                });
                Check(transfer.DialogResult == true && fakeRegistry.State.Exists, "transfer_dialog_applied");
                Check(OtpEngine.Unlock(fakeRegistry.State.Values, FakeDisks.Target, Defaults.Pin).Length == 20, "transfer_rebound");
                await manager.RestoreTransferAsync(); Check(!fakeRegistry.State.Exists, "transfer_undo");
                await main.RefreshAsync();

                _stage = "local_import_dialog";
                var localFiles = FixtureFiles(temporary, 4);
                var localValues = ProfileFiles.ParseRegistry(File.ReadAllBytes(localFiles.Reg));
                var localSeed = OtpEngine.Unlock(localValues, FakeDisks.Source, "482619");
                using var localSource = new RegistrySnapshot { Exists = true,
                    Values = OtpEngine.Rewrap(localSeed, localValues, FakeDisks.Target, "482619") };
                CryptographicOperations.ZeroMemory(localSeed); SecretBuffers.Clear(localValues);
                var interact = main.Dispatcher.InvokeAsync(async () =>
                {
                    var localImport = app.Windows.OfType<LocalImportDialog>().Single();
                    try
                    {
                        await WaitFor(() => ((Button)localImport.FindName("SubmitButton")).IsEnabled);
                        ((TextBox)localImport.FindName("AliasInput")).Text = "Örnek · Bu bilgisayar";
                        var localPin = (PasswordBox)localImport.FindName("PinInput");
                        Check(localPin.Password == Defaults.Pin, "default_local_import_pin");
                        Click(localImport, "SubmitButton");
                        await WaitFor(() => ((TextBlock)localImport.FindName("ErrorText")).Text.Contains("AnyOTP kaydı bulunamadı"));
                        Check((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries.Count == 4, "missing_local_registration_no_save");
                        fakeRegistry.Write(localSource);
                        var sourceWrites = fakeRegistry.Writes;
                        localPin.Password = "000000"; Click(localImport, "SubmitButton");
                        await WaitFor(() => ((TextBlock)localImport.FindName("ErrorText")).Text.Contains("eşleşmiyor"));
                        Check((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries.Count == 4, "wrong_local_pin_no_save");
                        localPin.Password = "482619";
                        Screenshot(localImport, Path.Combine(output, "06-local-import.png"));
                        Click(localImport, "SubmitButton"); await WaitFor(() => !localImport.IsVisible);
                        Check(localImport.DialogResult == true, "local_import_dialog_saved");
                        Check(fakeRegistry.Writes == sourceWrites && RegistrySnapshot.Equal(localSource, fakeRegistry.State), "local_import_source_unchanged");
                    }
                    finally { if (localImport.IsVisible) localImport.Close(); }
                });
                Click(main, "SidebarLocalAddButton");
                await interact.Task.Unwrap();
                await main.RefreshAsync();
                await WaitFor(() => ((ListBox)main.FindName("Cards")).Items.Count == 5);
                Check((await manager.ViewAsync(DateTimeOffset.UtcNow)).Entries.Any(e => e.Alias == "Örnek · Bu bilgisayar" && e.Otp.Code.Length == 6), "local_import_card_visible");
                Screenshot(main, Path.Combine(output, "07-local-added.png"));
                Check(binding.Errors == 0, "no_binding_errors");
                var actualDiskService = new DiskService();
                var actualDisks = actualDiskService.List();
                Check(actualDisks.Count > 0, "local_wmi_disks");
                Check(OtpEngine.DiskKey(actualDiskService.Read(actualDisks[0].Index)).Length == 20, "local_wmi_identity_supported");
                WriteIcon(Path.Combine(output, "AnyOTPManager.ico"));
                var report = new { status = "VERIFIED_TEST", checks = _passed, bindingErrors = binding.Errors,
                    realWpfWindows = true, fixtures = "synthetic only", clipboard = "injected sink",
                    activeAnyOtpRegistryTouched = false, localWmiRead = true, screenshots = 7, physicalUsb = "NOT RUN", liveAccountAcceptance = "NOT RUN" };
                File.WriteAllText(Path.Combine(output, "ui-verification.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                Console.WriteLine(JsonSerializer.Serialize(report)); result = 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "FAILED", stage = _stage, checks = _passed, type = e.GetType().Name }));
            }
            finally
            {
                foreach (Window window in app.Windows.Cast<Window>().ToArray()) window.Close();
                app.Shutdown();
            }
        };
        app.Run();
        var expectedRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "AnyOTPManager-ui")) + Path.DirectorySeparatorChar;
        if (Path.GetFullPath(temporary).StartsWith(expectedRoot, StringComparison.OrdinalIgnoreCase)) Directory.Delete(temporary, true);
        return result;
    }
    private static void Dialog(FormDialog dialog, Func<Task> actions)
    {
        Exception? failure = null;
        dialog.ContentRendered += async (_, _) =>
        {
            try { await Task.Delay(50); await actions(); }
            catch (Exception error) { failure = error; dialog.Close(); }
        };
        dialog.ShowDialog();
        if (failure is not null) throw failure;
    }
    private static void Click(FrameworkElement element, string name) => ((Button)element.FindName(name)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    private static async Task WaitFor(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition()) { if (watch.Elapsed > TimeSpan.FromSeconds(10)) throw new TimeoutException(); await Task.Delay(25); }
    }
    private static void Check(bool pass, string label) { if (!pass) throw new InvalidOperationException(label); _passed++; }
    private static void Screenshot(Window window, string path)
    {
        window.UpdateLayout();
        var content = (FrameworkElement)window.Content;
        var bitmap = new RenderTargetBitmap((int)content.ActualWidth, (int)content.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(content); var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(path); png.Save(file);
    }
    private static (string Txt, string Reg) FixtureFiles(string folder, int index)
    {
        var seed = SHA1.HashData(Encoding.ASCII.GetBytes("AnyOTPManager UI synthetic " + index));
        var env = Enumerable.Repeat((byte)'0', 26).ToArray(); env[14] = (byte)'0'; env[15] = (byte)'6';
        if (index == 0) { env[14] = (byte)'6'; env[15] = (byte)' '; }
        var template = new List<OtpRegistryValue> {
            new() { Name = "EnvInfo", Kind = OtpRegistryValueKind.Binary, Binary = env },
            new() { Name = "VMData", Kind = OtpRegistryValueKind.Binary, Binary = new byte[48] }
        };
        var values = OtpEngine.Rewrap(seed, template, FakeDisks.Source, "482619");
        var txt = Path.Combine(folder, "fixture-" + index + ".txt"); var reg = Path.Combine(folder, "fixture-" + index + ".reg");
        File.WriteAllBytes(txt, ProfileWriter.DiskFile(FakeDisks.Source)); File.WriteAllBytes(reg, ProfileWriter.RegistryFile(values));
        CryptographicOperations.ZeroMemory(seed); SecretBuffers.Clear(values); SecretBuffers.Clear(template);
        return (txt, reg);
    }
    private static void WriteIcon(string path)
    {
        var visual = new DrawingVisual();
        using (var d = visual.RenderOpen())
        {
            d.DrawRoundedRectangle(new SolidColorBrush(Color.FromRgb(16, 30, 51)), null, new Rect(0, 0, 128, 128), 25, 25);
            var outline = Geometry.Parse("M64,18 L103,32 L103,65 C103,87 82,106 64,115 C46,106 25,87 25,65 L25,32 Z");
            var mint = new SolidColorBrush(Color.FromRgb(83, 221, 210));
            d.DrawGeometry(null, new Pen(mint, 6), outline);
            d.DrawEllipse(null, new Pen(mint, 6), new Point(64, 57), 11, 11);
            d.DrawLine(new Pen(mint, 6), new Point(64, 68), new Point(64, 87));
        }
        var bitmap = new RenderTargetBitmap(128, 128, 96, 96, PixelFormats.Pbgra32); bitmap.Render(visual);
        var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(bitmap)); using var payload = new MemoryStream(); png.Save(payload);
        var bytes = payload.ToArray();
        using var file = File.Create(path); using var writer = new BinaryWriter(file);
        writer.Write((ushort)0); writer.Write((ushort)1); writer.Write((ushort)1);
        writer.Write((byte)128); writer.Write((byte)128); writer.Write((byte)0); writer.Write((byte)0);
        writer.Write((ushort)1); writer.Write((ushort)32); writer.Write(bytes.Length); writer.Write(22); writer.Write(bytes);
    }
}
internal sealed class FakeDisks : IDiskSource
{
    internal static DiskIdentity Source => new("SYNTHETIC\\DISK-IDENTITY-00000001", 0);
    internal static DiskIdentity Target => new("SYNTHETIC\\DISK-IDENTITY-00000002", 0xABCD1234);
    public IReadOnlyList<DiskChoice> List() => [new(0, "Disk 0 · Örnek yerel disk")];
    public DiskIdentity Read(int index) => Target;
}
internal sealed class MemoryRegistry : IRegistryStore
{
    public RegistrySnapshot State { get; private set; } = new();
    public int Writes { get; private set; }
    public RegistrySnapshot Read() => State.Clone();
    public void Write(RegistrySnapshot snapshot) { State.Dispose(); State = snapshot.Clone(); Writes++; }
}
internal sealed class BindingListener : TraceListener
{
    public int Errors { get; private set; }
    public override void Write(string? message) { if (message?.Contains("Error:") == true) Errors++; }
    public override void WriteLine(string? message) => Write(message);
}
