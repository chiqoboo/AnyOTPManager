using System.Security.Principal;
using System.Windows;
using AnyOTPManager.Windows;

namespace AnyOTPManager.App;

public partial class App : Application
{
    private Mutex? _instance;
    private OtpManager? _manager;
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        _instance = new Mutex(true, @"Local\AnyOTPManager-" + sid, out var first);
        if (!first) { MessageBox.Show("AnyOTPManager zaten açık.", "AnyOTPManager"); Shutdown(); return; }
        var directory = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AnyOTPManager");
        _manager = new(directory);
        MainWindow = new MainWindow(_manager);
        MainWindow.Show();
    }
    protected override void OnExit(ExitEventArgs e)
    {
        _manager?.Dispose();
        _instance?.Dispose();
        base.OnExit(e);
    }
}
