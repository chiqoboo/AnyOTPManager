using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AnyOTPManager.Core;
using AnyOTPManager.Windows;
using Microsoft.Win32;

namespace AnyOTPManager.App;

public abstract class FormDialog : Window
{
    protected readonly StackPanel Form = new();
    protected readonly Button Submit = new();
    protected readonly TextBlock Error = new() { TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.FromRgb(177, 65, 76)), Margin = new(0, 16, 0, 0) };
    protected readonly CancellationTokenSource Cancellation = new();
    private bool _busy, _closeAfter;
    protected FormDialog(string title, string description, string action)
    {
        Style = (Style)Application.Current.FindResource(typeof(Window));
        Title = title; Width = 540; SizeToContent = SizeToContent.Height; MaxHeight = SystemParameters.WorkArea.Height - 40;
        ResizeMode = ResizeMode.NoResize; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false; Background = Brushes.White;
        var container = new StackPanel { Margin = new(30) };
        container.Children.Add(new TextBlock { Text = title, FontSize = 25, FontWeight = FontWeights.SemiBold });
        container.Children.Add(new TextBlock { Text = description, Style = (Style)Application.Current.FindResource("MutedText"), Margin = new(0, 10, 0, 24) });
        container.Children.Add(Form); container.Children.Add(Error);
        var footer = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new(0, 24, 0, 0) };
        var cancel = new Button { Content = "Vazgeç", Margin = new(0, 0, 10, 0), IsCancel = false };
        cancel.Click += (_, _) => { if (_busy) { _closeAfter = true; Cancellation.Cancel(); Error.Text = "İşlem sonlandırılıyor…"; } else Close(); };
        Submit.Content = action; Submit.Style = (Style)Application.Current.FindResource("PrimaryButton"); Submit.IsDefault = true;
        Submit.Name = "SubmitButton"; Error.Name = "ErrorText";
        NameScope.SetNameScope(this, new NameScope());
        RegisterName("SubmitButton", Submit); RegisterName("ErrorText", Error);
        Submit.Click += async (_, _) =>
        {
            if (_busy) return;
            _busy = true; Form.IsEnabled = Submit.IsEnabled = false; Error.Text = "";
            try
            {
                await SubmitAsync(Cancellation.Token);
                _busy = false; DialogResult = true;
            }
            catch (Exception error) { Error.Text = UserErrors.Message(error); }
            finally
            {
                _busy = false; Form.IsEnabled = Submit.IsEnabled = true;
                if (_closeAfter && IsVisible) Close();
            }
        };
        footer.Children.Add(cancel); footer.Children.Add(Submit); container.Children.Add(footer);
        Content = new ScrollViewer { Content = container, Background = Brushes.White, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Closing += (_, e) => { if (_busy) { e.Cancel = true; _closeAfter = true; Cancellation.Cancel(); } };
        Closed += (_, _) => { Cancellation.Cancel(); };
        PreviewKeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Escape) { Close(); e.Handled = true; } };
    }
    protected T Field<T>(string label, T control, string name) where T : FrameworkElement
    {
        Form.Children.Add(new TextBlock { Text = label, FontWeight = FontWeights.SemiBold, Margin = new(0, 0, 0, 7) });
        control.Name = name; RegisterName(name, control); control.Margin = new(0, 0, 0, 18); Form.Children.Add(control); return control;
    }
    protected void Note(string text) => Form.Children.Add(new TextBlock
    { Text = text, Style = (Style)Application.Current.FindResource("MutedText"), FontSize = 12, Margin = new(0, 0, 0, 12) });
    protected abstract Task SubmitAsync(CancellationToken ct);
}

public sealed class ImportDialog : FormDialog
{
    private readonly OtpManager _manager;
    private readonly TextBox _alias, _txt, _reg;
    private readonly PasswordBox _pin;
    public ImportDialog(OtpManager manager) : base("OTP kaydı ekle", "Kendi AnyOTP yedeğinizi ekleyin. İçe aktarmada dosyaların mevcut PIN'i kullanılır.", "Kaydı ekle")
    {
        _manager = manager;
        _alias = Field("Kayıt adı (alias)", new TextBox { MaxLength = 64 }, "AliasInput");
        _txt = FileField("Cihaz bilgisi · TXT", "TXT dosyası|*.txt|Tüm dosyalar|*.*", "TxtPath");
        _reg = FileField("OTP kaydı · REG", "REG dosyası|*.reg", "RegPath");
        _pin = Field("Kaynak PIN · 6 rakam", new PasswordBox { MaxLength = 6, Password = Defaults.Pin }, "PinInput");
        Note("Dosyalarınız değiştirilmez. Ekledikten sonra kodlar PIN sorulmadan gösterilir.");
        AllowDrop = true;
        Drop += (_, e) =>
        {
            if (!Form.IsEnabled || !e.Data.GetDataPresent(DataFormats.FileDrop)) return;
            if (e.Data.GetData(DataFormats.FileDrop) is not string[] files || files.Length > 2) return;
            foreach (var file in files)
            { if (Path.GetExtension(file).Equals(".txt", StringComparison.OrdinalIgnoreCase)) _txt.Text = file;
              if (Path.GetExtension(file).Equals(".reg", StringComparison.OrdinalIgnoreCase)) _reg.Text = file; }
        };
        Loaded += (_, _) => _alias.Focus();
    }
    private TextBox FileField(string label, string filter, string name)
    {
        var row = new DockPanel();
        var button = new Button { Content = "Seç…", Margin = new(10, 0, 0, 0), Padding = new(14, 8, 14, 8) };
        DockPanel.SetDock(button, Dock.Right); row.Children.Add(button);
        var input = new TextBox { IsReadOnly = true, MinWidth = 100, ToolTip = "Dosya seçebilir veya TXT / REG çiftini pencereye sürükleyebilirsiniz." };
        RegisterName(name, input); row.Children.Add(input); Field(label, row, name + "Row");
        button.Click += (_, _) =>
        {
            var picker = new OpenFileDialog { Title = label, Filter = filter, CheckFileExists = true };
            if (picker.ShowDialog(this) == true) input.Text = picker.FileName;
        };
        return input;
    }
    protected override Task SubmitAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_txt.Text) || string.IsNullOrWhiteSpace(_reg.Text))
            throw new OtpException("TXT ve REG dosyalarını birlikte seçin.");
        return _manager.ImportAsync(_alias.Text, _txt.Text, _reg.Text, _pin.Password, ct);
    }
}

public sealed class LocalImportDialog : FormDialog
{
    private readonly OtpManager _manager;
    private readonly TextBox _alias;
    private readonly ComboBox _disks;
    private readonly PasswordBox _pin;

    public LocalImportDialog(OtpManager manager) : base("Bu bilgisayardan ekle",
        "Bu Windows hesabındaki AnyOTP kaydını mevcut PIN'iyle listenize ekleyin.", "Kaydı ekle")
    {
        _manager = manager;
        _alias = Field("Kayıt adı (alias)", new TextBox { MaxLength = 64 }, "AliasInput");
        _disks = Field("AnyOTP'nin kullandığı yerel disk", new ComboBox { DisplayMemberPath = "Label" }, "DiskInput");
        _pin = Field("Mevcut AnyOTP PIN'i · 6 rakam", new PasswordBox { MaxLength = 6, Password = Defaults.Pin }, "PinInput");
        Note("Disk bilgileri otomatik okunur. Birden fazla disk varsa AnyOTP'nin kurulduğu diski seçin.");
        Submit.IsEnabled = false;
        Loaded += async (_, _) =>
        {
            _alias.Focus();
            try
            {
                var disks = await _manager.DisksAsync(Cancellation.Token);
                _disks.ItemsSource = disks; _disks.SelectedIndex = 0;
                Submit.IsEnabled = disks.Count > 0;
                if (disks.Count == 0) Error.Text = "Bu bilgisayarda kullanılabilir disk bulunamadı.";
            }
            catch (Exception error) { Error.Text = UserErrors.Message(error); }
        };
    }

    protected override Task SubmitAsync(CancellationToken ct)
    {
        if (_disks.SelectedItem is not DiskChoice disk) throw new OtpException("AnyOTP'nin kullandığı yerel diski seçin.");
        return _manager.ImportFromComputerAsync(_alias.Text, disk, _pin.Password, ct);
    }
}

public sealed class PinDialog : FormDialog
{
    private readonly OtpManager _manager; private readonly Guid _id;
    private readonly PasswordBox _pin, _repeat;
    public PinDialog(OtpManager manager, Guid id, string alias) : base("PIN değiştir",
        $"“{alias}” kaydının PIN'ini güncelleyin. OTP anahtarı ve üretilen kodlar korunur.", "PIN'i kaydet")
    {
        _manager = manager; _id = id;
        _pin = Field("Yeni PIN · 6 rakam", new PasswordBox { Password = Defaults.Pin, MaxLength = 6 }, "NewPin");
        _repeat = Field("Yeni PIN tekrar", new PasswordBox { Password = Defaults.Pin, MaxLength = 6 }, "RepeatPin");
        Note("Varsayılan PIN: " + Defaults.Pin + "\nDeğişiklik bu kayıt için saklanır. Etkin AnyOTP kaydını güncellerken 'Bu bilgisayara aktar' ekranına yeni PIN'i girin.");
    }
    protected override Task SubmitAsync(CancellationToken ct)
    {
        if (_pin.Password != _repeat.Password) throw new OtpException("PIN alanları aynı olmalı.");
        return _manager.ChangePinAsync(_id, _pin.Password, ct);
    }
}

public sealed class RenameDialog : FormDialog
{
    private readonly OtpManager _manager; private readonly Guid _id; private readonly TextBox _alias;
    public RenameDialog(OtpManager manager, Guid id, string alias) : base("Kayıt adını düzenle", "Kayıtları kolayca ayırt etmek için bir ad verin.", "Kaydet")
    { _manager = manager; _id = id; _alias = Field("Kayıt adı", new TextBox { Text = alias, MaxLength = 64 }, "AliasInput"); Loaded += (_, _) => { _alias.Focus(); _alias.SelectAll(); }; }
    protected override Task SubmitAsync(CancellationToken ct) => _manager.RenameAsync(_id, _alias.Text, ct);
}

public sealed class TransferDialog : FormDialog
{
    private readonly OtpManager _manager; private readonly Guid _id;
    private readonly ComboBox _disks; private readonly PasswordBox _pin;
    public TransferDialog(OtpManager manager, Guid id, string alias) : base("Bu bilgisayara aktar",
        $"“{alias}” bu Windows kullanıcısının etkin AnyOTP kaydı olacak.", "Bu bilgisayara aktar")
    {
        _manager = manager; _id = id;
        _disks = Field("AnyOTP'nin kullanacağı yerel disk", new ComboBox { DisplayMemberPath = "Label" }, "DiskInput");
        _pin = Field("Bu bilgisayarda kullanılacak PIN", new PasswordBox { Password = Defaults.Pin, MaxLength = 6 }, "PinInput");
        Note("Varsayılan PIN: " + Defaults.Pin);
        var notice = new Border { Background = new SolidColorBrush(Color.FromRgb(240, 247, 246)), CornerRadius = new(8), Padding = new(15) };
        notice.Child = new TextBlock { Text = "AnyOTP'de aynı anda bir kayıt etkin olabilir. Mevcut kayıt yedeklenir ve seçtiğiniz kayıtla değiştirilir. Son aktarımı ana ekrandan geri alabilirsiniz.\n\nAktarmadan önce AnyOTP uygulamasını kapatın.",
            TextWrapping = TextWrapping.Wrap, LineHeight = 21, Foreground = new SolidColorBrush(Color.FromRgb(60, 96, 99)), FontSize = 13 };
        Form.Children.Add(notice); Submit.IsEnabled = false;
        Loaded += async (_, _) =>
        {
            try
            {
                var disks = await manager.DisksAsync(Cancellation.Token);
                _disks.ItemsSource = disks; _disks.SelectedIndex = 0; Submit.IsEnabled = disks.Count > 0;
            }
            catch (Exception error) { Error.Text = UserErrors.Message(error); }
        };
    }
    protected override async Task SubmitAsync(CancellationToken ct)
    {
        if (_disks.SelectedItem is not DiskChoice disk) throw new OtpException("Yerel disk seçin.");
        using var plan = await _manager.PrepareTransferAsync(_id, disk, _pin.Password, ct);
        await _manager.ApplyTransferAsync(plan, ct);
    }
}
