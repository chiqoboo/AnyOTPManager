using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using AnyOTPManager.Core;
using AnyOTPManager.Windows;
using Microsoft.Win32;

namespace AnyOTPManager.App;

public partial class MainWindow : Window
{
    private readonly OtpManager _manager;
    private readonly Action<string>? _copyOverride;
    private readonly ObservableCollection<EntryCard> _cards = [];
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly CancellationTokenSource _closing = new();
    private bool _refreshing, _ready, _busy, _closingRequested;
    private string? _copied;
    private DateTimeOffset _clipboardExpiry;
    public MainWindow(OtpManager manager, Action<string>? copyOverride = null)
    {
        InitializeComponent(); _manager = manager; _copyOverride = copyOverride;
        Cards.ItemsSource = _cards;
        CollectionViewSource.GetDefaultView(_cards).Filter = item => item is EntryCard card &&
            card.Alias.Contains(SearchBox.Text, StringComparison.CurrentCultureIgnoreCase);
        Loaded += async (_, _) =>
        {
            try
            {
                await _manager.InitializeAsync(_closing.Token); _ready = true;
                await RefreshAsync(); SetStatus("Hazır · Kodlar PIN sorulmadan otomatik yenilenir.");
                _timer.Start();
            }
            catch (Exception error) { SetStatus(UserErrors.Message(error), true); }
            AddButton.IsEnabled = SidebarLocalAddButton.IsEnabled = SidebarAddButton.IsEnabled = EmptyAddButton.IsEnabled = _ready;
        };
        _timer.Tick += async (_, _) => { await RefreshAsync(); ClearExpiredClipboard(); };
        Closing += Window_Closing;
        Closed += (_, _) => { _timer.Stop(); _closing.Cancel(); ClearOwnClipboard(); };
    }

    public async Task RefreshAsync()
    {
        if (!_ready || _refreshing || _busy || _closing.IsCancellationRequested) return;
        _refreshing = true;
        try
        {
            var view = await _manager.ViewAsync(DateTimeOffset.UtcNow, _closing.Token);
            var selected = (Cards.SelectedItem as EntryCard)?.Id;
            var ids = view.Entries.Select(e => e.Id).ToHashSet();
            foreach (var old in _cards.Where(c => !ids.Contains(c.Id)).ToArray()) _cards.Remove(old);
            foreach (var entry in view.Entries)
            {
                var card = _cards.FirstOrDefault(c => c.Id == entry.Id);
                if (card is null) { card = new(entry); _cards.Add(card); } else card.Update(entry);
            }
            SidebarCount.Text = _cards.Count.ToString();
            CountLabel.Text = $"{_cards.Count} kayıt · Otomatik yenileme";
            RestoreButton.Visibility = view.CanRestore ? Visibility.Visible : Visibility.Collapsed;
            if (view.HasPending) SetStatus("Tamamlanmamış aktarım var. 'Aktarımı geri al' ile önceki kaydı geri yükleyin.", true);
            if (Cards.SelectedItem is null) Cards.SelectedItem = _cards.FirstOrDefault(c => c.Id == selected) ?? _cards.FirstOrDefault();
            UpdateEmpty();
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            // Never leave old OTPs looking current after a failed refresh (for example an invalid system clock).
            foreach (var card in _cards) card.Invalidate();
            SetStatus(UserErrors.Message(error), true);
        }
        finally { _refreshing = false; }
    }

    private void Search_Changed(object sender, TextChangedEventArgs e)
    {
        if (Cards is null || SearchHint is null) return;
        SearchHint.Visibility = string.IsNullOrEmpty(SearchBox.Text) ? Visibility.Visible : Visibility.Collapsed;
        CollectionViewSource.GetDefaultView(_cards).Refresh(); UpdateEmpty();
    }
    private void UpdateEmpty()
    {
        var noMatches = Cards.Items.Count == 0;
        EmptyState.Visibility = noMatches ? Visibility.Visible : Visibility.Collapsed;
        EmptyTitle.Text = _cards.Count == 0 ? "İlk OTP kaydınızı ekleyin" : "Eşleşen kayıt bulunamadı";
        EmptyDescription.Text = _cards.Count == 0 ? "Bu bilgisayardaki AnyOTP kaydını veya TXT ve REG dosyalarınızı ekleyin. Kodlarınız burada otomatik yenilenir." : "Farklı bir kayıt adıyla tekrar arayın.";
        EmptyAddButton.Visibility = _cards.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }
    private void Cards_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DetailPanel is null) return;
        var card = Cards.SelectedItem as EntryCard;
        DetailPanel.DataContext = card;
        DetailPanel.Visibility = card is null ? Visibility.Collapsed : Visibility.Visible;
        DetailEmpty.Visibility = card is null ? Visibility.Visible : Visibility.Collapsed;
    }
    private EntryCard? Selected => Cards.SelectedItem as EntryCard;
    private async void Add_Click(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closing.IsCancellationRequested) return;
        var dialog = new ImportDialog(_manager) { Owner = this };
        if (dialog.ShowDialog() == true) { SetStatus("Kayıt eklendi. Güncel kodunuz hazır."); await RefreshAsync(); }
    }
    private async void AddLocal_Click(object sender, RoutedEventArgs e)
    {
        if (!_ready || _busy || _closing.IsCancellationRequested) return;
        if (new LocalImportDialog(_manager) { Owner = this }.ShowDialog() == true)
        { SetStatus("Bu bilgisayardaki AnyOTP kaydı listeye eklendi."); await RefreshAsync(); }
    }
    private async void Pin_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } card) return;
        if (new PinDialog(_manager, card.Id, card.Alias) { Owner = this }.ShowDialog() == true)
        { SetStatus("Kayıt PIN'i değiştirildi. Aktif AnyOTP kaydına uygulamak için yeniden aktarın."); await RefreshAsync(); }
    }
    private async void Rename_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } card) return;
        if (new RenameDialog(_manager, card.Id, card.Alias) { Owner = this }.ShowDialog() == true)
        { await RefreshAsync(); CollectionViewSource.GetDefaultView(_cards).Refresh(); SetStatus("Kayıt adı güncellendi."); }
    }
    private async void Transfer_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } card) return;
        if (new TransferDialog(_manager, card.Id, card.Alias) { Owner = this }.ShowDialog() == true)
            SetStatus("Kayıt bu bilgisayara aktarıldı ve yeniden okunarak doğrulandı.");
        await RefreshAsync();
    }
    private async void Copy_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } selected) return;
        try
        {
            var view = await _manager.ViewAsync(DateTimeOffset.UtcNow, _closing.Token);
            var code = view.Entries.Single(e => e.Id == selected.Id).Otp.Code;
            if (_copyOverride is not null) _copyOverride(code);
            else { Clipboard.SetText(code); _copied = code; _clipboardExpiry = DateTimeOffset.UtcNow.AddSeconds(20); }
            SetStatus("Kod kopyalandı. Pano 20 saniye sonra temizlenir.");
        }
        catch (Exception error) { SetStatus(UserErrors.Message(error), true); }
    }
    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } card) return;
        var picker = new OpenFolderDialog { Title = "TXT ve REG dosyalarının kaydedileceği klasör" };
        if (picker.ShowDialog(this) != true) return;
        await DoAsync(async () => { await _manager.ExportAsync(card.Id, picker.FolderName, _closing.Token); SetStatus("TXT ve REG dosyaları seçilen klasörün içindeki yeni klasöre kaydedildi."); });
    }
    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } card) return;
        if (MessageBox.Show(this, $"“{card.Alias}” listeden kaldırılsın mı?\nKaynak dosyalar ve bilgisayardaki etkin AnyOTP kaydı korunur.",
            "Kaydı kaldır", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await DoAsync(async () => { await _manager.DeleteAsync(card.Id, _closing.Token); SetStatus("Kayıt listeden kaldırıldı."); });
    }
    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Son aktarım öncesindeki AnyOTP kaydı bu bilgisayarda geri yüklensin mi?",
            "Aktarımı geri al", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await DoAsync(async () => { await _manager.RestoreTransferAsync(_closing.Token); SetStatus("Önceki AnyOTP kaydı geri yüklendi ve doğrulandı."); });
    }
    private void Folder_Click(object sender, RoutedEventArgs e)
    {
        try { Directory.CreateDirectory(_manager.DataDirectory); Process.Start(new ProcessStartInfo(_manager.DataDirectory) { UseShellExecute = true }); }
        catch { SetStatus("Kayıt klasörü açılamadı.", true); }
    }
    private async Task DoAsync(Func<Task> action)
    {
        if (_busy) return;
        _busy = true; DetailPanel.IsEnabled = AddButton.IsEnabled = SidebarLocalAddButton.IsEnabled = SidebarAddButton.IsEnabled = EmptyAddButton.IsEnabled = RestoreButton.IsEnabled = false;
        try { await action(); }
        catch (OperationCanceledException) { SetStatus("İşlem iptal edildi."); }
        catch (Exception error) { SetStatus(UserErrors.Message(error), true); }
        finally
        {
            _busy = false; DetailPanel.IsEnabled = AddButton.IsEnabled = SidebarLocalAddButton.IsEnabled = SidebarAddButton.IsEnabled = EmptyAddButton.IsEnabled = RestoreButton.IsEnabled = true;
            if (_closingRequested) Close(); else await RefreshAsync();
        }
    }
    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _closing.Cancel();
        if (_busy) { e.Cancel = true; _closingRequested = true; SetStatus("İşlem güvenle tamamlanıyor…"); }
    }
    private void SetStatus(string text, bool error = false)
    {
        StatusText.Text = text;
        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(error ? "#B0444E" : "#5A6D80"));
    }
    private void ClearExpiredClipboard() { if (_copied is not null && DateTimeOffset.UtcNow >= _clipboardExpiry) ClearOwnClipboard(); }
    private void ClearOwnClipboard()
    {
        try { if (_copied is not null && Clipboard.ContainsText() && Clipboard.GetText() == _copied) Clipboard.Clear(); }
        catch { /* A locked clipboard belongs to another application; never overwrite it. */ }
        finally { _copied = null; }
    }
}

public sealed class EntryCard : INotifyPropertyChanged
{
    private EntryView _view;
    private bool _valid = true;
    public EntryCard(EntryView view) => _view = view;
    public Guid Id => _view.Id;
    public string Alias => _view.Alias;
    public string Initial => Alias[..1].ToUpperInvariant();
    public string FormattedCode => !_valid ? "— — —" : _view.Otp.Code.Insert(_view.Otp.Code.Length / 2, " ");
    public string Countdown => _valid ? $"{_view.Otp.SecondsRemaining} sn" : "—";
    public string CountdownDescription => _valid ? $"{_view.Otp.SecondsRemaining} saniye sonra yenilenir" : "Saat kontrolü gerekiyor";
    public string Description => $"{_view.Digits} hane · {_view.StepSeconds} saniyede bir";
    public double Progress => _valid ? _view.Otp.RemainingFraction * 100 : 0;
    public void Update(EntryView view) { _view = view; _valid = true; PropertyChanged?.Invoke(this, new(null)); }
    public void Invalidate() { _valid = false; PropertyChanged?.Invoke(this, new(null)); }
    public event PropertyChangedEventHandler? PropertyChanged;
}

public static class UserErrors
{
    public static string Message(Exception error) => error switch
    {
        OtpException => error.Message,
        InvalidDataException => "Dosya biçimi desteklenmiyor. AnyOTP TXT ve REG dosyalarını seçin.",
        FileNotFoundException => "Seçilen dosya artık bulunamıyor.",
        UnauthorizedAccessException => "Dosya veya kayıt erişimi reddedildi. Bu Windows hesabının erişim izinlerini kontrol edin.",
        OperationCanceledException => "İşlem iptal edildi.",
        _ => "İşlem tamamlanamadı. Dosyaları, erişim izinlerini ve seçiminizi kontrol edin."
    };
}
