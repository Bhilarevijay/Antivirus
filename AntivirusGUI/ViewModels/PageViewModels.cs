using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using AntivirusGUI.Services;

namespace AntivirusGUI.ViewModels;

public partial class ProtectionViewModel : ViewModelBase
{
    private readonly ScanEngineService _engine;

    [ObservableProperty] private bool _realTimeProtection = true;
    [ObservableProperty] private bool _autoQuarantine = true;
    [ObservableProperty] private bool _scanDownloads = true;
    [ObservableProperty] private bool _scanUsb = true;
    [ObservableProperty] private bool _cloudLookup;
    [ObservableProperty] private string _engineStatus = "Checking...";

    public ProtectionViewModel()
    {
        _engine = new ScanEngineService();
        PageTitle = "Protection";
        PageIcon = "\uE72E";
        _ = LoadStatus();
    }

    private async Task LoadStatus()
    {
        try
        {
            if (!_engine.IsEngineAvailable)
            {
                EngineStatus = "Engine not found";
                return;
            }
            var status = await _engine.GetStatusAsync();
            EngineStatus = status.IsReady
                ? $"Running — {status.Threads} threads, {status.SignatureCount} signatures"
                : "Not ready";
        }
        catch { EngineStatus = "Error checking status"; }
    }

    partial void OnRealTimeProtectionChanged(bool value)
    {
        SetStatus(value ? "Real-time protection enabled" : "Real-time protection disabled");
    }

    partial void OnAutoQuarantineChanged(bool value)
    {
        SetStatus(value ? "Auto quarantine enabled" : "Auto quarantine disabled");
    }
}

// ═══════════════════════════════════════════
// USB GUARD
// ═══════════════════════════════════════════
public partial class UsbGuardViewModel : ViewModelBase
{
    private UsbGuardService? _usb;

    [ObservableProperty] private bool _usbBlockingEnabled;
    [ObservableProperty] private bool _autoBlockNew;

    public ObservableCollection<UsbDeviceItem> Devices { get; } = new();

    public UsbGuardViewModel()
    {
        PageTitle = "USB Guard";
        PageIcon = "\uE88E";
        _ = InitAsync();
    }

    private async Task InitAsync()
    {
        try
        {
            await Task.Run(() =>
            {
                _usb = new UsbGuardService();

                _usb.OnDeviceInserted += device =>
                {
                    Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        Devices.Add(new UsbDeviceItem
                        {
                            Name = device.Name,
                            DeviceId = device.DeviceId,
                            Status = "Connected",
                            IsStorage = device.IsStorage
                        });
                        SetStatus($"New device: {device.Name}");
                    });
                };

                _usb.OnDeviceRemoved += msg =>
                {
                    Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        SetStatus("A USB device was removed");
                        _ = RefreshDevices();
                    });
                };

                _usb.StartMonitoring();

                var devices = _usb.GetConnectedDevices();
                Application.Current?.Dispatcher?.Invoke(() =>
                {
                    foreach (var d in devices)
                    {
                        Devices.Add(new UsbDeviceItem
                        {
                            Name = d.Name,
                            DeviceId = d.DeviceId,
                            Status = d.Status,
                            IsStorage = d.IsStorage
                        });
                    }
                    SetStatus($"Found {Devices.Count} USB devices");
                });
            });
        }
        catch (Exception ex)
        {
            SetStatus($"USB init failed: {ex.Message}");
        }
    }

    partial void OnUsbBlockingEnabledChanged(bool value)
    {
        try
        {
            if (value) _usb?.BlockUsbStorage();
            else _usb?.UnblockUsbStorage();
            SetStatus(value ? "USB storage blocked globally" : "USB storage unblocked globally");
        }
        catch { SetStatus("Requires admin privileges"); }
    }

    [RelayCommand]
    private async Task ToggleDevice(UsbDeviceItem? device)
    {
        if (device == null || _usb == null) return;
        IsBusy = true;
        try
        {
            if (device.IsBlocked)
            {
                // Enable the device
                var (success, msg) = await Task.Run(() => _usb.EnableDevice(device.DeviceId));
                if (success)
                {
                    device.IsBlocked = false;
                    device.Status = "Connected";
                    SetStatus($"✅ Enabled: {device.Name} — {msg}");
                }
                else
                    SetStatus($"❌ Failed: {msg}");
            }
            else
            {
                // Disable the device
                var (success, msg) = await Task.Run(() => _usb.DisableDevice(device.DeviceId));
                if (success)
                {
                    device.IsBlocked = true;
                    device.Status = "Disabled";
                    SetStatus($"🔒 Disabled: {device.Name} — {msg}");
                }
                else
                    SetStatus($"❌ Failed: {msg}");
            }
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RefreshDevices()
    {
        try
        {
            SetStatus("Refreshing...");
            Devices.Clear();
            await Task.Run(() =>
            {
                var devices = _usb?.GetConnectedDevices() ?? new();
                Application.Current?.Dispatcher?.Invoke(() =>
                {
                    foreach (var d in devices)
                        Devices.Add(new UsbDeviceItem
                        {
                            Name = d.Name,
                            DeviceId = d.DeviceId,
                            Status = d.Status,
                            IsStorage = d.IsStorage,
                            IsBlocked = d.Status == "Disabled"
                        });
                    SetStatus($"Found {Devices.Count} USB devices");
                });
            });
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
    }
}

public class UsbDeviceItem : ObservableObject
{
    private bool _isBlocked;
    private string _status = "Connected";
    public string Name { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public bool IsStorage { get; set; }
    public string Status { get => _status; set => SetProperty(ref _status, value); }
    public bool IsBlocked { get => _isBlocked; set => SetProperty(ref _isBlocked, value); }
}

// ═══════════════════════════════════════════
// WEB SHIELD
// ═══════════════════════════════════════════
public partial class WebShieldViewModel : ViewModelBase
{
    private readonly WebShieldService _webService;

    [ObservableProperty] private bool _webShieldEnabled = true;
    [ObservableProperty] private string _newUrl = "";

    public ObservableCollection<string> BlockedSites { get; } = new();
    public ObservableCollection<string> BlockedApps { get; } = new();

    public WebShieldViewModel()
    {
        _webService = new WebShieldService();
        PageTitle = "Web Shield";
        PageIcon = "\uE774";

        try
        {
            foreach (var site in _webService.GetBlockedWebsites()) BlockedSites.Add(site);
            foreach (var app in _webService.GetBlockedApps()) BlockedApps.Add(app);
        }
        catch (Exception ex) { SetStatus($"Load error: {ex.Message}"); }

        SetStatus($"{BlockedSites.Count} sites, {BlockedApps.Count} apps blocked");
    }

    [RelayCommand]
    private void AddBlockedSite()
    {
        if (string.IsNullOrWhiteSpace(NewUrl)) return;
        var domain = NewUrl.Trim().Replace("http://", "").Replace("https://", "")
                          .Replace("www.", "").Trim('/').ToLower();
        if (string.IsNullOrEmpty(domain)) return;

        if (!BlockedSites.Contains(domain))
        {
            try
            {
                var (success, msg) = _webService.BlockWebsite(domain);
                if (success)
                {
                    BlockedSites.Add(domain);
                    SetStatus($"✅ {msg}");
                }
                else
                    SetStatus($"❌ {msg}");
            }
            catch { SetStatus("Requires Administrator privileges"); }
        }
        NewUrl = "";
    }

    [RelayCommand]
    private void RemoveBlockedSite(string? site)
    {
        if (site == null) return;
        try
        {
            var (_, msg) = _webService.UnblockWebsite(site);
            SetStatus($"✅ {msg}");
        }
        catch { }
        BlockedSites.Remove(site);
    }

    [RelayCommand]
    private void AddBlockedApp()
    {
        // Open file picker for .exe selection
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select application to block network access",
            Filter = "Applications (*.exe)|*.exe|All files (*.*)|*.*",
            Multiselect = false
        };
        if (dialog.ShowDialog() == true)
        {
            var exePath = dialog.FileName;
            if (BlockedApps.Contains(exePath)) return;

            try
            {
                var (success, msg) = _webService.BlockApp(exePath);
                if (success)
                {
                    BlockedApps.Add(exePath);
                    SetStatus($"🔒 {msg}");
                }
                else
                    SetStatus($"❌ {msg}");
            }
            catch { SetStatus("Requires Administrator privileges"); }
        }
    }

    [RelayCommand]
    private void RemoveBlockedApp(string? app)
    {
        if (app == null) return;
        try
        {
            var (_, msg) = _webService.UnblockApp(app);
            SetStatus($"✅ {msg}");
        }
        catch { }
        BlockedApps.Remove(app);
    }
}

// ═══════════════════════════════════════════
// SYSTEM CLEANER
// ═══════════════════════════════════════════
public partial class CleanerViewModel : ViewModelBase
{
    private readonly CleanerService _cleaner;

    [ObservableProperty] private bool _isCleaning;
    [ObservableProperty] private long _tempFilesSize;
    [ObservableProperty] private long _recycleBinSize;
    [ObservableProperty] private long _browserCacheSize;
    [ObservableProperty] private long _totalCleanable;
    [ObservableProperty] private long _freedSpace;
    [ObservableProperty] private bool _cleanTemp = true;
    [ObservableProperty] private bool _cleanRecycle = true;
    [ObservableProperty] private bool _cleanBrowserCache;

    public CleanerViewModel()
    {
        _cleaner = new CleanerService();
        PageTitle = "System Cleaner";
        PageIcon = "\uE74D";
        // Auto-run analysis on page load
        _ = Analyze();
    }

    [RelayCommand]
    private async Task Analyze()
    {
        IsBusy = true;
        SetStatus("Analyzing system...");
        try
        {
            var analysis = await _cleaner.AnalyzeAsync();
            TempFilesSize = analysis.TempFiles + analysis.WindowsTempFiles;
            RecycleBinSize = analysis.RecycleBinSize;
            BrowserCacheSize = analysis.BrowserCacheSize;
            TotalCleanable = analysis.TotalCleanable;
            SetStatus($"Found {FormatSize(TotalCleanable)} cleanable data");
        }
        catch (Exception ex)
        {
            SetStatus($"Error: {ex.Message}");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task Clean()
    {
        if (!CleanTemp && !CleanRecycle && !CleanBrowserCache)
        {
            SetStatus("Select at least one category to clean");
            return;
        }

        IsCleaning = true;
        SetStatus("Cleaning...");
        try
        {
            var result = await _cleaner.CleanAsync(CleanTemp, CleanRecycle, CleanBrowserCache);
            FreedSpace = result.TotalCleaned;
            SetStatus($"Freed {FormatSize(FreedSpace)}");
            await Analyze(); // Re-scan after cleaning
        }
        catch (Exception ex)
        {
            SetStatus($"Error: {ex.Message}");
        }
        finally { IsCleaning = false; }
    }

    public static string FormatSize(long bytes)
    {
        if (bytes >= 1073741824) return $"{bytes / 1073741824.0:F1} GB";
        if (bytes >= 1048576) return $"{bytes / 1048576.0:F1} MB";
        if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
    }
}

// ═══════════════════════════════════════════
// SYSTEM TUNER
// ═══════════════════════════════════════════
public partial class TunerViewModel : ViewModelBase
{
    private TunerService? _tuner;

    [ObservableProperty] private double _cpuUsage;
    [ObservableProperty] private double _ramUsage;
    [ObservableProperty] private double _diskUsage;

    public ObservableCollection<StartupItem> StartupItems { get; } = new();

    public TunerViewModel()
    {
        PageTitle = "System Tuner";
        PageIcon = "\uE713";
        _ = LoadDataAsync();
    }

    private async Task LoadDataAsync()
    {
        IsBusy = true;
        try
        {
            _tuner = new TunerService();

            // Get metrics on background
            var metrics = await _tuner.GetMetricsAsync();
            CpuUsage = metrics.CpuUsage;
            RamUsage = metrics.RamUsage;
            DiskUsage = metrics.DiskUsage;

            // Load startup items
            var items = await Task.Run(() => _tuner.GetStartupPrograms());
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                StartupItems.Clear();
                foreach (var entry in items)
                {
                    StartupItems.Add(new StartupItem
                    {
                        Name = entry.Name,
                        Publisher = entry.Publisher,
                        Impact = entry.Impact,
                        IsEnabled = entry.IsEnabled
                    });
                }
                SetStatus($"{StartupItems.Count} startup programs, CPU: {CpuUsage:F0}%, RAM: {RamUsage:F0}%");
            });
        }
        catch (Exception ex)
        {
            SetStatus($"Error loading: {ex.Message}");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task Optimize()
    {
        if (_tuner == null) return;
        IsBusy = true;
        SetStatus("Optimizing system...");
        try
        {
            // Disable high-impact startup items
            int disabled = 0;
            foreach (var item in StartupItems)
            {
                if (item.Impact == "High" && item.IsEnabled)
                {
                    if (_tuner.DisableStartupProgram(item.Name, "Current User"))
                    {
                        item.IsEnabled = false;
                        disabled++;
                    }
                }
            }
            SetStatus(disabled > 0
                ? $"Disabled {disabled} high-impact startup items"
                : "No high-impact items to optimize");

            await LoadDataAsync();
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
        finally { IsBusy = false; }
    }
}

public class StartupItem : ObservableObject
{
    private bool _isEnabled = true;
    public string Name { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string Impact { get; set; } = "Low";
    public bool IsEnabled { get => _isEnabled; set => SetProperty(ref _isEnabled, value); }
}

// ═══════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════
public partial class ReportsViewModel : ViewModelBase
{
    private readonly AuditReportService _reportService;

    public ObservableCollection<ReportItem> ScanHistory { get; } = new();

    public ReportsViewModel()
    {
        _reportService = new AuditReportService();
        PageTitle = "Reports";
        PageIcon = "\uE9F9";
        try { LoadHistory(); } catch { }
    }

    private void LoadHistory()
    {
        var history = _reportService.GetScanHistory();
        ScanHistory.Clear();
        foreach (var entry in history)
        {
            ScanHistory.Add(new ReportItem
            {
                Date = entry.Date,
                ScanType = entry.ScanType,
                FilesScanned = entry.FilesScanned,
                ThreatsFound = entry.ThreatsFound,
                Duration = entry.Duration
            });
        }
        SetStatus($"{ScanHistory.Count} scan records");
    }

    [RelayCommand]
    private async Task GenerateAuditReport()
    {
        IsBusy = true;
        SetStatus("Generating audit report...");
        try
        {
            var path = await _reportService.GenerateReportAsync();
            SetStatus($"Report saved: {Path.GetFileName(path)}");
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            SetStatus($"Error: {ex.Message}");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task ExportReport()
    {
        IsBusy = true;
        SetStatus("Exporting...");
        try
        {
            var path = await _reportService.GenerateReportAsync();
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export Audit Report",
                Filter = "HTML Report|*.html|All Files|*.*",
                FileName = Path.GetFileName(path),
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };
            if (dlg.ShowDialog() == true)
            {
                File.Copy(path, dlg.FileName, true);
                SetStatus($"Exported to: {dlg.FileName}");
            }
            else
                SetStatus("Export cancelled");
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private void Refresh()
    {
        try
        {
            LoadHistory();
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
    }
}

public class ReportItem
{
    public string Date { get; set; } = "";
    public string ScanType { get; set; } = "";
    public int FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public string Duration { get; set; } = "";
}

// ═══════════════════════════════════════════
// QUARANTINE
// ═══════════════════════════════════════════
public partial class QuarantineViewModel : ViewModelBase
{
    private readonly ScanEngineService _engine;
    public ObservableCollection<QuarantinedFile> Files { get; } = new();

    public QuarantineViewModel()
    {
        _engine = new ScanEngineService();
        PageTitle = "Quarantine";
        PageIcon = "\uE7BA";
        _ = LoadQuarantineAsync();
    }

    private async Task LoadQuarantineAsync()
    {
        try
        {
            if (!_engine.IsEngineAvailable) { SetStatus("Engine not found"); return; }
            IsBusy = true;
            var entries = await _engine.GetQuarantineListAsync();
            Application.Current?.Dispatcher?.Invoke(() =>
            {
                Files.Clear();
                foreach (var e in entries)
                {
                    Files.Add(new QuarantinedFile
                    {
                        Id = e.Id,
                        Name = Path.GetFileName(e.OriginalPath),
                        ThreatName = e.ThreatName,
                        OriginalPath = e.OriginalPath,
                        Size = e.Size,
                        QuarantinedDate = DateTime.Now.ToString("yyyy-MM-dd")
                    });
                }
                SetStatus($"{Files.Count} quarantined files");
            });
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RestoreFile(QuarantinedFile? file)
    {
        if (file == null) return;
        try
        {
            var success = await _engine.RestoreQuarantinedFileAsync(file.Id);
            if (success)
            {
                Files.Remove(file);
                SetStatus($"Restored: {file.Name}");
            }
            else SetStatus("Restore failed");
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
    }

    [RelayCommand]
    private async Task DeleteFile(QuarantinedFile? file)
    {
        if (file == null) return;
        try
        {
            var success = await _engine.DeleteQuarantinedFileAsync(file.Id);
            if (success)
            {
                Files.Remove(file);
                SetStatus($"Deleted: {file.Name}");
            }
            else SetStatus("Delete failed");
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
    }

    [RelayCommand]
    private async Task Refresh() => await LoadQuarantineAsync();
}

public class QuarantinedFile
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public string QuarantinedDate { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public long Size { get; set; }
}

// ═══════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════
public partial class SettingsViewModel : ViewModelBase
{
    [ObservableProperty] private bool _darkMode = true;
    [ObservableProperty] private bool _autoUpdate = true;
    [ObservableProperty] private bool _startWithWindows;
    [ObservableProperty] private bool _minimizeToTray = true;
    [ObservableProperty] private int _scanThreads = 16;

    public ObservableCollection<string> Exclusions { get; } = new();

    private readonly string _settingsPath;

    public SettingsViewModel()
    {
        PageTitle = "Settings";
        PageIcon = "\uE115";

        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelAV");
        Directory.CreateDirectory(appData);
        _settingsPath = Path.Combine(appData, "settings.json");

        LoadSettings();
    }

    partial void OnDarkModeChanged(bool value)
    {
        ApplyTheme(value);
        SaveSettings();
        SetStatus(value ? "Dark mode enabled" : "Light mode enabled");
    }

    partial void OnStartWithWindowsChanged(bool value)
    {
        try
        {
            var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
            if (key != null)
            {
                if (value)
                    key.SetValue("SentinelAV", $"\"{Environment.ProcessPath}\"");
                else
                    key.DeleteValue("SentinelAV", false);
            }
            SetStatus(value ? "Will start with Windows" : "Removed from startup");
        }
        catch { SetStatus("Failed — requires permissions"); }
        SaveSettings();
    }

    partial void OnAutoUpdateChanged(bool value) => SaveSettings();
    partial void OnMinimizeToTrayChanged(bool value) => SaveSettings();
    partial void OnScanThreadsChanged(int value) => SaveSettings();

    [RelayCommand]
    private void AddExclusion()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select folder to exclude from scanning"
        };
        if (dialog.ShowDialog() == true)
        {
            if (!Exclusions.Contains(dialog.FolderName))
            {
                Exclusions.Add(dialog.FolderName);
                SetStatus($"Excluded: {dialog.FolderName}");
                SaveSettings();
            }
        }
    }

    [RelayCommand]
    private void RemoveExclusion(string? path)
    {
        if (path != null)
        {
            Exclusions.Remove(path);
            SetStatus($"Removed exclusion: {Path.GetFileName(path)}");
            SaveSettings();
        }
    }

    /// <summary>Apply light or dark theme by replacing brush resources.
    /// All XAML uses DynamicResource, so replacing the brush triggers a full UI refresh.</summary>
    private static void ApplyTheme(bool isDark)
    {
        var app = Application.Current;
        if (app == null) return;

        var colorMap = isDark ? new Dictionary<string, string>
        {
            ["BgPrimaryColor"] = "#FF0D1B2A",
            ["BgSecondaryColor"] = "#FF1B2838",
            ["BgCardColor"] = "#FF162032",
            ["BgHoverColor"] = "#FF1E3048",
            ["BgInputColor"] = "#FF0F2033",
            ["TextPrimaryColor"] = "#FFECEFF4",
            ["TextSecondaryColor"] = "#FF8899AA",
            ["TextMutedColor"] = "#FF556677",
        }
        : new Dictionary<string, string>
        {
            ["BgPrimaryColor"] = "#FFF0F2F5",
            ["BgSecondaryColor"] = "#FFFFFFFF",
            ["BgCardColor"] = "#FFFFFFFF",
            ["BgHoverColor"] = "#FFE8ECF0",
            ["BgInputColor"] = "#FFF5F7FA",
            ["TextPrimaryColor"] = "#FF1A1A2E",
            ["TextSecondaryColor"] = "#FF5A6A7A",
            ["TextMutedColor"] = "#FF8899AA",
        };

        // Replace Color and Brush resources directly in the App resource dictionary.
        // DynamicResource in XAML will automatically pick up the new values.
        foreach (var kvp in colorMap)
        {
            var color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(kvp.Value);

            // Replace the Color resource
            app.Resources[kvp.Key] = color;

            // Replace the Brush resource with a new unfrozen brush
            var brushKey = kvp.Key.Replace("Color", "Brush");
            app.Resources[brushKey] = new System.Windows.Media.SolidColorBrush(color);
        }

        // Replace sidebar gradient
        var sidebarGrad = new System.Windows.Media.LinearGradientBrush
        {
            StartPoint = new System.Windows.Point(0, 0),
            EndPoint = new System.Windows.Point(0, 1)
        };
        if (isDark)
        {
            sidebarGrad.GradientStops.Add(new System.Windows.Media.GradientStop(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF0A1628"), 0));
            sidebarGrad.GradientStops.Add(new System.Windows.Media.GradientStop(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF0D1B2A"), 1));
        }
        else
        {
            sidebarGrad.GradientStops.Add(new System.Windows.Media.GradientStop(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FFE2E6EA"), 0));
            sidebarGrad.GradientStops.Add(new System.Windows.Media.GradientStop(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FFF0F2F5"), 1));
        }
        app.Resources["SidebarGradientBrush"] = sidebarGrad;

        // Update the main Window background
        if (app.MainWindow != null)
        {
            var bgColor = isDark ? "#FF0D1B2A" : "#FFF0F2F5";
            app.MainWindow.Background = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(bgColor));
        }
    }

    private void LoadSettings()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = File.ReadAllText(_settingsPath);
                var s = JsonSerializer.Deserialize<SettingsData>(json);
                if (s != null)
                {
#pragma warning disable MVVMTK0034 // Direct field access is intentional during load
                    _darkMode = s.DarkMode;
                    _autoUpdate = s.AutoUpdate;
                    _startWithWindows = s.StartWithWindows;
                    _minimizeToTray = s.MinimizeToTray;
                    _scanThreads = s.ScanThreads > 0 ? s.ScanThreads : 16;
#pragma warning restore MVVMTK0034
                    foreach (var ex in s.Exclusions ?? new()) Exclusions.Add(ex);

                    // Notify UI of loaded values
                    OnPropertyChanged(nameof(DarkMode));
                    OnPropertyChanged(nameof(AutoUpdate));
                    OnPropertyChanged(nameof(StartWithWindows));
                    OnPropertyChanged(nameof(MinimizeToTray));
                    OnPropertyChanged(nameof(ScanThreads));
                }
            }
        }
        catch { }
    }

    private void SaveSettings()
    {
        try
        {
            var data = new SettingsData
            {
                DarkMode = DarkMode,
                AutoUpdate = AutoUpdate,
                StartWithWindows = StartWithWindows,
                MinimizeToTray = MinimizeToTray,
                ScanThreads = ScanThreads,
                Exclusions = new List<string>(Exclusions)
            };
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_settingsPath, json);
        }
        catch { }
    }
}

internal class SettingsData
{
    public bool DarkMode { get; set; } = true;
    public bool AutoUpdate { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public int ScanThreads { get; set; } = 16;
    public List<string> Exclusions { get; set; } = new();
}
