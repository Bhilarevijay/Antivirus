using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using System.IO;
using AntivirusGUI.Services;

namespace AntivirusGUI.ViewModels;

public partial class ScanViewModel : ViewModelBase
{
    private readonly ScanEngineService _engine;
    private readonly AuditReportService _reportService;
    private CancellationTokenSource? _scanCts;

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private double _scanProgress;
    [ObservableProperty] private string _scanStatus = "Ready to scan";
    [ObservableProperty] private int _filesScanned;
    [ObservableProperty] private int _threatsFound;
    [ObservableProperty] private string _currentFile = "";
    [ObservableProperty] private string _scanMode = "Quick";
    [ObservableProperty] private string _customPath = "";
    [ObservableProperty] private double _scanRate;
    [ObservableProperty] private bool _engineAvailable;

    public ObservableCollection<ThreatItem> Threats { get; } = new();

    /// <summary>Static flag set by DashboardViewModel to auto-start a quick scan on navigation</summary>
    public static bool AutoStartQuickScan { get; set; }

    public ScanViewModel()
    {
        _engine = new ScanEngineService();
        _reportService = new AuditReportService();
        PageTitle = "Scan";
        PageIcon = "\uE8B5";
        EngineAvailable = _engine.IsEngineAvailable;
        ScanStatus = _engine.IsEngineAvailable
            ? "Engine ready — select scan type"
            : $"Engine not found at: {_engine.ResolvedEnginePath}";

        // If auto-start was requested from Dashboard
        if (AutoStartQuickScan && EngineAvailable)
        {
            AutoStartQuickScan = false;
            _ = StartQuickScan();
        }
    }

    [RelayCommand]
    private async Task StartQuickScan()
    {
        if (IsScanning) return;
        ScanMode = "Quick";
        await RunScan("quick");
    }

    [RelayCommand]
    private async Task StartFullScan()
    {
        if (IsScanning) return;
        ScanMode = "Full";
        await RunScan("full");
    }

    [RelayCommand]
    private async Task StartCustomScan()
    {
        if (IsScanning) return;
        // ALWAYS show folder picker for custom scan
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select folder to scan",
            Multiselect = false
        };
        if (dialog.ShowDialog() == true)
        {
            CustomPath = dialog.FolderName;
            ScanMode = "Custom";
            await RunScan($"scan \"{CustomPath}\"");
        }
    }

    [RelayCommand]
    private void StopScan()
    {
        _scanCts?.Cancel();
        _engine.CancelScan();
        IsScanning = false;
        ScanStatus = "Scan cancelled";
    }

    private async Task RunScan(string command)
    {
        // Re-entrance guard
        if (IsScanning) return;

        if (!_engine.IsEngineAvailable)
        {
            ScanStatus = $"Error: Engine not found at {_engine.ResolvedEnginePath}";
            return;
        }

        IsScanning = true;
        ScanProgress = 0;
        FilesScanned = 0;
        ThreatsFound = 0;
        ScanRate = 0;
        Threats.Clear();
        ScanStatus = $"{ScanMode} scan in progress...";
        CurrentFile = "Initializing engine...";

        _scanCts = new CancellationTokenSource();

        // Subscribe to engine events
        _engine.OnProgress += OnEngineProgress;
        _engine.OnLogMessage += OnEngineLog;
        _engine.OnThreatDetected += OnThreatDetected;

        try
        {
            var startTime = DateTime.Now;
            var result = await _engine.RunScanAsync(command, _scanCts.Token);
            var duration = DateTime.Now - startTime;

            // Final stats from result
            FilesScanned = result.ScannedFiles;
            ThreatsFound = result.InfectedFiles;
            ScanRate = result.ScanRate;
            ScanProgress = 100;

            // Add any threats that came from results but weren't caught by event
            foreach (var threat in result.Threats)
            {
                var exists = false;
                foreach (var t in Threats) { if (t.FullPath == threat.FilePath) { exists = true; break; } }
                if (!exists)
                {
                    System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        Threats.Add(new ThreatItem
                        {
                            FileName = Path.GetFileName(threat.FilePath),
                            ThreatName = threat.ThreatName,
                            Severity = "High",
                            Action = "Quarantined",
                            FullPath = threat.FilePath
                        });
                    });
                }
            }

            // Record in audit history
            try
            {
                _reportService.RecordScan(new ScanHistoryEntry
                {
                    Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
                    ScanType = ScanMode,
                    FilesScanned = FilesScanned,
                    ThreatsFound = ThreatsFound,
                    Duration = !string.IsNullOrEmpty(result.Duration)
                        ? result.Duration
                        : duration.TotalSeconds < 60
                            ? $"{duration.TotalSeconds:F1}s"
                            : duration.ToString(@"mm\:ss")
                });
            }
            catch { }

            ScanStatus = result.WasCancelled
                ? "Scan cancelled"
                : $"{ScanMode} scan complete — {FilesScanned:N0} files, {ThreatsFound} threats ({ScanRate:F0} files/sec)";

            if (!string.IsNullOrEmpty(result.Error))
                ScanStatus += $" ({result.Error})";
        }
        catch (Exception ex)
        {
            ScanStatus = $"Scan error: {ex.Message}";
        }
        finally
        {
            // ALWAYS unsubscribe to prevent handler accumulation
            _engine.OnProgress -= OnEngineProgress;
            _engine.OnLogMessage -= OnEngineLog;
            _engine.OnThreatDetected -= OnThreatDetected;

            ScanProgress = 100;
            CurrentFile = "";
            IsScanning = false;
        }
    }

    private void OnEngineProgress(ScanProgress progress)
    {
        System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
        {
            FilesScanned = progress.ScannedFiles;
            ThreatsFound = progress.InfectedFiles;
            ScanRate = progress.ScanRate;

            // Smart progress estimation when TotalFiles is unknown
            if (progress.TotalFiles > 0 && progress.TotalFiles > progress.ScannedFiles)
            {
                ScanProgress = progress.Percentage;
            }
            else
            {
                // Logarithmic curve: approaches 99% as files scanned increases
                double estimated = 99.0 * (1.0 - Math.Exp(-progress.ScannedFiles / 5000.0));
                ScanProgress = Math.Max(1, Math.Min(99, estimated));
            }
        });
    }

    private void OnEngineLog(string message)
    {
        System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
        {
            CurrentFile = message.Length > 120 ? message[..117] + "..." : message;
        });
    }

    private void OnThreatDetected(ThreatInfo threat)
    {
        System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
        {
            Threats.Add(new ThreatItem
            {
                FileName = Path.GetFileName(threat.FilePath),
                ThreatName = threat.ThreatName,
                Severity = "High",
                Action = "Quarantined",
                FullPath = threat.FilePath
            });
            ThreatsFound = Threats.Count;
        });
    }
}

public class ThreatItem
{
    public string FileName { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Action { get; set; } = "Quarantined";
    public string FullPath { get; set; } = "";
}
