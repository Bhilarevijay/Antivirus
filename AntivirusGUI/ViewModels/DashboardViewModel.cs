using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using AntivirusGUI.Services;

namespace AntivirusGUI.ViewModels;

public partial class DashboardViewModel : ViewModelBase
{
    private readonly ScanEngineService _engine;

    [ObservableProperty] private string _protectionStatus = "Initializing...";
    [ObservableProperty] private string _protectionStatusColor = "#F39C12";
    [ObservableProperty] private string _protectionDescription = "Checking engine status...";
    [ObservableProperty] private int _totalScanned;
    [ObservableProperty] private int _threatsBlocked;
    [ObservableProperty] private string _lastScanTime = "Never";
    [ObservableProperty] private int _signatureCount;
    [ObservableProperty] private string _gpuStatus = "Detecting...";
    [ObservableProperty] private double _systemHealth = 92;
    [ObservableProperty] private bool _engineAvailable;
    [ObservableProperty] private string _engineVersion = "";
    [ObservableProperty] private int _threadCount;
    [ObservableProperty] private int _quarantinedCount;

    /// <summary>Event to request navigation to Scan page from the MainViewModel</summary>
    public static event Action? NavigateToScanRequested;

    public DashboardViewModel()
    {
        _engine = new ScanEngineService();
        PageTitle = "Dashboard";
        PageIcon = "\uE80F";
        EngineAvailable = _engine.IsEngineAvailable;

        if (EngineAvailable)
            _ = LoadEngineStatusAsync();
        else
        {
            ProtectionStatus = "Engine Not Found";
            ProtectionStatusColor = "#E74C3C";
            ProtectionDescription = $"Engine not found. Expected at: {_engine.ResolvedEnginePath}";
            GpuStatus = "N/A";
            SignatureCount = 0;
        }
    }

    private async Task LoadEngineStatusAsync()
    {
        try
        {
            var status = await _engine.GetStatusAsync();
            SignatureCount = status.SignatureCount;
            ThreadCount = status.Threads;
            QuarantinedCount = status.QuarantinedFiles;
            GpuStatus = !string.IsNullOrEmpty(status.GpuName) ? status.GpuName : "CPU mode";

            if (status.IsReady)
            {
                ProtectionStatus = "Protected";
                ProtectionStatusColor = "#2ECC71";
                ProtectionDescription = $"All systems are secure. {ThreadCount} threads, {(status.GpuBackend == "CUDA" ? "CUDA GPU active" : "CPU mode")}.";
                SystemHealth = 95;
            }
            else
            {
                ProtectionStatus = "Engine not ready";
                ProtectionStatusColor = "#F39C12";
                ProtectionDescription = "Engine is initializing or encountered an error.";
            }

            if (SignatureCount == 0)
            {
                ProtectionDescription += " No signatures loaded — run Update.";
                SystemHealth = Math.Max(70, SystemHealth - 15);
            }

            // Get version
            try
            {
                var version = await _engine.GetVersionAsync();
                foreach (var line in version.Split('\n'))
                {
                    var clean = System.Text.RegularExpressions.Regex.Replace(line.Trim(), @"\x1B\[[0-9;]*m", "");
                    if (clean.StartsWith("Version:"))
                    {
                        EngineVersion = clean.Split(':')[1].Trim();
                        break;
                    }
                }
            }
            catch { }
        }
        catch (Exception ex)
        {
            ProtectionStatus = "Error";
            ProtectionStatusColor = "#E74C3C";
            ProtectionDescription = $"Failed to connect to engine: {ex.Message}";
            GpuStatus = $"Error: {ex.Message}";
        }
    }

    [RelayCommand]
    private void QuickScan()
    {
        // Set flag so ScanViewModel auto-starts a quick scan when created/navigated to
        ScanViewModel.AutoStartQuickScan = true;
        // Request navigation to Scan page
        NavigateToScanRequested?.Invoke();
    }

    [RelayCommand]
    private async Task UpdateSignatures()
    {
        IsBusy = true;
        SetStatus("Updating signatures...");
        try
        {
            var result = await _engine.UpdateSignaturesAsync();
            var clean = System.Text.RegularExpressions.Regex.Replace(result, @"\x1B\[[0-9;]*m", "");
            if (clean.Contains("complete", StringComparison.OrdinalIgnoreCase))
                SetStatus("Signatures updated successfully");
            else if (clean.Contains("failed", StringComparison.OrdinalIgnoreCase))
                SetStatus("Update failed — check internet");
            else
                SetStatus("Update finished");
            await LoadEngineStatusAsync();
        }
        catch (Exception ex) { SetStatus($"Error: {ex.Message}"); }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RefreshStatus()
    {
        IsBusy = true;
        await LoadEngineStatusAsync();
        IsBusy = false;
    }
}
