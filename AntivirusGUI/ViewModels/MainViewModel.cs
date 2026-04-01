using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusGUI.ViewModels;

public partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private ViewModelBase _currentViewModel;

    [ObservableProperty]
    private string _currentPageName = "Dashboard";

    [ObservableProperty]
    private bool _isProtectionEnabled = true;

    // Lazy-loaded page ViewModels — only created when navigated to
    private DashboardViewModel? _dashboard;
    private ScanViewModel? _scan;
    private ProtectionViewModel? _protection;
    private UsbGuardViewModel? _usbGuard;
    private WebShieldViewModel? _webShield;
    private CleanerViewModel? _cleaner;
    private TunerViewModel? _tuner;
    private ReportsViewModel? _reports;
    private QuarantineViewModel? _quarantine;
    private SettingsViewModel? _settings;

    public MainViewModel()
    {
        _dashboard = new DashboardViewModel();
        _currentViewModel = _dashboard;

        // Listen for Dashboard's request to navigate to Scan
        DashboardViewModel.NavigateToScanRequested += () =>
        {
            System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
            {
                // Force recreate ScanViewModel so it picks up AutoStartQuickScan flag
                _scan = new ScanViewModel();
                Navigate("Scan");
            });
        };
    }

    [RelayCommand]
    private void Navigate(string page)
    {
        CurrentPageName = page;
        try
        {
            CurrentViewModel = page switch
            {
                "Dashboard" => _dashboard ??= new DashboardViewModel(),
                "Scan" => _scan ??= new ScanViewModel(),
                "Protection" => _protection ??= new ProtectionViewModel(),
                "USB Guard" => _usbGuard ??= new UsbGuardViewModel(),
                "Web Shield" => _webShield ??= new WebShieldViewModel(),
                "Cleaner" => _cleaner ??= new CleanerViewModel(),
                "Tuner" => _tuner ??= new TunerViewModel(),
                "Reports" => _reports ??= new ReportsViewModel(),
                "Quarantine" => _quarantine ??= new QuarantineViewModel(),
                "Settings" => _settings ??= new SettingsViewModel(),
                _ => _dashboard ??= new DashboardViewModel()
            };
        }
        catch (Exception)
        {
            // If a ViewModel fails to create, stay on dashboard
            CurrentViewModel = _dashboard ??= new DashboardViewModel();
            CurrentPageName = "Dashboard";
        }
    }
}
