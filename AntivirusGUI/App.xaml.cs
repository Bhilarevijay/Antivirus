using System.Diagnostics;
using System.Windows;

namespace AntivirusGUI;

public partial class App : Application
{
    private bool _isShowingError;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Global exception handler — prevent cascading error dialogs
        DispatcherUnhandledException += (s, args) =>
        {
            args.Handled = true; // Always handle to prevent crash

            // Prevent infinite dialog cascade
            if (_isShowingError) return;
            _isShowingError = true;

            try
            {
                Debug.WriteLine($"[Sentinel] Unhandled: {args.Exception}");
                MessageBox.Show($"An error occurred:\n{args.Exception.Message}",
                    "Sentinel Antivirus", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                _isShowingError = false;
            }
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                Debug.WriteLine($"[Sentinel] Fatal: {ex}");
                if (!_isShowingError)
                {
                    _isShowingError = true;
                    MessageBox.Show($"Fatal error:\n{ex.Message}",
                        "Sentinel Antivirus", MessageBoxButton.OK, MessageBoxImage.Error);
                    _isShowingError = false;
                }
            }
        };

        TaskScheduler.UnobservedTaskException += (s, args) =>
        {
            args.SetObserved(); // Prevent crash from unobserved task exceptions
            Debug.WriteLine($"[Sentinel] Unobserved task: {args.Exception}");
        };

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Kill ALL child antivirus.exe processes launched by this app
        try
        {
            foreach (var proc in Process.GetProcessesByName("antivirus"))
            {
                try
                {
                    proc.Kill(true); // true = kill entire process tree
                    proc.Dispose();
                }
                catch { }
            }
        }
        catch { }

        base.OnExit(e);
    }
}
