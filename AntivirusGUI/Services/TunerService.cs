using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using Microsoft.Win32;

namespace AntivirusGUI.Services;

/// <summary>
/// System tuner: startup program management, service monitoring,
/// performance counters, and system optimization.
/// </summary>
public class TunerService
{
    /// <summary>Get all startup programs from registry and startup folder</summary>
    public List<StartupEntry> GetStartupPrograms()
    {
        var entries = new List<StartupEntry>();

        // HKCU Run
        AddRegistryStartups(entries, Registry.CurrentUser,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Current User");

        // HKLM Run
        AddRegistryStartups(entries, Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "All Users");

        // HKCU RunOnce
        AddRegistryStartups(entries, Registry.CurrentUser,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Current User (Once)");

        // Startup folder
        var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (Directory.Exists(startupFolder))
        {
            foreach (var file in Directory.GetFiles(startupFolder))
            {
                entries.Add(new StartupEntry
                {
                    Name = Path.GetFileNameWithoutExtension(file),
                    Command = file,
                    Location = "Startup Folder",
                    IsEnabled = true,
                    Publisher = GetFilePublisher(file)
                });
            }
        }

        return entries;
    }

    /// <summary>Get system performance metrics</summary>
    public async Task<SystemMetrics> GetMetricsAsync()
    {
        var metrics = new SystemMetrics();

        await Task.Run(() =>
        {
            // CPU usage via WMI
            try
            {
                using var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // First call always returns 0
                Thread.Sleep(500);
                metrics.CpuUsage = Math.Round(cpuCounter.NextValue(), 1);
            }
            catch { metrics.CpuUsage = 0; }

            // RAM usage
            try
            {
                var gcInfo = GC.GetGCMemoryInfo();
                var totalMem = gcInfo.TotalAvailableMemoryBytes;
                var process = Process.GetCurrentProcess();

                using var ramCounter = new PerformanceCounter("Memory", "Available MBytes");
                var availMB = ramCounter.NextValue();
                var totalMB = totalMem / (1024.0 * 1024.0);
                metrics.TotalRamMB = totalMB;
                metrics.AvailableRamMB = availMB;
                metrics.RamUsage = Math.Round((1 - availMB / totalMB) * 100, 1);
            }
            catch { metrics.RamUsage = 0; }

            // Disk usage
            try
            {
                var drive = new DriveInfo("C");
                metrics.TotalDiskGB = drive.TotalSize / (1024.0 * 1024.0 * 1024.0);
                metrics.FreeDiskGB = drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
                metrics.DiskUsage = Math.Round((1 - metrics.FreeDiskGB / metrics.TotalDiskGB) * 100, 1);
            }
            catch { metrics.DiskUsage = 0; }

            // Running processes count
            metrics.ProcessCount = Process.GetProcesses().Length;
        });

        return metrics;
    }

    /// <summary>Get running services</summary>
    public List<ServiceEntry> GetServices()
    {
        var services = new List<ServiceEntry>();
        try
        {
            foreach (var sc in ServiceController.GetServices())
            {
                services.Add(new ServiceEntry
                {
                    Name = sc.ServiceName,
                    DisplayName = sc.DisplayName,
                    Status = sc.Status.ToString(),
                    StartType = GetServiceStartType(sc.ServiceName)
                });
            }
        }
        catch { }
        return services;
    }

    /// <summary>Disable a startup program</summary>
    public bool DisableStartupProgram(string name, string location)
    {
        try
        {
            if (location == "Startup Folder")
            {
                var folder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                var files = Directory.GetFiles(folder, $"{name}.*");
                foreach (var file in files)
                {
                    var disabledDir = Path.Combine(folder, ".disabled");
                    Directory.CreateDirectory(disabledDir);
                    File.Move(file, Path.Combine(disabledDir, Path.GetFileName(file)));
                }
                return true;
            }
            else
            {
                // Registry-based: rename the value
                var key = location.Contains("All Users")
                    ? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true)
                    : Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);

                if (key != null)
                {
                    var value = key.GetValue(name);
                    if (value != null)
                    {
                        // Store disabled entries in a backup key
                        var backupKey = Registry.CurrentUser.CreateSubKey(
                            @"SOFTWARE\SentinelAV\DisabledStartup");
                        backupKey.SetValue(name, value);
                        key.DeleteValue(name);
                        return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }

    /// <summary>Enable a previously disabled startup program</summary>
    public bool EnableStartupProgram(string name)
    {
        try
        {
            var backupKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\SentinelAV\DisabledStartup", true);
            if (backupKey != null)
            {
                var value = backupKey.GetValue(name);
                if (value != null)
                {
                    var runKey = Registry.CurrentUser.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                    runKey?.SetValue(name, value);
                    backupKey.DeleteValue(name);
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static void AddRegistryStartups(List<StartupEntry> entries, RegistryKey root, string path, string location)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            if (key == null) return;

            foreach (var name in key.GetValueNames())
            {
                entries.Add(new StartupEntry
                {
                    Name = name,
                    Command = key.GetValue(name)?.ToString() ?? "",
                    Location = location,
                    IsEnabled = true,
                    Publisher = ""
                });
            }
        }
        catch { }
    }

    private static string GetServiceStartType(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            var start = key?.GetValue("Start");
            return start switch
            {
                0 => "Boot",
                1 => "System",
                2 => "Automatic",
                3 => "Manual",
                4 => "Disabled",
                _ => "Unknown"
            };
        }
        catch { return "Unknown"; }
    }

    private static string GetFilePublisher(string filePath)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(filePath);
            return info.CompanyName ?? "";
        }
        catch { return ""; }
    }
}

public class StartupEntry
{
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string Location { get; set; } = "";
    public bool IsEnabled { get; set; }
    public string Publisher { get; set; } = "";
    public string Impact => Command.Length > 100 ? "High" : "Low";
}

public class SystemMetrics
{
    public double CpuUsage { get; set; }
    public double RamUsage { get; set; }
    public double DiskUsage { get; set; }
    public double TotalRamMB { get; set; }
    public double AvailableRamMB { get; set; }
    public double TotalDiskGB { get; set; }
    public double FreeDiskGB { get; set; }
    public int ProcessCount { get; set; }
}

public class ServiceEntry
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Status { get; set; } = "";
    public string StartType { get; set; } = "";
}
