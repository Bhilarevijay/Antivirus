using System.Diagnostics;
using System.Management;

namespace AntivirusGUI.Services;

/// <summary>
/// USB device monitoring and control.
/// Uses PowerShell Disable-PnpDevice/Enable-PnpDevice for reliable device control.
/// These cmdlets use the same Windows APIs as Device Manager.
/// </summary>
public class UsbGuardService : IDisposable
{
    private ManagementEventWatcher? _insertWatcher;
    private ManagementEventWatcher? _removeWatcher;

    public event Action<UsbDeviceInfo>? OnDeviceInserted;
    public event Action<string>? OnDeviceRemoved;

    /// <summary>Start listening for USB device events via WMI</summary>
    public void StartMonitoring()
    {
        try
        {
            var insertQuery = new WqlEventQuery(
                "__InstanceCreationEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_USBControllerDevice'");

            _insertWatcher = new ManagementEventWatcher(insertQuery);
            _insertWatcher.EventArrived += (s, e) =>
            {
                var device = GetDeviceInfoFromEvent(e.NewEvent);
                if (device != null) OnDeviceInserted?.Invoke(device);
            };
            _insertWatcher.Start();

            var removeQuery = new WqlEventQuery(
                "__InstanceDeletionEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_USBControllerDevice'");

            _removeWatcher = new ManagementEventWatcher(removeQuery);
            _removeWatcher.EventArrived += (s, e) => OnDeviceRemoved?.Invoke("removed");
            _removeWatcher.Start();
        }
        catch { }
    }

    /// <summary>Get all currently connected USB devices with their status</summary>
    public List<UsbDeviceInfo> GetConnectedDevices()
    {
        var devices = new List<UsbDeviceInfo>();
        try
        {
            // Get USB PnP entities (excludes root hubs and host controllers)
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB\\\\%'");

            foreach (var obj in searcher.Get())
            {
                var name = obj["Description"]?.ToString()
                        ?? obj["Caption"]?.ToString()
                        ?? "USB Device";
                var devId = obj["PNPDeviceID"]?.ToString() ?? "";
                var status = obj["Status"]?.ToString() ?? "Unknown";
                var service = obj["Service"]?.ToString() ?? "";
                var devClass = obj["PNPClass"]?.ToString() ?? "";

                // Skip internal infrastructure
                if (name.Contains("Root Hub", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.Contains("Host Controller", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.IsNullOrEmpty(devId)) continue;

                // Determine if storage
                bool isStorage = service.Equals("USBSTOR", StringComparison.OrdinalIgnoreCase)
                              || devClass.Equals("DiskDrive", StringComparison.OrdinalIgnoreCase)
                              || name.Contains("Mass Storage", StringComparison.OrdinalIgnoreCase);

                devices.Add(new UsbDeviceInfo
                {
                    Name = name,
                    DeviceId = devId,
                    Status = status == "OK" ? "Connected" : (status == "Error" ? "Disabled" : status),
                    IsStorage = isStorage,
                    IsBlocked = status != "OK"
                });
            }

            // Also get USB disk drives specifically
            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
            foreach (var obj in diskSearcher.Get())
            {
                var devId = obj["PNPDeviceID"]?.ToString() ?? "";
                if (devices.Any(d => d.DeviceId == devId)) continue;

                devices.Add(new UsbDeviceInfo
                {
                    Name = obj["Caption"]?.ToString() ?? "USB Storage",
                    DeviceId = devId,
                    Size = Convert.ToInt64(obj["Size"] ?? 0),
                    Status = "Connected",
                    IsStorage = true,
                    IsBlocked = false
                });
            }
        }
        catch { }
        return devices;
    }

    /// <summary>Block ALL USB storage devices globally via USBSTOR registry</summary>
    public bool BlockUsbStorage()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\USBSTOR", true);
            if (key != null)
            {
                key.SetValue("Start", 4); // 4 = disabled
                return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>Unblock USB storage devices globally</summary>
    public bool UnblockUsbStorage()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\USBSTOR", true);
            if (key != null)
            {
                key.SetValue("Start", 3); // 3 = manual start (normal)
                return true;
            }
        }
        catch { }
        return false;
    }

    /// <summary>Disable a specific USB device using PowerShell Disable-PnpDevice</summary>
    public (bool Success, string Message) DisableDevice(string instanceId)
    {
        try
        {
            // Use PowerShell Disable-PnpDevice — same as Device Manager "Disable device"
            var (exitCode, output, error) = RunPowerShell(
                $"Disable-PnpDevice -InstanceId '{EscapeForPS(instanceId)}' -Confirm:$false");

            if (exitCode == 0 && string.IsNullOrEmpty(error))
                return (true, "Device disabled via PowerShell");

            // Check if it actually worked despite error text
            var (_, statusOut, _) = RunPowerShell(
                $"(Get-PnpDevice -InstanceId '{EscapeForPS(instanceId)}').Status");
            if (statusOut.Trim().Contains("Error") || statusOut.Trim().Contains("Disabled"))
                return (true, "Device disabled");

            return (false, $"Failed: {(string.IsNullOrEmpty(error) ? output : error).Trim()}");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    /// <summary>Enable a specific USB device using PowerShell Enable-PnpDevice</summary>
    public (bool Success, string Message) EnableDevice(string instanceId)
    {
        try
        {
            var (exitCode, output, error) = RunPowerShell(
                $"Enable-PnpDevice -InstanceId '{EscapeForPS(instanceId)}' -Confirm:$false");

            if (exitCode == 0 && string.IsNullOrEmpty(error))
                return (true, "Device enabled via PowerShell");

            // Check if it actually worked
            var (_, statusOut, _) = RunPowerShell(
                $"(Get-PnpDevice -InstanceId '{EscapeForPS(instanceId)}').Status");
            if (statusOut.Trim() == "OK")
                return (true, "Device enabled");

            return (false, $"Failed: {(string.IsNullOrEmpty(error) ? output : error).Trim()}");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    /// <summary>Check if a specific device is currently enabled</summary>
    public bool IsDeviceEnabled(string instanceId)
    {
        try
        {
            var (_, output, _) = RunPowerShell(
                $"(Get-PnpDevice -InstanceId '{EscapeForPS(instanceId)}').Status");
            return output.Trim() == "OK";
        }
        catch { return false; }
    }

    // ─── Helpers ───

    private static string EscapeForPS(string s) => s.Replace("'", "''");

    private static (int ExitCode, string Output, string Error) RunPowerShell(string command)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var proc = Process.Start(psi);
        if (proc == null) return (-1, "", "Failed to start PowerShell");
        var output = proc.StandardOutput.ReadToEnd();
        var error = proc.StandardError.ReadToEnd();
        proc.WaitForExit(15000);
        return (proc.ExitCode, output, error);
    }

    private static UsbDeviceInfo? GetDeviceInfoFromEvent(ManagementBaseObject? evt)
    {
        if (evt == null) return null;
        try
        {
            var target = evt["TargetInstance"] as ManagementBaseObject;
            var dependent = target?["Dependent"]?.ToString() ?? "";
            // Extract PnP device ID from WMI path
            var match = System.Text.RegularExpressions.Regex.Match(
                dependent, "DeviceID=\"(.+?)\"");
            var devId = match.Success ? match.Groups[1].Value.Replace("\\\\", "\\") : dependent;

            return new UsbDeviceInfo
            {
                DeviceId = devId,
                Name = "New USB Device",
                Status = "Connected"
            };
        }
        catch { return null; }
    }

    public void Dispose()
    {
        _insertWatcher?.Stop();
        _insertWatcher?.Dispose();
        _removeWatcher?.Stop();
        _removeWatcher?.Dispose();
    }
}

public class UsbDeviceInfo
{
    public string Name { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public long Size { get; set; }
    public string Status { get; set; } = "";
    public bool IsStorage { get; set; }
    public bool IsBlocked { get; set; }
}
