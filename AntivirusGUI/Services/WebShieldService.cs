using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace AntivirusGUI.Services;

/// <summary>
/// Website and application network blocking.
/// Website blocking: hosts file + Windows Firewall outbound rules + DNS flush.
/// App blocking: Windows Firewall outbound rules to block network access.
/// </summary>
public class WebShieldService
{
    private const string HOSTS_PATH = @"C:\Windows\System32\drivers\etc\hosts";
    private const string SENTINEL_MARKER = "# Sentinel Antivirus Web Shield";
    private const string RULE_PREFIX = "Sentinel_web_";
    private const string APP_RULE_PREFIX = "Sentinel_app_";
    private readonly string _configPath;

    public WebShieldService()
    {
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelAV");
        Directory.CreateDirectory(appData);
        _configPath = Path.Combine(appData, "webshield.json");
    }

    // ═══════════════════════════════════════════
    // WEBSITE BLOCKING
    // ═══════════════════════════════════════════

    /// <summary>Block a website using hosts file + Windows Firewall + DNS flush</summary>
    public (bool Success, string Message) BlockWebsite(string domain)
    {
        try
        {
            domain = NormalizeDomain(domain);
            if (string.IsNullOrEmpty(domain))
                return (false, "Invalid domain");

            bool hostsOk = AddToHostsFile(domain);
            bool firewallOk = AddFirewallRule(domain);
            FlushDnsCache();

            SaveBlockedSite(domain);

            if (hostsOk && firewallOk)
                return (true, $"Blocked {domain} (hosts + firewall + DNS flushed)");
            else if (hostsOk)
                return (true, $"Blocked {domain} (hosts file + DNS flushed)");
            else if (firewallOk)
                return (true, $"Blocked {domain} (firewall rule added)");
            else
                return (false, "Failed — run as Administrator");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    /// <summary>Unblock a website — remove from hosts file + firewall + flush DNS</summary>
    public (bool Success, string Message) UnblockWebsite(string domain)
    {
        try
        {
            domain = NormalizeDomain(domain);
            if (string.IsNullOrEmpty(domain))
                return (false, "Invalid domain");

            RemoveFromHostsFile(domain);
            RemoveFirewallRule(domain);
            FlushDnsCache();
            RemoveBlockedSite(domain);

            return (true, $"Unblocked {domain} (hosts + firewall + DNS flushed)");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    /// <summary>Get all currently blocked websites</summary>
    public List<string> GetBlockedWebsites()
    {
        return LoadConfig().BlockedSites;
    }

    // ═══════════════════════════════════════════
    // APPLICATION BLOCKING (Network Access)
    // ═══════════════════════════════════════════

    /// <summary>Block an application's network access using Windows Firewall</summary>
    public (bool Success, string Message) BlockApp(string exePath)
    {
        try
        {
            if (!File.Exists(exePath))
                return (false, $"File not found: {exePath}");

            var appName = Path.GetFileNameWithoutExtension(exePath);
            var ruleName = $"{APP_RULE_PREFIX}{appName}";

            // Add outbound firewall rule blocking this app
            var outResult = RunNetsh(
                $"advfirewall firewall add rule name=\"{ruleName}_out\" " +
                $"dir=out action=block program=\"{exePath}\" " +
                $"enable=yes profile=any");

            // Also add inbound rule
            var inResult = RunNetsh(
                $"advfirewall firewall add rule name=\"{ruleName}_in\" " +
                $"dir=in action=block program=\"{exePath}\" " +
                $"enable=yes profile=any");

            bool ok = outResult.Contains("Ok", StringComparison.OrdinalIgnoreCase);

            if (ok)
            {
                var config = LoadConfig();
                if (!config.BlockedApps.Contains(exePath))
                {
                    config.BlockedApps.Add(exePath);
                    SaveConfig(config);
                }
                return (true, $"Blocked network access for {appName}");
            }
            return (false, $"Firewall rule failed: {outResult.Trim()}");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    /// <summary>Unblock an application's network access</summary>
    public (bool Success, string Message) UnblockApp(string exePath)
    {
        try
        {
            var appName = Path.GetFileNameWithoutExtension(exePath);
            var ruleName = $"{APP_RULE_PREFIX}{appName}";

            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}_out\"");
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}_in\"");

            var config = LoadConfig();
            config.BlockedApps.Remove(exePath);
            SaveConfig(config);

            return (true, $"Unblocked network access for {appName}");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    /// <summary>Get blocked applications</summary>
    public List<string> GetBlockedApps()
    {
        return LoadConfig().BlockedApps;
    }

    // ═══════════════════════════════════════════
    // PRIVATE — Hosts File Operations
    // ═══════════════════════════════════════════

    private bool AddToHostsFile(string domain)
    {
        try
        {
            var lines = File.Exists(HOSTS_PATH) ? File.ReadAllLines(HOSTS_PATH).ToList() : new();

            // Check if already blocked
            if (lines.Any(l => l.Contains(domain) && l.Contains("0.0.0.0")))
                return true;

            if (!lines.Contains(SENTINEL_MARKER))
                lines.Add(SENTINEL_MARKER);

            lines.Add($"0.0.0.0 {domain}");
            lines.Add($"0.0.0.0 www.{domain}");

            File.WriteAllLines(HOSTS_PATH, lines);
            return true;
        }
        catch { return false; }
    }

    private void RemoveFromHostsFile(string domain)
    {
        try
        {
            if (!File.Exists(HOSTS_PATH)) return;

            var lines = File.ReadAllLines(HOSTS_PATH)
                .Where(l => !l.Contains(domain))
                .ToList();

            // Clean up empty Sentinel marker
            if (lines.Contains(SENTINEL_MARKER))
            {
                var idx = lines.IndexOf(SENTINEL_MARKER);
                bool hasEntries = lines.Skip(idx + 1).Any(l => l.StartsWith("0.0.0.0"));
                if (!hasEntries) lines.Remove(SENTINEL_MARKER);
            }

            File.WriteAllLines(HOSTS_PATH, lines);
        }
        catch { }
    }

    // ═══════════════════════════════════════════
    // PRIVATE — Windows Firewall Operations
    // ═══════════════════════════════════════════

    private bool AddFirewallRule(string domain)
    {
        try
        {
            var ruleName = $"{RULE_PREFIX}{domain.Replace(".", "_")}";
            var result = RunNetsh(
                $"advfirewall firewall add rule name=\"{ruleName}\" " +
                $"dir=out action=block remotehost={domain} " +
                $"enable=yes profile=any");

            // Also block www subdomain
            RunNetsh(
                $"advfirewall firewall add rule name=\"{ruleName}_www\" " +
                $"dir=out action=block remotehost=www.{domain} " +
                $"enable=yes profile=any");

            return result.Contains("Ok", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private void RemoveFirewallRule(string domain)
    {
        try
        {
            var ruleName = $"{RULE_PREFIX}{domain.Replace(".", "_")}";
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\"");
            RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}_www\"");
        }
        catch { }
    }

    // ═══════════════════════════════════════════
    // PRIVATE — Utilities
    // ═══════════════════════════════════════════

    private static string NormalizeDomain(string domain)
    {
        return domain.Replace("http://", "").Replace("https://", "")
                     .Replace("www.", "").Trim('/').Trim().ToLower();
    }

    private static void FlushDnsCache()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ipconfig",
                Arguments = "/flushdns",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
        }
        catch { }
    }

    private static string RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return "";
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);
            return output;
        }
        catch { return ""; }
    }

    private void SaveBlockedSite(string domain)
    {
        var config = LoadConfig();
        if (!config.BlockedSites.Contains(domain))
        {
            config.BlockedSites.Add(domain);
            SaveConfig(config);
        }
    }

    private void RemoveBlockedSite(string domain)
    {
        var config = LoadConfig();
        config.BlockedSites.Remove(domain);
        SaveConfig(config);
    }

    private WebShieldConfig LoadConfig()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                var json = File.ReadAllText(_configPath);
                return JsonSerializer.Deserialize<WebShieldConfig>(json) ?? new();
            }
        }
        catch { }
        return new WebShieldConfig();
    }

    private void SaveConfig(WebShieldConfig config)
    {
        try
        {
            var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_configPath, json);
        }
        catch { }
    }
}

public class WebShieldConfig
{
    public List<string> BlockedSites { get; set; } = new();
    public List<string> BlockedApps { get; set; } = new();
}
