using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;
using System.Text.Json;

namespace AntivirusGUI.Services;

/// <summary>
/// Audit report service: reads Windows Event Logs,
/// generates security audit reports in HTML format.
/// </summary>
public class AuditReportService
{
    private readonly string _reportDir;
    private readonly string _historyPath;

    public AuditReportService()
    {
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelAV");
        _reportDir = Path.Combine(appData, "Reports");
        _historyPath = Path.Combine(appData, "scan_history.json");
        Directory.CreateDirectory(_reportDir);
    }

    /// <summary>Record a scan in history</summary>
    public void RecordScan(ScanHistoryEntry entry)
    {
        var history = LoadHistory();
        history.Add(entry);
        SaveHistory(history);
    }

    /// <summary>Get scan history</summary>
    public List<ScanHistoryEntry> GetScanHistory()
    {
        return LoadHistory();
    }

    /// <summary>Get security events from Windows Event Log</summary>
    public List<SecurityEvent> GetSecurityEvents(int maxEvents = 100)
    {
        var events = new List<SecurityEvent>();

        try
        {
            // Query security log for key events
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4688 or EventID=4697 or EventID=4719 or EventID=4720 or EventID=4726)]]")
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(query);
            EventRecord? record;
            int count = 0;

            while ((record = reader.ReadEvent()) != null && count < maxEvents)
            {
                events.Add(new SecurityEvent
                {
                    EventId = record.Id,
                    TimeCreated = record.TimeCreated ?? DateTime.Now,
                    Description = GetEventDescription(record.Id),
                    Level = record.Level?.ToString() ?? "Info",
                    Source = record.ProviderName ?? ""
                });
                count++;
                record.Dispose();
            }
        }
        catch (Exception)
        {
            // Security log access may require admin
        }

        // Also check Application log for antivirus-related events
        try
        {
            var appQuery = new EventLogQuery("Application", PathType.LogName,
                "*[System[(Level=1 or Level=2)]]")
            {
                ReverseDirection = true
            };

            using var reader = new EventLogReader(appQuery);
            EventRecord? record;
            int count = 0;

            while ((record = reader.ReadEvent()) != null && count < 20)
            {
                events.Add(new SecurityEvent
                {
                    EventId = record.Id,
                    TimeCreated = record.TimeCreated ?? DateTime.Now,
                    Description = record.FormatDescription() ?? $"Event {record.Id}",
                    Level = record.Level == 1 ? "Critical" : "Error",
                    Source = record.ProviderName ?? ""
                });
                count++;
                record.Dispose();
            }
        }
        catch { }

        return events.OrderByDescending(e => e.TimeCreated).ToList();
    }

    /// <summary>Generate HTML audit report</summary>
    public async Task<string> GenerateReportAsync()
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
        var fileName = $"SentinelAV_Audit_{timestamp}.html";
        var filePath = Path.Combine(_reportDir, fileName);

        var history = LoadHistory();
        var events = GetSecurityEvents(50);

        var html = await Task.Run(() => BuildHtmlReport(history, events, timestamp));

        await File.WriteAllTextAsync(filePath, html);
        return filePath;
    }

    /// <summary>Get system information for report</summary>
    public Dictionary<string, string> GetSystemInfo()
    {
        var info = new Dictionary<string, string>
        {
            ["Computer Name"] = Environment.MachineName,
            ["User Name"] = Environment.UserName,
            ["OS Version"] = Environment.OSVersion.ToString(),
            [".NET Version"] = Environment.Version.ToString(),
            ["Processor Count"] = Environment.ProcessorCount.ToString(),
            ["System Directory"] = Environment.SystemDirectory,
            ["64-bit OS"] = Environment.Is64BitOperatingSystem.ToString(),
            ["System Uptime"] = TimeSpan.FromMilliseconds(Environment.TickCount64).ToString(@"dd\.hh\:mm\:ss")
        };
        return info;
    }

    private string BuildHtmlReport(List<ScanHistoryEntry> history,
        List<SecurityEvent> events, string timestamp)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head>");
        sb.AppendLine("<meta charset='utf-8'>");
        sb.AppendLine($"<title>Sentinel AV Audit Report — {timestamp}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { font-family: 'Inter', 'Segoe UI', sans-serif; background: #0D1B2A; color: #ECEFF4; margin: 40px; }");
        sb.AppendLine("h1 { color: #1B9AAA; } h2 { color: #8899AA; border-bottom: 1px solid #1E3048; padding-bottom: 8px; }");
        sb.AppendLine("table { width: 100%; border-collapse: collapse; margin: 16px 0; }");
        sb.AppendLine("th { background: #1B2838; color: #1B9AAA; padding: 10px; text-align: left; }");
        sb.AppendLine("td { padding: 8px 10px; border-bottom: 1px solid #162032; }");
        sb.AppendLine("tr:hover { background: #1E3048; }");
        sb.AppendLine(".card { background: #162032; border-radius: 12px; padding: 20px; margin: 16px 0; border: 1px solid #1E3048; }");
        sb.AppendLine(".stat { font-size: 28px; font-weight: bold; color: #1B9AAA; }");
        sb.AppendLine(".danger { color: #E74C3C; } .success { color: #2ECC71; } .warning { color: #F39C12; }");
        sb.AppendLine("</style></head><body>");

        // Header
        sb.AppendLine($"<h1>🛡️ Sentinel Antivirus — Audit Report</h1>");
        sb.AppendLine($"<p>Generated: {DateTime.Now:MMMM dd, yyyy HH:mm:ss}</p>");

        // System Info
        sb.AppendLine("<div class='card'><h2>System Information</h2><table>");
        foreach (var kvp in GetSystemInfo())
            sb.AppendLine($"<tr><td><strong>{kvp.Key}</strong></td><td>{kvp.Value}</td></tr>");
        sb.AppendLine("</table></div>");

        // Scan History
        sb.AppendLine("<div class='card'><h2>Scan History</h2>");
        if (history.Count > 0)
        {
            sb.AppendLine("<table><tr><th>Date</th><th>Type</th><th>Files</th><th>Threats</th><th>Duration</th></tr>");
            foreach (var scan in history.OrderByDescending(s => s.Date))
            {
                var threatClass = scan.ThreatsFound > 0 ? "danger" : "success";
                sb.AppendLine($"<tr><td>{scan.Date}</td><td>{scan.ScanType}</td><td>{scan.FilesScanned}</td>" +
                              $"<td class='{threatClass}'>{scan.ThreatsFound}</td><td>{scan.Duration}</td></tr>");
            }
            sb.AppendLine("</table>");
        }
        else
            sb.AppendLine("<p>No scan history available.</p>");
        sb.AppendLine("</div>");

        // Security Events
        sb.AppendLine("<div class='card'><h2>Security Events</h2>");
        if (events.Count > 0)
        {
            sb.AppendLine("<table><tr><th>Time</th><th>Event</th><th>Source</th><th>Level</th></tr>");
            foreach (var evt in events.Take(50))
            {
                var levelClass = evt.Level == "Critical" ? "danger" : evt.Level == "Error" ? "warning" : "";
                sb.AppendLine($"<tr><td>{evt.TimeCreated:yyyy-MM-dd HH:mm}</td><td>{evt.Description}</td>" +
                              $"<td>{evt.Source}</td><td class='{levelClass}'>{evt.Level}</td></tr>");
            }
            sb.AppendLine("</table>");
        }
        else
            sb.AppendLine("<p>No security events found (may require admin privileges).</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("<footer style='margin-top:40px; color:#556677; text-align:center;'>");
        sb.AppendLine("<p>Sentinel Antivirus Security Suite v1.0 — Audit Report</p>");
        sb.AppendLine("</footer></body></html>");

        return sb.ToString();
    }

    private static string GetEventDescription(int eventId) => eventId switch
    {
        4624 => "Successful logon",
        4625 => "Failed logon attempt",
        4648 => "Logon using explicit credentials",
        4688 => "New process created",
        4697 => "Service installed",
        4719 => "Audit policy changed",
        4720 => "User account created",
        4726 => "User account deleted",
        _ => $"Security event {eventId}"
    };

    private List<ScanHistoryEntry> LoadHistory()
    {
        try
        {
            if (File.Exists(_historyPath))
            {
                var json = File.ReadAllText(_historyPath);
                return JsonSerializer.Deserialize<List<ScanHistoryEntry>>(json) ?? new();
            }
        }
        catch { }
        return new();
    }

    private void SaveHistory(List<ScanHistoryEntry> history)
    {
        try
        {
            var json = JsonSerializer.Serialize(history, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_historyPath, json);
        }
        catch { }
    }
}

public class ScanHistoryEntry
{
    public string Date { get; set; } = "";
    public string ScanType { get; set; } = "";
    public int FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public string Duration { get; set; } = "";
}

public class SecurityEvent
{
    public int EventId { get; set; }
    public DateTime TimeCreated { get; set; }
    public string Description { get; set; } = "";
    public string Level { get; set; } = "";
    public string Source { get; set; } = "";
}
