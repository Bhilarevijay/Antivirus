using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace AntivirusGUI.Services;

/// <summary>
/// Integrates with the C++ antivirus engine (antivirus.exe) via subprocess.
/// Matches the exact CLI:
///   Commands: quick, full, scan <path>, status, update, quarantine list/restore/delete, version
///   Progress: \r[X scanned | Y infected | Z files/sec]
///   Results:  Total files: N, Scanned: N, Infected: N, Duration: N ms, Scan rate: N files/sec
///   Threats:  ⚠️  THREAT DETECTED: <name> in <path>
///   Status:   Ready: Yes/No, Signatures loaded: N, Thread pool threads: N, GPU: ..., Quarantined files: N
/// </summary>
public class ScanEngineService
{
    private readonly string _enginePath;
    private Process? _activeProcess;
    private CancellationTokenSource? _cts;

    public event Action<ScanProgress>? OnProgress;
    public event Action<string>? OnLogMessage;
    public event Action<ThreatInfo>? OnThreatDetected;

    /// <summary>The resolved path to the engine (for debugging)</summary>
    public string ResolvedEnginePath => _enginePath;

    public ScanEngineService()
    {
        // Build a list of candidate paths, ordered by likelihood
        var candidates = new List<string>();

        // 1. Same directory as the actual running .exe (works for published single-file)
        var processDir = Path.GetDirectoryName(Environment.ProcessPath ?? "");
        if (!string.IsNullOrEmpty(processDir))
            candidates.Add(Path.Combine(processDir, "antivirus.exe"));

        // 2. BaseDirectory (works for debug/non-single-file)
        candidates.Add(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "antivirus.exe"));

        // 3. Navigate from BaseDirectory to project build output
        //    During dev: BaseDirectory = ...AntivirusGUI\bin\Debug\net8.0-windows\
        //    Engine lives at: ...S\build\bin\Release\antivirus.exe
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        // Walk up to the solution root (S folder)
        var dir = baseDir;
        for (int i = 0; i < 8 && dir != null; i++)
        {
            dir = Path.GetDirectoryName(dir);
            if (dir != null)
            {
                var buildPath = Path.Combine(dir, "build", "bin", "Release", "antivirus.exe");
                if (!candidates.Contains(buildPath))
                    candidates.Add(buildPath);
            }
        }

        // 4. Hardcoded workspace path (absolute fallback)
        candidates.Add(@"c:\Users\bhila\Desktop\S\build\bin\Release\antivirus.exe");

        // 5. Publish directory
        candidates.Add(@"c:\Users\bhila\Desktop\S\publish\antivirus.exe");

        _enginePath = candidates.FirstOrDefault(File.Exists) ?? candidates[0];

        // Log which path was resolved (visible in debug output)
        System.Diagnostics.Debug.WriteLine($"[ScanEngine] Resolved engine path: {_enginePath}");
        System.Diagnostics.Debug.WriteLine($"[ScanEngine] Engine available: {File.Exists(_enginePath)}");
    }

    public bool IsEngineAvailable => File.Exists(_enginePath);

    /// <summary>Run a scan: "quick", "full", or "scan C:\path"</summary>
    public async Task<ScanResult> RunScanAsync(string command, CancellationToken ct = default)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        var result = new ScanResult();

        var psi = new ProcessStartInfo
        {
            FileName = _enginePath,
            Arguments = command,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_enginePath) ?? ""
        };

        try
        {
            _activeProcess = Process.Start(psi);
            if (_activeProcess == null)
            {
                result.Error = "Failed to start engine process";
                return result;
            }

            // Read output using synchronous read on a background thread.
            // This avoids the "stream in use" race condition from concurrent ReadAsync calls.
            var buffer = new char[4096];
            var lineBuffer = new System.Text.StringBuilder();
            var stream = _activeProcess.StandardOutput;

            // Read synchronously on a background thread — no race conditions possible
            await Task.Run(() =>
            {
                try
                {
                    int read;
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (token.IsCancellationRequested) break;

                        for (int i = 0; i < read; i++)
                        {
                            char c = buffer[i];
                            if (c == '\r' || c == '\n')
                            {
                                var line = lineBuffer.ToString().Trim();
                                if (!string.IsNullOrEmpty(line))
                                {
                                    var clean = StripAnsi(line);
                                    ParseLine(clean, result);
                                    OnLogMessage?.Invoke(clean);
                                }
                                lineBuffer.Clear();
                            }
                            else
                            {
                                lineBuffer.Append(c);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception) { } // Stream closed
            }, token);

            // Process remaining buffer
            var leftover = lineBuffer.ToString().Trim();
            if (!string.IsNullOrEmpty(leftover))
            {
                var clean = StripAnsi(leftover);
                ParseLine(clean, result);
            }

            // Wait for process exit (with timeout)
            if (!_activeProcess.HasExited)
            {
                try
                {
                    using var exitCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                    await _activeProcess.WaitForExitAsync(exitCts.Token);
                }
                catch
                {
                    try { _activeProcess.Kill(true); } catch { }
                }
            }

            result.ExitCode = _activeProcess.HasExited ? _activeProcess.ExitCode : -1;
        }
        catch (OperationCanceledException)
        {
            try { _activeProcess?.Kill(true); } catch { }
            result.WasCancelled = true;
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        finally
        {
            _activeProcess?.Dispose();
            _activeProcess = null;
        }

        return result;
    }

    /// <summary>Get engine status</summary>
    public async Task<EngineStatus> GetStatusAsync()
    {
        var status = new EngineStatus();
        if (!IsEngineAvailable) return status;

        var output = await RunCommandAsync("status");

        foreach (var raw in output.Split('\n'))
        {
            var line = StripAnsi(raw.Trim());
            if (line.StartsWith("Signatures loaded:") && int.TryParse(ExtractValue(line), out var sigCount))
                status.SignatureCount = sigCount;
            else if (line.StartsWith("GPU:"))
                status.GpuName = ExtractValue(line);
            else if (line.StartsWith("GPU Backend:"))
                status.GpuBackend = ExtractValue(line);
            else if (line.StartsWith("Thread pool threads:") && int.TryParse(ExtractValue(line), out var threads))
                status.Threads = threads;
            else if (line.StartsWith("Ready:"))
                status.IsReady = ExtractValue(line).Equals("Yes", StringComparison.OrdinalIgnoreCase);
            else if (line.StartsWith("Quarantined files:") && int.TryParse(ExtractValue(line), out var qFiles))
                status.QuarantinedFiles = qFiles;
            else if (line.StartsWith("Quarantine size:") && long.TryParse(ExtractNumber(line), out var qSize))
                status.QuarantineSize = qSize;
        }

        return status;
    }

    /// <summary>Update malware signatures</summary>
    public async Task<string> UpdateSignaturesAsync()
    {
        return await RunCommandAsync("update");
    }

    /// <summary>Get version info</summary>
    public async Task<string> GetVersionAsync()
    {
        return await RunCommandAsync("version");
    }

    /// <summary>List quarantined files</summary>
    public async Task<List<QuarantineEntry>> GetQuarantineListAsync()
    {
        var entries = new List<QuarantineEntry>();
        if (!IsEngineAvailable) return entries;

        var output = await RunCommandAsync("quarantine list");
        
        QuarantineEntry? current = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = StripAnsi(raw.Trim());
            if (line.StartsWith("ID:"))
            {
                current = new QuarantineEntry { Id = ExtractValue(line).Replace("...", "") };
            }
            else if (line.StartsWith("Original:") && current != null)
            {
                current.OriginalPath = ExtractValue(line);
            }
            else if (line.StartsWith("Threat:") && current != null)
            {
                current.ThreatName = ExtractValue(line);
            }
            else if (line.StartsWith("Size:") && current != null)
            {
                if (long.TryParse(ExtractNumber(line), out var size))
                    current.Size = size;
                entries.Add(current);
                current = null;
            }
        }

        return entries;
    }

    /// <summary>Restore a quarantined file by ID</summary>
    public async Task<bool> RestoreQuarantinedFileAsync(string id)
    {
        var output = await RunCommandAsync($"quarantine restore {id}");
        return output.Contains("restored successfully", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Delete a quarantined file by ID</summary>
    public async Task<bool> DeleteQuarantinedFileAsync(string id)
    {
        var output = await RunCommandAsync($"quarantine delete {id}");
        return output.Contains("deleted successfully", StringComparison.OrdinalIgnoreCase);
    }

    public void CancelScan()
    {
        _cts?.Cancel();
        try { _activeProcess?.Kill(true); } catch { }
    }

    private async Task<string> RunCommandAsync(string args)
    {
        if (!IsEngineAvailable) return "Engine not found";

        var psi = new ProcessStartInfo
        {
            FileName = _enginePath,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_enginePath) ?? ""
        };

        using var proc = Process.Start(psi);
        if (proc == null) return "Failed to start engine";

        var output = await proc.StandardOutput.ReadToEndAsync();

        // Wait with timeout
        using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await proc.WaitForExitAsync(exitCts.Token); }
        catch { try { proc.Kill(true); } catch { } }

        return output;
    }

    private void ParseLine(string line, ScanResult result)
    {
        // Progress line: [123 scanned | 0 infected | 45.6 files/sec]
        var progressMatch = Regex.Match(line, @"\[(\d+)\s+scanned\s*\|\s*(\d+)\s+infected\s*\|\s*([\d.]+)\s+files/sec\]");
        if (progressMatch.Success)
        {
            if (int.TryParse(progressMatch.Groups[1].Value, out var scanned))
                result.ScannedFiles = scanned;
            if (int.TryParse(progressMatch.Groups[2].Value, out var infected))
                result.InfectedFiles = infected;
            if (double.TryParse(progressMatch.Groups[3].Value, out var rate))
                result.ScanRate = rate;

            OnProgress?.Invoke(new ScanProgress
            {
                ScannedFiles = result.ScannedFiles,
                TotalFiles = result.TotalFiles > 0 ? result.TotalFiles : result.ScannedFiles,
                InfectedFiles = result.InfectedFiles,
                ScanRate = result.ScanRate
            });
            return;
        }

        // Threat line: ⚠️  THREAT DETECTED: <name> in <path>
        var threatMatch = Regex.Match(line, @"THREAT DETECTED:\s*(.+?)\s+in\s+(.+)$");
        if (threatMatch.Success)
        {
            var threat = new ThreatInfo
            {
                ThreatName = threatMatch.Groups[1].Value.Trim(),
                FilePath = threatMatch.Groups[2].Value.Trim()
            };
            result.Threats.Add(threat);
            OnThreatDetected?.Invoke(threat);
            return;
        }

        // Result lines
        if (line.StartsWith("Total files:") && int.TryParse(ExtractNumber(line), out var total))
            result.TotalFiles = total;
        else if (line.StartsWith("Scanned:") && int.TryParse(ExtractNumber(line), out var s))
            result.ScannedFiles = s;
        else if (line.StartsWith("Infected:") && int.TryParse(ExtractNumber(line), out var inf))
            result.InfectedFiles = inf;
        else if (line.StartsWith("Quarantined:") && int.TryParse(ExtractNumber(line), out var q))
            result.QuarantinedFiles = q;
        else if (line.StartsWith("Errors:") && int.TryParse(ExtractNumber(line), out var err))
            result.Errors = err;
        else if (line.StartsWith("Duration:"))
            result.Duration = ExtractValue(line);
        else if (line.StartsWith("Scan rate:") && double.TryParse(Regex.Match(line, @"([\d.]+)").Groups[1].Value, out var sr))
            result.ScanRate = sr;
    }

    private static string StripAnsi(string text) =>
        Regex.Replace(text, @"\x1B\[[0-9;]*m", "");

    private static string ExtractValue(string line)
    {
        var idx = line.IndexOf(':');
        return idx >= 0 ? line[(idx + 1)..].Trim() : line;
    }

    private static string ExtractNumber(string text)
    {
        var match = Regex.Match(text, @":\s*(\d+)");
        return match.Success ? match.Groups[1].Value : "0";
    }
}

// ═══════════════════════════════════════════
// Data Models
// ═══════════════════════════════════════════

public class ScanProgress
{
    public int ScannedFiles { get; set; }
    public int TotalFiles { get; set; }
    public int InfectedFiles { get; set; }
    public double ScanRate { get; set; }
    public double Percentage => TotalFiles > 0 ? ScannedFiles * 100.0 / TotalFiles : 0;
}

public class ScanResult
{
    public int TotalFiles { get; set; }
    public int ScannedFiles { get; set; }
    public int InfectedFiles { get; set; }
    public int QuarantinedFiles { get; set; }
    public int Errors { get; set; }
    public double ScanRate { get; set; }
    public string Duration { get; set; } = "";
    public int ExitCode { get; set; }
    public bool WasCancelled { get; set; }
    public string Error { get; set; } = "";
    public List<ThreatInfo> Threats { get; } = new();
}

public class ThreatInfo
{
    public string ThreatName { get; set; } = "";
    public string FilePath { get; set; } = "";
}

public class EngineStatus
{
    public bool IsReady { get; set; }
    public int SignatureCount { get; set; }
    public int Threads { get; set; }
    public string GpuName { get; set; } = "";
    public string GpuBackend { get; set; } = "";
    public int QuarantinedFiles { get; set; }
    public long QuarantineSize { get; set; }
}

public class QuarantineEntry
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public long Size { get; set; }
}
