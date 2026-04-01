using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AntivirusGUI.Services;

/// <summary>
/// System cleaner: temp files, recycle bin, browser cache.
/// Uses Win32 API for recycle bin and filesystem operations.
/// </summary>
public class CleanerService
{
    [DllImport("Shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);

    [DllImport("Shell32.dll")]
    private static extern int SHQueryRecycleBin(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct SHQUERYRBINFO
    {
        public uint cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    private const uint SHERB_NOCONFIRMATION = 0x1;
    private const uint SHERB_NOPROGRESSUI = 0x2;
    private const uint SHERB_NOSOUND = 0x4;

    /// <summary>Analyze system for cleanable data</summary>
    public async Task<CleanAnalysis> AnalyzeAsync()
    {
        var analysis = new CleanAnalysis();

        await Task.Run(() =>
        {
            // Temp files
            analysis.TempFiles = GetDirectorySize(Path.GetTempPath());
            var localTemp = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
            if (Directory.Exists(localTemp))
                analysis.TempFiles += GetDirectorySize(localTemp);

            // Windows temp
            var winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            if (Directory.Exists(winTemp))
                analysis.WindowsTempFiles = GetDirectorySize(winTemp);

            // Recycle bin
            analysis.RecycleBinSize = GetRecycleBinSize();

            // Browser caches
            analysis.BrowserCacheSize = GetBrowserCacheSize();

            // Windows prefetch
            var prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            if (Directory.Exists(prefetch))
                analysis.PrefetchSize = GetDirectorySize(prefetch);

            // Thumbnail cache
            var thumbCache = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "Windows", "Explorer");
            if (Directory.Exists(thumbCache))
            {
                foreach (var file in Directory.GetFiles(thumbCache, "thumbcache_*.db"))
                    analysis.ThumbnailCacheSize += new FileInfo(file).Length;
            }
        });

        return analysis;
    }

    /// <summary>Clean selected categories</summary>
    public async Task<CleanResult> CleanAsync(bool tempFiles, bool recycleBin, bool browserCache,
        bool prefetch = false, bool thumbnails = false)
    {
        var result = new CleanResult();

        await Task.Run(() =>
        {
            if (tempFiles)
                result.TempFilesCleaned = CleanDirectory(Path.GetTempPath());

            if (recycleBin)
                result.RecycleBinCleaned = EmptyRecycleBin();

            if (browserCache)
                result.BrowserCacheCleaned = CleanBrowserCaches();

            if (prefetch)
                result.PrefetchCleaned = CleanDirectory(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"));

            if (thumbnails)
            {
                var thumbDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Windows", "Explorer");
                foreach (var file in Directory.GetFiles(thumbDir, "thumbcache_*.db"))
                {
                    try { File.Delete(file); result.ThumbnailsCleaned += new FileInfo(file).Length; }
                    catch { }
                }
            }
        });

        result.TotalCleaned = result.TempFilesCleaned + result.RecycleBinCleaned +
                              result.BrowserCacheCleaned + result.PrefetchCleaned + result.ThumbnailsCleaned;
        return result;
    }

    private long GetRecycleBinSize()
    {
        try
        {
            var info = new SHQUERYRBINFO { cbSize = (uint)Marshal.SizeOf<SHQUERYRBINFO>() };
            SHQueryRecycleBin(null, ref info);
            return info.i64Size;
        }
        catch { return 0; }
    }

    private long EmptyRecycleBin()
    {
        var size = GetRecycleBinSize();
        try
        {
            SHEmptyRecycleBin(IntPtr.Zero, null,
                SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
            return size;
        }
        catch { return 0; }
    }

    private long GetBrowserCacheSize()
    {
        long total = 0;
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Chrome
        var chromeCache = Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Cache");
        if (Directory.Exists(chromeCache)) total += GetDirectorySize(chromeCache);

        // Edge
        var edgeCache = Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Cache");
        if (Directory.Exists(edgeCache)) total += GetDirectorySize(edgeCache);

        // Firefox
        var firefoxDir = Path.Combine(localApp, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxDir))
        {
            foreach (var profile in Directory.GetDirectories(firefoxDir))
            {
                var cache = Path.Combine(profile, "cache2");
                if (Directory.Exists(cache)) total += GetDirectorySize(cache);
            }
        }

        return total;
    }

    private long CleanBrowserCaches()
    {
        long cleaned = 0;
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        cleaned += CleanDirectory(Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Cache"));
        cleaned += CleanDirectory(Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Cache"));

        var firefoxDir = Path.Combine(localApp, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxDir))
        {
            foreach (var profile in Directory.GetDirectories(firefoxDir))
                cleaned += CleanDirectory(Path.Combine(profile, "cache2"));
        }

        return cleaned;
    }

    private static long GetDirectorySize(string path)
    {
        if (!Directory.Exists(path)) return 0;
        long size = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try { size += new FileInfo(file).Length; }
                catch { }
            }
        }
        catch { }
        return size;
    }

    private static long CleanDirectory(string path)
    {
        if (!Directory.Exists(path)) return 0;
        long cleaned = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    var size = new FileInfo(file).Length;
                    File.Delete(file);
                    cleaned += size;
                }
                catch { }
            }
        }
        catch { }
        return cleaned;
    }
}

public class CleanAnalysis
{
    public long TempFiles { get; set; }
    public long WindowsTempFiles { get; set; }
    public long RecycleBinSize { get; set; }
    public long BrowserCacheSize { get; set; }
    public long PrefetchSize { get; set; }
    public long ThumbnailCacheSize { get; set; }
    public long TotalCleanable => TempFiles + WindowsTempFiles + RecycleBinSize +
                                  BrowserCacheSize + PrefetchSize + ThumbnailCacheSize;
}

public class CleanResult
{
    public long TempFilesCleaned { get; set; }
    public long RecycleBinCleaned { get; set; }
    public long BrowserCacheCleaned { get; set; }
    public long PrefetchCleaned { get; set; }
    public long ThumbnailsCleaned { get; set; }
    public long TotalCleaned { get; set; }
}
