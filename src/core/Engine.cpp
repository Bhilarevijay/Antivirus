/**
 * @file Engine.cpp
 * @brief Core antivirus engine implementation
 */

#include "antivirus/core/Engine.hpp"
#include "antivirus/detection/ScanCache.hpp"
#include <algorithm>
#include <iostream>
#include <span>
#include <unordered_set>

#ifdef _WIN32
    #include <Windows.h>
#endif

namespace antivirus {

// ============================================================================
// Engine Implementation
// ============================================================================

Engine::Engine(
    std::shared_ptr<IFileScanner> scanner,
    std::shared_ptr<IThreadPool> threadPool,
    std::shared_ptr<SignatureDatabase> signatureDb,
    std::shared_ptr<HashEngine> hashEngine,
    std::shared_ptr<PatternMatcher> patternMatcher,
    std::shared_ptr<IQuarantineManager> quarantine,
    std::shared_ptr<ILogger> logger,
    std::shared_ptr<IConfigManager> config,
    std::shared_ptr<IGpuCompute> gpuCompute
)
    : m_scanner(std::move(scanner))
    , m_threadPool(std::move(threadPool))
    , m_signatureDb(std::move(signatureDb))
    , m_hashEngine(std::move(hashEngine))
    , m_patternMatcher(std::move(patternMatcher))
    , m_quarantine(std::move(quarantine))
    , m_logger(std::move(logger))
    , m_config(std::move(config))
    , m_gpuCompute(std::move(gpuCompute))
{
}

Engine::~Engine() {
    Shutdown();
}

bool Engine::Initialize() {
    if (m_initialized.load()) {
        return true;
    }
    
    m_logger->Info("Initializing antivirus engine...");
    
    // Validate dependencies
    if (!m_scanner || !m_threadPool || !m_signatureDb || 
        !m_hashEngine || !m_patternMatcher || !m_quarantine) {
        m_logger->Error("Engine initialization failed: missing dependencies");
        return false;
    }
    
    // Load signatures
    try {
        if (!ReloadSignatures()) {
            m_logger->Warn("Failed to load signature database");
            // Continue anyway - might be first run
        }
    } catch (const std::exception& e) {
        m_logger->Warn("Failed to load signature database: {}", e.what());
    }
    
    // Initialize scan cache (persists between sessions)
    try {
        auto exeDir = std::filesystem::path(".");
#ifdef _WIN32
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0) {
            exeDir = std::filesystem::path(exePath).parent_path();
        }
#endif
        auto cachePath = exeDir / "scan_cache.dat";
        m_scanCache = std::make_shared<ScanCache>(cachePath, m_logger);
        auto cacheEntries = m_scanCache->Load();
        m_logger->Info("Scan cache: {} file entries loaded", cacheEntries);
    } catch (const std::exception& e) {
        m_logger->Warn("Failed to load scan cache: {}", e.what());
    }
    
    // Initialize YARA rule engine
#ifdef HAS_YARA
    try {
        m_yaraEngine = std::make_shared<YaraEngine>(m_logger);
        if (m_yaraEngine->Initialize()) {
            auto exeDir2 = std::filesystem::path(".");
#ifdef _WIN32
            wchar_t ep[MAX_PATH];
            if (GetModuleFileNameW(nullptr, ep, MAX_PATH) > 0) {
                exeDir2 = std::filesystem::path(ep).parent_path();
            }
#endif
            auto rulesDir = exeDir2 / "rules";
            auto rulesLoaded = m_yaraEngine->LoadRulesFromDirectory(rulesDir);
            if (rulesLoaded > 0) {
                m_yaraEngine->CompileRules();
                m_logger->Info("YARA: {} rules compiled from {} files",
                    m_yaraEngine->GetRuleCount(), rulesLoaded);
            } else {
                m_logger->Info("YARA: No rule files found in {}", rulesDir.string());
            }
        }
    } catch (const std::exception& e) {
        m_logger->Warn("YARA init failed: {}", e.what());
    }
#endif
    
    m_logger->Info("Engine initialized with {} signatures", 
        m_signatureDb->GetSignatureCount());
    
    m_initialized.store(true);
    SetState(ScanState::Idle);
    return true;
}

void Engine::Shutdown() {
    if (m_shutdownRequested.exchange(true)) {
        return;  // Already shutting down
    }
    
    m_logger->Info("Shutting down engine...");
    
    // Cancel any ongoing scan
    if (m_state.load() == ScanState::Scanning) {
        CancelScan();
    }
    
    // Stop thread pool
    if (m_threadPool) {
        m_threadPool->Stop(true);
    }
    
    m_initialized.store(false);
    SetState(ScanState::Idle);
    
    m_logger->Info("Engine shutdown complete");
}

bool Engine::IsReady() const noexcept {
    return m_initialized.load() && !m_shutdownRequested.load();
}

bool Engine::StartScan(const ScanConfig& config) {
    if (!IsReady()) {
        m_logger->Error("Cannot start scan: engine not ready");
        return false;
    }
    
    // Try to transition from Idle to Initializing
    ScanState expected = ScanState::Idle;
    if (!m_state.compare_exchange_strong(expected, ScanState::Initializing)) {
        // If state is Completed, Cancelled, or Error, reset to Idle and retry
        ScanState current = m_state.load();
        if (current == ScanState::Completed || current == ScanState::Cancelled || current == ScanState::Error) {
            m_state.store(ScanState::Idle);
            expected = ScanState::Idle;
            if (!m_state.compare_exchange_strong(expected, ScanState::Initializing)) {
                m_logger->Warn("Cannot start scan: scan already in progress (state={})", static_cast<int>(m_state.load()));
                return false;
            }
        } else {
            m_logger->Warn("Cannot start scan: scan already in progress (state={})", static_cast<int>(current));
            return false;
        }
    }
    
    m_logger->Info("Starting {} scan with {} target paths...", 
        config.mode == ScanMode::Quick ? "quick" :
        config.mode == ScanMode::Full ? "full" : "custom",
        config.targetPaths.size());
    
    // Log each target path
    for (const auto& p : config.targetPaths) {
        m_logger->Info("  Scan target: {}", p.string());
    }
    
    // Reset statistics
    m_stats.Reset();
    m_stats.startTime = std::chrono::system_clock::now();
    
    // Clear previous results
    {
        std::lock_guard<std::mutex> lock(m_resultsMutex);
        m_results.clear();
    }
    
    // Store config
    m_currentConfig = config;
    
    // Set cancellation token for scanner
    m_cancelledToken.store(false);
    m_scanner->SetCancellationToken(&m_cancelledToken);
    
    // Start file enumeration and scanning
    SetState(ScanState::Scanning);
    
    for (const auto& targetPath : config.targetPaths) {
        if (m_state.load() == ScanState::Cancelled) break;
        
        m_scanner->EnumerateFiles(
            targetPath,
            [this](const FileInfo& fileInfo) {
                OnFileEnumerated(fileInfo);
            },
            config
        );
    }
    
    // Wait for all tasks to complete
    m_threadPool->WaitAll();
    
    OnScanComplete();
    return true;
}

bool Engine::StartQuickScan() {
    ScanConfig config;
    config.mode = ScanMode::Quick;
    config.targetPaths = GetQuickScanPaths();
    return StartScan(config);
}

bool Engine::StartFullScan() {
    ScanConfig config;
    config.mode = ScanMode::Full;
    config.targetPaths = GetFullScanPaths();
    return StartScan(config);
}

bool Engine::StartCustomScan(const std::vector<FilePath>& paths) {
    ScanConfig config;
    config.mode = ScanMode::Custom;
    config.targetPaths = paths;
    return StartScan(config);
}

void Engine::PauseScan() {
    if (m_state.load() != ScanState::Scanning) {
        return;
    }
    
    m_paused.store(true);
    SetState(ScanState::Paused);
    m_logger->Info("Scan paused");
}

void Engine::ResumeScan() {
    if (m_state.load() != ScanState::Paused) {
        return;
    }
    
    m_paused.store(false);
    SetState(ScanState::Scanning);
    m_pauseCondition.notify_all();
    m_logger->Info("Scan resumed");
}

void Engine::CancelScan() {
    ScanState state = m_state.load();
    if (state != ScanState::Scanning && state != ScanState::Paused) {
        return;
    }
    
    m_logger->Info("Cancelling scan...");
    SetState(ScanState::Cancelled);
    
    // Resume if paused so threads can exit
    m_paused.store(false);
    m_pauseCondition.notify_all();
}

ScanState Engine::GetState() const noexcept {
    return m_state.load();
}

const ScanStatistics& Engine::GetStatistics() const noexcept {
    return m_stats;
}

std::vector<ScanResult> Engine::GetResults() const {
    std::lock_guard<std::mutex> lock(m_resultsMutex);
    return m_results;
}

void Engine::SetScanCallback(ScanCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_scanCallback = std::move(callback);
}

void Engine::SetThreatCallback(ThreatCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_threatCallback = std::move(callback);
}

void Engine::SetProgressCallback(ProgressCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_progressCallback = std::move(callback);
}

void Engine::SetStateCallback(StateCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_stateCallback = std::move(callback);
}

bool Engine::ReloadSignatures() {
    if (!m_config) {
        return false;
    }
    
    auto sigPath = m_config->GetSignaturePath();
    auto sigDir = sigPath.parent_path();
    
    // Load all .db files from the signatures directory
    if (!sigDir.empty() && std::filesystem::is_directory(sigDir)) {
        return m_signatureDb->LoadDirectory(sigDir);
    }
    
    // Fallback: load single file
    return m_signatureDb->Load(sigPath);
}

size_t Engine::GetSignatureCount() const noexcept {
    return m_signatureDb ? m_signatureDb->GetSignatureCount() : 0;
}

// ============================================================================
// Private Methods
// ============================================================================

void Engine::SetState(ScanState newState) {
    ScanState oldState = m_state.exchange(newState);
    
    if (oldState != newState) {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_stateCallback) {
            m_stateCallback(oldState, newState);
        }
    }
}

void Engine::OnFileEnumerated(const FileInfo& fileInfo) {
    m_stats.totalFiles.fetch_add(1);
    
    // Check scan cache — skip if file is unchanged since last clean scan
    if (m_scanCache) {
        auto modTime = std::chrono::duration_cast<std::chrono::seconds>(
            fileInfo.lastModified.time_since_epoch()
        ).count();
        
        if (m_scanCache->CanSkipFile(fileInfo.path, fileInfo.size, modTime)) {
            // File unchanged since last clean scan → skip
            m_stats.scannedFiles.fetch_add(1);
            m_stats.skippedFiles.fetch_add(1);
            return;
        }
    }
    
    // Submit to thread pool for scanning
    m_threadPool->Submit([this, fileInfo]() {
        ProcessFile(fileInfo);
    });
}

void Engine::ProcessFile(const FileInfo& fileInfo) {
    // Check for pause
    if (m_paused.load()) {
        std::unique_lock<std::mutex> lock(m_pauseMutex);
        m_pauseCondition.wait(lock, [this]() {
            return !m_paused.load() || m_state.load() == ScanState::Cancelled;
        });
    }
    
    // Check for cancellation
    if (m_state.load() == ScanState::Cancelled) {
        return;
    }
    
    auto result = ScanFileContent(fileInfo);
    
    // Update statistics
    if (result.scanned) {
        m_stats.scannedFiles.fetch_add(1);
        m_stats.bytesScanned.fetch_add(fileInfo.size);
        
        // Invoke progress callback every 100 files for live updates
        auto scanned = m_stats.scannedFiles.load();
        if (scanned % 100 == 0) {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            if (m_progressCallback) {
                m_progressCallback(m_stats);
            }
        }
    } else {
        m_stats.skippedFiles.fetch_add(1);
    }
    
    if (result.threatDetected) {
        m_stats.infectedFiles.fetch_add(1);
        HandleThreat(fileInfo, *result.threat);
    }
    
    // Store result
    {
        std::lock_guard<std::mutex> lock(m_resultsMutex);
        m_results.push_back(result);
    }
    
    // Invoke callback
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_scanCallback) {
            m_scanCallback(result);
        }
    }
}

ScanResult Engine::ScanFileContent(const FileInfo& fileInfo) {
    ScanResult result;
    result.fileInfo = fileInfo;
    
    auto startTime = std::chrono::steady_clock::now();
    
    try {
        // Read file in chunks
        std::vector<uint8_t> buffer(constants::DEFAULT_CHUNK_SIZE);
        auto bytesRead = m_scanner->ReadFile(fileInfo.path, std::span<uint8_t>(buffer));
        
        if (bytesRead == 0) {
            result.errorMessage = "Failed to read file";
            return result;
        }
        
        buffer.resize(bytesRead);
        
        // Compute hashes
        auto sha256 = m_hashEngine->ComputeSHA256(buffer);
        
        // Hash-based cache verification:
        // Even though size+mtime check passed in OnFileEnumerated (or this is a new file),
        // compare the computed hash with the cached hash to detect content changes.
        if (m_scanCache) {
            auto cachedHash = m_scanCache->GetCachedHash(fileInfo.path);
            auto currentHash = HashEngine::HashToHex(sha256);
            if (!cachedHash.empty() && cachedHash == currentHash) {
                // Hash matches cached value → file content truly unchanged
                auto modTime = std::chrono::duration_cast<std::chrono::seconds>(
                    fileInfo.lastModified.time_since_epoch()
                ).count();
                if (m_scanCache->CanSkipFileWithHash(fileInfo.path, fileInfo.size, modTime, currentHash)) {
                    result.scanned = true;
                    // Update cache entry (refreshes mtime in case it changed)
                    m_scanCache->UpdateEntry(fileInfo.path, fileInfo.size, modTime, currentHash, true);
                    return result;  // Skip expensive pattern+YARA scanning
                }
            }
        }
        
        // Check bloom filter first (quick rejection)
        if (m_signatureDb->MayMatchHash(sha256, HashType::SHA256)) {
            // Full lookup
            auto signature = m_signatureDb->LookupByHash(sha256, HashType::SHA256);
            if (signature) {
                result.threatDetected = true;
                result.threat = ThreatInfo{
                    signature->id,
                    signature->name,
                    "Matched hash signature",
                    signature->level,
                    HashType::SHA256,
                    "",
                    0
                };
            }
        }
        
        // Pattern matching if no hash match
        if (!result.threatDetected) {
            auto patternMatches = m_signatureDb->ScanPatterns(buffer);
            if (!patternMatches.empty()) {
                const auto& [sig, offset] = patternMatches[0];
                result.threatDetected = true;
                result.threat = ThreatInfo{
                    sig.id,
                    sig.name,
                    "Matched pattern signature",
                    sig.level,
                    HashType::SHA256,
                    HashEngine::HashToHex(sig.hexPattern),
                    offset
                };
            }
        }
        
        // YARA rule scanning (if no threat detected yet by hash/pattern)
#ifdef HAS_YARA
        if (!result.threatDetected && m_yaraEngine && m_yaraEngine->IsReady()) {
            // Only YARA-scan file types that are commonly malicious
            auto ext = fileInfo.path.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            static const std::unordered_set<std::string> yaraExts = {
                ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr", ".com",  // PE binaries
                ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",   // Scripts
                ".wsf", ".wsh", ".hta", ".msi", ".msp",                  // Installers/scripts
                ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",      // Office (macros)
                ".ppt", ".pptx", ".pptm", ".rtf",                        // Office (macros)
                ".php", ".asp", ".aspx", ".jsp", ".cgi",                  // Web scripts
                ".py", ".rb", ".pl",                                      // Scripting langs
                ".zip", ".rar", ".7z", ".cab", ".iso",                   // Archives
                ".lnk", ".inf", ".reg",                                   // System files
            };
            if (yaraExts.count(ext)) {
            auto yaraMatches = m_yaraEngine->ScanBuffer(buffer);
            if (!yaraMatches.empty()) {
                const auto& ym = yaraMatches[0];
                result.threatDetected = true;
                result.threat = ThreatInfo{
                    "YARA:" + ym.ruleName,
                    ym.ruleName,
                    ym.description.empty() ? "Matched YARA rule" : ym.description,
                    ym.level,
                    HashType::SHA256,
                    "",
                    ym.matchedStrings.empty() ? 0 : ym.matchedStrings[0].second
                };
            }
            } // end if yaraExts
        }
#endif
        
        result.scanned = true;
        
        // Update scan cache with this file's result
        if (m_scanCache) {
            auto modTime = std::chrono::duration_cast<std::chrono::seconds>(
                fileInfo.lastModified.time_since_epoch()
            ).count();
            auto sha256Hex = HashEngine::HashToHex(sha256);
            m_scanCache->UpdateEntry(
                fileInfo.path, fileInfo.size, modTime,
                sha256Hex, !result.threatDetected
            );
        }
        
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        m_stats.errorCount.fetch_add(1);
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.scanTime = std::chrono::duration_cast<Duration>(endTime - startTime);
    
    return result;
}

void Engine::HandleThreat(const FileInfo& fileInfo, const ThreatInfo& threat) {
    m_logger->Warn("Threat detected: {} in {}", 
        threat.threatName, fileInfo.path.string());
    
    // Quarantine the file
    auto entry = m_quarantine->Quarantine(fileInfo.path, threat);
    if (entry) {
        m_stats.quarantinedFiles.fetch_add(1);
        m_logger->Info("File quarantined: {}", entry->id);
    }
    
    // Invoke threat callback
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_threatCallback) {
            m_threatCallback(fileInfo, threat);
        }
    }
}

void Engine::OnScanComplete() {
    m_stats.endTime = std::chrono::system_clock::now();
    
    // Save scan cache to disk (persists for next session)
    if (m_scanCache) {
        m_scanCache->Save();
        m_logger->Info("Scan cache: {} files cached, {} cache hits (skipped)",
            m_scanCache->GetEntryCount(), m_scanCache->GetCacheHits());
        auto mismatches = m_scanCache->GetHashMismatches();
        if (mismatches > 0) {
            m_logger->Warn("Scan cache: {} hash mismatches detected (possible file tampering)", mismatches);
        }
    }
    
    if (m_state.load() != ScanState::Cancelled) {
        SetState(ScanState::Completed);
    }
    
    m_logger->Info("Scan complete: {} files scanned, {} threats found, {} quarantined",
        m_stats.scannedFiles.load(),
        m_stats.infectedFiles.load(),
        m_stats.quarantinedFiles.load());
}

std::vector<FilePath> Engine::GetQuickScanPaths() const {
    // Quick scan targets: areas where malware commonly persists.
    // Based on industry standard (Windows Defender, Kaspersky, Malwarebytes):
    //   1. User-writable hotspots (Downloads, Desktop, Documents, Temp)
    //   2. Startup/persistence locations (Startup folders, ProgramData)
    //   3. System critical areas (System32\drivers, Prefetch, Windows\Temp)
    //   4. Browser download and extension folders
    std::vector<FilePath> paths;
    
#ifdef _WIN32
    // ── User profile locations (malware drop zones) ──
    char* userProfile = nullptr;
    size_t len = 0;
    if (_dupenv_s(&userProfile, &len, "USERPROFILE") == 0 && userProfile) {
        std::string up(userProfile);
        paths.emplace_back(up + "\\Downloads");
        paths.emplace_back(up + "\\Desktop");
        paths.emplace_back(up + "\\Documents");
        paths.emplace_back(up + "\\AppData\\Local\\Temp");
        
        // User startup folder (persistence vector)
        paths.emplace_back(up + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        
        // Browser extensions (can contain malicious extensions)
        paths.emplace_back(up + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions");
        paths.emplace_back(up + "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions");
        
        // Recent files
        paths.emplace_back(up + "\\AppData\\Roaming\\Microsoft\\Windows\\Recent");
        
        free(userProfile);
    }
    
    // ── Public folders (common malware drop) ──
    paths.emplace_back("C:\\Users\\Public\\Downloads");
    paths.emplace_back("C:\\Users\\Public\\Desktop");
    
    // ── System temp directories ──
    char* temp = nullptr;
    if (_dupenv_s(&temp, &len, "TEMP") == 0 && temp) {
        paths.emplace_back(temp);
        free(temp);
    }
    paths.emplace_back("C:\\Windows\\Temp");
    
    // ── Startup & persistence locations (targeted, NOT full ProgramData) ──
    paths.emplace_back("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    
    // ── System critical areas (small, fast to scan) ──
    paths.emplace_back("C:\\Windows\\System32\\drivers");
    paths.emplace_back("C:\\Windows\\System32\\Tasks");

    // ── Remove non-existent paths ──
    paths.erase(
        std::remove_if(paths.begin(), paths.end(),
            [](const FilePath& p) { return !std::filesystem::exists(p); }),
        paths.end());
    
#else
    // Linux quick scan paths
    if (auto home = std::getenv("HOME")) {
        paths.emplace_back(std::string(home) + "/Downloads");
        paths.emplace_back(std::string(home) + "/Desktop");
        paths.emplace_back(std::string(home) + "/Documents");
        paths.emplace_back(std::string(home) + "/.local/share");
        paths.emplace_back(std::string(home) + "/.config");
        paths.emplace_back("/tmp");
        paths.emplace_back("/var/tmp");
    }
#endif
    
    return paths;
}

std::vector<FilePath> Engine::GetFullScanPaths() const {
    std::vector<FilePath> paths;
    
#ifdef _WIN32
    // Scan all fixed drives
    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        std::string drivePath = std::string(1, drive) + ":\\";
        if (GetDriveTypeA(drivePath.c_str()) == DRIVE_FIXED) {
            paths.emplace_back(drivePath);
        }
    }
#else
    paths.emplace_back("/");
#endif
    
    return paths;
}

// ============================================================================
// EngineBuilder Implementation
// ============================================================================

EngineBuilder& EngineBuilder::WithScanner(std::shared_ptr<IFileScanner> scanner) {
    m_scanner = std::move(scanner);
    return *this;
}

EngineBuilder& EngineBuilder::WithThreadPool(std::shared_ptr<IThreadPool> pool) {
    m_threadPool = std::move(pool);
    return *this;
}

EngineBuilder& EngineBuilder::WithSignatureDatabase(std::shared_ptr<SignatureDatabase> db) {
    m_signatureDb = std::move(db);
    return *this;
}

EngineBuilder& EngineBuilder::WithHashEngine(std::shared_ptr<HashEngine> engine) {
    m_hashEngine = std::move(engine);
    return *this;
}

EngineBuilder& EngineBuilder::WithPatternMatcher(std::shared_ptr<PatternMatcher> matcher) {
    m_patternMatcher = std::move(matcher);
    return *this;
}

EngineBuilder& EngineBuilder::WithQuarantine(std::shared_ptr<IQuarantineManager> quarantine) {
    m_quarantine = std::move(quarantine);
    return *this;
}

EngineBuilder& EngineBuilder::WithLogger(std::shared_ptr<ILogger> logger) {
    m_logger = std::move(logger);
    return *this;
}

EngineBuilder& EngineBuilder::WithConfig(std::shared_ptr<IConfigManager> config) {
    m_config = std::move(config);
    return *this;
}

EngineBuilder& EngineBuilder::WithGpuCompute(std::shared_ptr<IGpuCompute> gpu) {
    m_gpuCompute = std::move(gpu);
    return *this;
}

std::unique_ptr<Engine> EngineBuilder::Build() {
    return std::unique_ptr<Engine>(new Engine(
        m_scanner,
        m_threadPool,
        m_signatureDb,
        m_hashEngine,
        m_patternMatcher,
        m_quarantine,
        m_logger,
        m_config,
        m_gpuCompute
    ));
}

}  // namespace antivirus
