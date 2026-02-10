/**
 * @file Engine.cpp
 * @brief Core antivirus engine implementation
 */

#include "antivirus/core/Engine.hpp"
#include <algorithm>

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
    if (!ReloadSignatures()) {
        m_logger->Warn("Failed to load signature database");
        // Continue anyway - might be first run
    }
    
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
    
    ScanState expected = ScanState::Idle;
    if (!m_state.compare_exchange_strong(expected, ScanState::Initializing)) {
        m_logger->Warn("Cannot start scan: scan already in progress");
        return false;
    }
    
    m_logger->Info("Starting {} scan...", 
        config.mode == ScanMode::Quick ? "quick" :
        config.mode == ScanMode::Full ? "full" : "custom");
    
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
    static std::atomic<bool> cancelled{false};
    cancelled.store(false);
    m_scanner->SetCancellationToken(&cancelled);
    
    // Start file enumeration and scanning
    SetState(ScanState::Scanning);
    
    for (const auto& targetPath : config.targetPaths) {
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
        auto bytesRead = m_scanner->ReadFile(fileInfo.path, buffer);
        
        if (bytesRead == 0) {
            result.errorMessage = "Failed to read file";
            return result;
        }
        
        buffer.resize(bytesRead);
        
        // Compute hashes
        auto sha256 = m_hashEngine->ComputeSHA256(buffer);
        
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
        
        result.scanned = true;
        
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
    
    if (m_state.load() != ScanState::Cancelled) {
        SetState(ScanState::Completed);
    }
    
    m_logger->Info("Scan complete: {} files scanned, {} threats found, {} quarantined",
        m_stats.scannedFiles.load(),
        m_stats.infectedFiles.load(),
        m_stats.quarantinedFiles.load());
}

std::vector<FilePath> Engine::GetQuickScanPaths() const {
    // Common malware locations on Windows
    std::vector<FilePath> paths;
    
#ifdef _WIN32
    // User profile locations
    char* userProfile = nullptr;
    size_t len = 0;
    if (_dupenv_s(&userProfile, &len, "USERPROFILE") == 0 && userProfile) {
        paths.emplace_back(std::string(userProfile) + "\\Downloads");
        paths.emplace_back(std::string(userProfile) + "\\Desktop");
        paths.emplace_back(std::string(userProfile) + "\\AppData\\Local\\Temp");
        paths.emplace_back(std::string(userProfile) + "\\AppData\\Roaming");
        free(userProfile);
    }
    
    // System temp
    char* temp = nullptr;
    if (_dupenv_s(&temp, &len, "TEMP") == 0 && temp) {
        paths.emplace_back(temp);
        free(temp);
    }
    
    // Common startup locations
    paths.emplace_back("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
#else
    // Linux quick scan paths
    if (auto home = std::getenv("HOME")) {
        paths.emplace_back(std::string(home) + "/Downloads");
        paths.emplace_back(std::string(home) + "/Desktop");
        paths.emplace_back("/tmp");
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
