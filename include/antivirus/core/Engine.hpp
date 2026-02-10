/**
 * @file Engine.hpp
 * @brief Core antivirus engine implementation
 * 
 * The Engine class is the central orchestrator that coordinates
 * all scanning operations and manages subsystem lifecycles.
 */

#pragma once

#include "antivirus/core/IEngine.hpp"
#include "antivirus/scanner/IFileScanner.hpp"
#include "antivirus/threading/IThreadPool.hpp"
#include "antivirus/detection/SignatureDatabase.hpp"
#include "antivirus/detection/HashEngine.hpp"
#include "antivirus/detection/PatternMatcher.hpp"
#include "antivirus/quarantine/IQuarantineManager.hpp"
#include "antivirus/logging/ILogger.hpp"
#include "antivirus/config/IConfigManager.hpp"
#include "antivirus/gpu/IGpuCompute.hpp"

#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <queue>

namespace antivirus {

/**
 * @class Engine
 * @brief Production implementation of IEngine
 * 
 * Design decisions:
 * - Uses dependency injection for all subsystems (testability)
 * - Thread-safe state management with mutex protection
 * - Non-blocking callbacks via internal queue
 * - RAII-based resource management
 */
class Engine final : public IEngine {
public:
    /**
     * @brief Construct engine with injected dependencies
     * 
     * All dependencies are provided externally for flexibility
     * and testability. Use EngineBuilder for convenient construction.
     */
    Engine(
        std::shared_ptr<IFileScanner> scanner,
        std::shared_ptr<IThreadPool> threadPool,
        std::shared_ptr<SignatureDatabase> signatureDb,
        std::shared_ptr<HashEngine> hashEngine,
        std::shared_ptr<PatternMatcher> patternMatcher,
        std::shared_ptr<IQuarantineManager> quarantine,
        std::shared_ptr<ILogger> logger,
        std::shared_ptr<IConfigManager> config,
        std::shared_ptr<IGpuCompute> gpuCompute = nullptr
    );
    
    ~Engine() override;
    
    // IEngine interface implementation
    [[nodiscard]] bool Initialize() override;
    void Shutdown() override;
    [[nodiscard]] bool IsReady() const noexcept override;
    
    [[nodiscard]] bool StartScan(const ScanConfig& config) override;
    [[nodiscard]] bool StartQuickScan() override;
    [[nodiscard]] bool StartFullScan() override;
    [[nodiscard]] bool StartCustomScan(const std::vector<FilePath>& paths) override;
    
    void PauseScan() override;
    void ResumeScan() override;
    void CancelScan() override;
    
    [[nodiscard]] ScanState GetState() const noexcept override;
    [[nodiscard]] const ScanStatistics& GetStatistics() const noexcept override;
    [[nodiscard]] std::vector<ScanResult> GetResults() const override;
    
    void SetScanCallback(ScanCallback callback) override;
    void SetThreatCallback(ThreatCallback callback) override;
    void SetProgressCallback(ProgressCallback callback) override;
    void SetStateCallback(StateCallback callback) override;
    
    [[nodiscard]] bool ReloadSignatures() override;
    [[nodiscard]] size_t GetSignatureCount() const noexcept override;

private:
    // ========================================================================
    // Internal Methods
    // ========================================================================
    
    void SetState(ScanState newState);
    void ProcessFile(const FileInfo& fileInfo);
    void OnFileEnumerated(const FileInfo& fileInfo);
    void OnScanComplete();
    ScanResult ScanFileContent(const FileInfo& fileInfo);
    void HandleThreat(const FileInfo& fileInfo, const ThreatInfo& threat);
    
    std::vector<FilePath> GetQuickScanPaths() const;
    std::vector<FilePath> GetFullScanPaths() const;
    
    // ========================================================================
    // Dependencies (injected)
    // ========================================================================
    
    std::shared_ptr<IFileScanner> m_scanner;
    std::shared_ptr<IThreadPool> m_threadPool;
    std::shared_ptr<SignatureDatabase> m_signatureDb;
    std::shared_ptr<HashEngine> m_hashEngine;
    std::shared_ptr<PatternMatcher> m_patternMatcher;
    std::shared_ptr<IQuarantineManager> m_quarantine;
    std::shared_ptr<ILogger> m_logger;
    std::shared_ptr<IConfigManager> m_config;
    std::shared_ptr<IGpuCompute> m_gpuCompute;
    
    // ========================================================================
    // State
    // ========================================================================
    
    mutable std::shared_mutex m_stateMutex;
    std::atomic<ScanState> m_state{ScanState::Idle};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdownRequested{false};
    
    ScanConfig m_currentConfig;
    ScanStatistics m_stats;
    
    mutable std::mutex m_resultsMutex;
    std::vector<ScanResult> m_results;
    
    // ========================================================================
    // Callbacks
    // ========================================================================
    
    mutable std::mutex m_callbackMutex;
    ScanCallback m_scanCallback;
    ThreatCallback m_threatCallback;
    ProgressCallback m_progressCallback;
    StateCallback m_stateCallback;
    
    // ========================================================================
    // Synchronization
    // ========================================================================
    
    std::condition_variable m_pauseCondition;
    std::mutex m_pauseMutex;
    std::atomic<bool> m_paused{false};
};

/**
 * @class EngineBuilder
 * @brief Builder pattern for convenient Engine construction
 */
class EngineBuilder {
public:
    EngineBuilder& WithScanner(std::shared_ptr<IFileScanner> scanner);
    EngineBuilder& WithThreadPool(std::shared_ptr<IThreadPool> pool);
    EngineBuilder& WithSignatureDatabase(std::shared_ptr<SignatureDatabase> db);
    EngineBuilder& WithHashEngine(std::shared_ptr<HashEngine> engine);
    EngineBuilder& WithPatternMatcher(std::shared_ptr<PatternMatcher> matcher);
    EngineBuilder& WithQuarantine(std::shared_ptr<IQuarantineManager> quarantine);
    EngineBuilder& WithLogger(std::shared_ptr<ILogger> logger);
    EngineBuilder& WithConfig(std::shared_ptr<IConfigManager> config);
    EngineBuilder& WithGpuCompute(std::shared_ptr<IGpuCompute> gpu);
    
    [[nodiscard]] std::unique_ptr<Engine> Build();
    
private:
    std::shared_ptr<IFileScanner> m_scanner;
    std::shared_ptr<IThreadPool> m_threadPool;
    std::shared_ptr<SignatureDatabase> m_signatureDb;
    std::shared_ptr<HashEngine> m_hashEngine;
    std::shared_ptr<PatternMatcher> m_patternMatcher;
    std::shared_ptr<IQuarantineManager> m_quarantine;
    std::shared_ptr<ILogger> m_logger;
    std::shared_ptr<IConfigManager> m_config;
    std::shared_ptr<IGpuCompute> m_gpuCompute;
};

}  // namespace antivirus
