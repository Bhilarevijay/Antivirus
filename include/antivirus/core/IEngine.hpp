/**
 * @file IEngine.hpp
 * @brief Abstract interface for the antivirus core engine
 * 
 * Defines the contract for engine implementations, enabling
 * dependency injection and testability.
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include <memory>

namespace antivirus {

/**
 * @interface IEngine
 * @brief Core engine interface for antivirus operations
 * 
 * The engine is the central orchestrator that coordinates all
 * scanning operations, manages subsystems, and handles lifecycle.
 */
class IEngine {
public:
    virtual ~IEngine() = default;
    
    // Prevent copying, allow moving
    IEngine(const IEngine&) = delete;
    IEngine& operator=(const IEngine&) = delete;
    IEngine(IEngine&&) = default;
    IEngine& operator=(IEngine&&) = default;
    
    // ========================================================================
    // Lifecycle Management
    // ========================================================================
    
    /**
     * @brief Initialize the engine with configuration
     * @return true if initialization successful
     */
    [[nodiscard]] virtual bool Initialize() = 0;
    
    /**
     * @brief Shutdown the engine gracefully
     */
    virtual void Shutdown() = 0;
    
    /**
     * @brief Check if engine is initialized and ready
     */
    [[nodiscard]] virtual bool IsReady() const noexcept = 0;
    
    // ========================================================================
    // Scan Operations
    // ========================================================================
    
    /**
     * @brief Start a scan with the given configuration
     * @param config Scan configuration
     * @return true if scan started successfully
     */
    [[nodiscard]] virtual bool StartScan(const ScanConfig& config) = 0;
    
    /**
     * @brief Start a quick scan of default locations
     */
    [[nodiscard]] virtual bool StartQuickScan() = 0;
    
    /**
     * @brief Start a full system scan
     */
    [[nodiscard]] virtual bool StartFullScan() = 0;
    
    /**
     * @brief Start a custom scan of specified paths
     * @param paths Paths to scan
     */
    [[nodiscard]] virtual bool StartCustomScan(const std::vector<FilePath>& paths) = 0;
    
    /**
     * @brief Pause the current scan
     */
    virtual void PauseScan() = 0;
    
    /**
     * @brief Resume a paused scan
     */
    virtual void ResumeScan() = 0;
    
    /**
     * @brief Cancel the current scan
     */
    virtual void CancelScan() = 0;
    
    // ========================================================================
    // Status & Statistics
    // ========================================================================
    
    /**
     * @brief Get current scan state
     */
    [[nodiscard]] virtual ScanState GetState() const noexcept = 0;
    
    /**
     * @brief Get current scan statistics
     */
    [[nodiscard]] virtual const ScanStatistics& GetStatistics() const noexcept = 0;
    
    /**
     * @brief Get last scan results
     */
    [[nodiscard]] virtual std::vector<ScanResult> GetResults() const = 0;
    
    // ========================================================================
    // Callbacks
    // ========================================================================
    
    /**
     * @brief Register callback for scan completion events
     */
    virtual void SetScanCallback(ScanCallback callback) = 0;
    
    /**
     * @brief Register callback for threat detection events
     */
    virtual void SetThreatCallback(ThreatCallback callback) = 0;
    
    /**
     * @brief Register callback for progress updates
     */
    virtual void SetProgressCallback(ProgressCallback callback) = 0;
    
    /**
     * @brief Register callback for state changes
     */
    virtual void SetStateCallback(StateCallback callback) = 0;
    
    // ========================================================================
    // Signature Database
    // ========================================================================
    
    /**
     * @brief Reload signature database from disk
     */
    [[nodiscard]] virtual bool ReloadSignatures() = 0;
    
    /**
     * @brief Get number of loaded signatures
     */
    [[nodiscard]] virtual size_t GetSignatureCount() const noexcept = 0;
    
protected:
    IEngine() = default;
};

/// Shared pointer type for engine instances
using IEnginePtr = std::shared_ptr<IEngine>;

}  // namespace antivirus
