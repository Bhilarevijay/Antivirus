/**
 * @file IConfigManager.hpp
 * @brief Configuration management interface
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include <string>
#include <optional>
#include <memory>

namespace antivirus {

/**
 * @interface IConfigManager
 * @brief Interface for configuration management
 */
class IConfigManager {
public:
    virtual ~IConfigManager() = default;
    
    /**
     * @brief Load configuration from file
     * @return true if loaded successfully
     */
    [[nodiscard]] virtual bool Load() = 0;
    
    /**
     * @brief Save current configuration to file
     * @return true if saved successfully
     */
    [[nodiscard]] virtual bool Save() = 0;
    
    /**
     * @brief Reset to default configuration
     */
    virtual void ResetToDefaults() = 0;
    
    // ========================================================================
    // Scan Settings
    // ========================================================================
    
    [[nodiscard]] virtual ScanConfig GetDefaultScanConfig() const = 0;
    virtual void SetDefaultScanConfig(const ScanConfig& config) = 0;
    
    // ========================================================================
    // Thread Settings
    // ========================================================================
    
    [[nodiscard]] virtual uint32_t GetThreadCount() const = 0;
    virtual void SetThreadCount(uint32_t count) = 0;
    
    // ========================================================================
    // Paths
    // ========================================================================
    
    [[nodiscard]] virtual FilePath GetQuarantinePath() const = 0;
    virtual void SetQuarantinePath(const FilePath& path) = 0;
    
    [[nodiscard]] virtual FilePath GetSignaturePath() const = 0;
    virtual void SetSignaturePath(const FilePath& path) = 0;
    
    [[nodiscard]] virtual FilePath GetLogPath() const = 0;
    virtual void SetLogPath(const FilePath& path) = 0;
    
    // ========================================================================
    // Exclusions
    // ========================================================================
    
    [[nodiscard]] virtual std::vector<FilePath> GetExcludedPaths() const = 0;
    virtual void AddExcludedPath(const FilePath& path) = 0;
    virtual void RemoveExcludedPath(const FilePath& path) = 0;
    
    [[nodiscard]] virtual std::vector<std::string> GetExcludedExtensions() const = 0;
    virtual void AddExcludedExtension(const std::string& ext) = 0;
    virtual void RemoveExcludedExtension(const std::string& ext) = 0;
    
    // ========================================================================
    // Performance
    // ========================================================================
    
    [[nodiscard]] virtual bool IsGpuEnabled() const = 0;
    virtual void SetGpuEnabled(bool enabled) = 0;
    
    [[nodiscard]] virtual FileSize GetMaxFileSize() const = 0;
    virtual void SetMaxFileSize(FileSize size) = 0;
    
protected:
    IConfigManager() = default;
};

using IConfigManagerPtr = std::shared_ptr<IConfigManager>;

}  // namespace antivirus
