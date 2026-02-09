/**
 * @file ConfigManager.hpp
 * @brief JSON-based configuration management
 */

#pragma once

#include "antivirus/config/IConfigManager.hpp"
#include <filesystem>
#include <mutex>

namespace antivirus {

/**
 * @class ConfigManager
 * @brief Thread-safe JSON configuration manager
 * 
 * Stores configuration in JSON format for human readability.
 * Uses mutex protection for thread safety.
 */
class ConfigManager final : public IConfigManager {
public:
    /**
     * @brief Create config manager with config file path
     * @param configPath Path to JSON config file
     */
    explicit ConfigManager(const std::filesystem::path& configPath);
    
    ~ConfigManager() override = default;
    
    [[nodiscard]] bool Load() override;
    [[nodiscard]] bool Save() override;
    void ResetToDefaults() override;
    
    [[nodiscard]] ScanConfig GetDefaultScanConfig() const override;
    void SetDefaultScanConfig(const ScanConfig& config) override;
    
    [[nodiscard]] uint32_t GetThreadCount() const override;
    void SetThreadCount(uint32_t count) override;
    
    [[nodiscard]] FilePath GetQuarantinePath() const override;
    void SetQuarantinePath(const FilePath& path) override;
    
    [[nodiscard]] FilePath GetSignaturePath() const override;
    void SetSignaturePath(const FilePath& path) override;
    
    [[nodiscard]] FilePath GetLogPath() const override;
    void SetLogPath(const FilePath& path) override;
    
    [[nodiscard]] std::vector<FilePath> GetExcludedPaths() const override;
    void AddExcludedPath(const FilePath& path) override;
    void RemoveExcludedPath(const FilePath& path) override;
    
    [[nodiscard]] std::vector<std::string> GetExcludedExtensions() const override;
    void AddExcludedExtension(const std::string& ext) override;
    void RemoveExcludedExtension(const std::string& ext) override;
    
    [[nodiscard]] bool IsGpuEnabled() const override;
    void SetGpuEnabled(bool enabled) override;
    
    [[nodiscard]] FileSize GetMaxFileSize() const override;
    void SetMaxFileSize(FileSize size) override;
    
private:
    std::filesystem::path m_configPath;
    mutable std::mutex m_mutex;
    
    // Configuration data
    ScanConfig m_defaultScanConfig;
    uint32_t m_threadCount{0};  // 0 = auto
    FilePath m_quarantinePath;
    FilePath m_signaturePath;
    FilePath m_logPath;
    std::vector<FilePath> m_excludedPaths;
    std::vector<std::string> m_excludedExtensions;
    bool m_gpuEnabled{false};
    FileSize m_maxFileSize{100 * 1024 * 1024};  // 100MB
};

}  // namespace antivirus
