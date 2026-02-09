/**
 * @file QuarantineManager.hpp
 * @brief Windows quarantine manager implementation
 */

#pragma once

#include "antivirus/quarantine/IQuarantineManager.hpp"
#include "antivirus/logging/ILogger.hpp"

#include <mutex>
#include <unordered_map>

namespace antivirus {

/**
 * @class QuarantineManager
 * @brief Production quarantine implementation for Windows
 * 
 * Features:
 * - Secure file movement with Windows ACL
 * - Deny-execute permissions on quarantine folder
 * - JSON-based index for fast lookup
 * - File encryption (optional)
 */
class QuarantineManager final : public IQuarantineManager {
public:
    /**
     * @brief Create quarantine manager
     * @param quarantinePath Path to quarantine folder
     * @param logger Logger instance
     */
    QuarantineManager(
        const FilePath& quarantinePath,
        std::shared_ptr<ILogger> logger
    );
    
    ~QuarantineManager() override;
    
    [[nodiscard]] std::optional<QuarantineEntry> Quarantine(
        const FilePath& path,
        const ThreatInfo& threat
    ) override;
    
    [[nodiscard]] bool Restore(
        const std::string& entryId,
        const FilePath& restorePath = {}
    ) override;
    
    [[nodiscard]] bool Delete(const std::string& entryId) override;
    
    [[nodiscard]] std::vector<QuarantineEntry> GetEntries() const override;
    
    [[nodiscard]] std::optional<QuarantineEntry> GetEntry(
        const std::string& entryId
    ) const override;
    
    [[nodiscard]] size_t Cleanup(uint32_t maxAgeDays = 30) override;
    
    [[nodiscard]] FilePath GetQuarantinePath() const override;
    
    [[nodiscard]] FileSize GetTotalSize() const override;
    
    [[nodiscard]] size_t GetEntryCount() const override;

private:
    [[nodiscard]] bool Initialize();
    [[nodiscard]] bool LoadIndex();
    [[nodiscard]] bool SaveIndex();
    [[nodiscard]] std::string GenerateEntryId() const;
    [[nodiscard]] FilePath GenerateQuarantinePath(const std::string& entryId) const;
    
#ifdef _WIN32
    [[nodiscard]] bool SetQuarantineAcl();
    [[nodiscard]] bool ApplySecurityPermissions(const FilePath& path);
#endif
    
    FilePath m_quarantinePath;
    FilePath m_indexPath;
    std::shared_ptr<ILogger> m_logger;
    
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, QuarantineEntry> m_entries;
    bool m_initialized{false};
};

}  // namespace antivirus
