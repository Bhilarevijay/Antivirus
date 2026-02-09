/**
 * @file IQuarantineManager.hpp
 * @brief Quarantine management interface
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include "antivirus/quarantine/QuarantineEntry.hpp"

#include <memory>
#include <vector>
#include <optional>

namespace antivirus {

/**
 * @interface IQuarantineManager
 * @brief Interface for quarantine operations
 */
class IQuarantineManager {
public:
    virtual ~IQuarantineManager() = default;
    
    /**
     * @brief Quarantine a file
     * @param path Path to file to quarantine
     * @param threat Threat information
     * @return Quarantine entry if successful
     */
    [[nodiscard]] virtual std::optional<QuarantineEntry> Quarantine(
        const FilePath& path,
        const ThreatInfo& threat
    ) = 0;
    
    /**
     * @brief Restore a quarantined file
     * @param entryId Quarantine entry ID
     * @param restorePath Path to restore to (empty = original)
     * @return true if restored successfully
     */
    [[nodiscard]] virtual bool Restore(
        const std::string& entryId,
        const FilePath& restorePath = {}
    ) = 0;
    
    /**
     * @brief Delete a quarantined file permanently
     * @param entryId Quarantine entry ID
     * @return true if deleted successfully
     */
    [[nodiscard]] virtual bool Delete(const std::string& entryId) = 0;
    
    /**
     * @brief Get all quarantine entries
     */
    [[nodiscard]] virtual std::vector<QuarantineEntry> GetEntries() const = 0;
    
    /**
     * @brief Get specific quarantine entry
     */
    [[nodiscard]] virtual std::optional<QuarantineEntry> GetEntry(
        const std::string& entryId
    ) const = 0;
    
    /**
     * @brief Clean up old quarantine entries
     * @param maxAgeDays Maximum age in days
     * @return Number of entries removed
     */
    [[nodiscard]] virtual size_t Cleanup(uint32_t maxAgeDays = 30) = 0;
    
    /**
     * @brief Get quarantine folder path
     */
    [[nodiscard]] virtual FilePath GetQuarantinePath() const = 0;
    
    /**
     * @brief Get total size of quarantined files
     */
    [[nodiscard]] virtual FileSize GetTotalSize() const = 0;
    
    /**
     * @brief Get number of quarantined files
     */
    [[nodiscard]] virtual size_t GetEntryCount() const = 0;

protected:
    IQuarantineManager() = default;
};

using IQuarantineManagerPtr = std::shared_ptr<IQuarantineManager>;

}  // namespace antivirus
