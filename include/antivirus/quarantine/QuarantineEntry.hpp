/**
 * @file QuarantineEntry.hpp
 * @brief Quarantine entry metadata structure
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include <string>

namespace antivirus {

/**
 * @struct QuarantineEntry
 * @brief Metadata for a quarantined file
 */
struct QuarantineEntry {
    std::string id;                     ///< Unique entry ID (UUID)
    FilePath originalPath;              ///< Original file path
    FilePath quarantinePath;            ///< Path in quarantine folder
    std::string threatName;             ///< Name of detected threat
    std::string signatureId;            ///< Matching signature ID
    ThreatLevel threatLevel{ThreatLevel::High};
    FileSize originalSize{0};           ///< Original file size
    Timestamp quarantineTime;           ///< When file was quarantined
    SHA256Hash originalHash;            ///< Hash before quarantine
    bool encrypted{false};              ///< Whether file is encrypted
    std::string username;               ///< User who owned the file
    
    /**
     * @brief Generate JSON representation for storage
     */
    [[nodiscard]] std::string ToJson() const;
    
    /**
     * @brief Parse from JSON
     */
    [[nodiscard]] static std::optional<QuarantineEntry> FromJson(
        const std::string& json
    );
};

}  // namespace antivirus
