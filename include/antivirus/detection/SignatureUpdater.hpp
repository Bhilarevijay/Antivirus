/**
 * @file SignatureUpdater.hpp
 * @brief Online signature database updater
 * 
 * Downloads latest malware signatures from public threat
 * intelligence sources using Windows native WinHTTP.
 */

#pragma once

#include "antivirus/logging/ILogger.hpp"
#include <filesystem>
#include <string>
#include <vector>
#include <functional>
#include <unordered_set>

namespace antivirus {

/**
 * @struct UpdateStats
 * @brief Statistics from a signature update operation
 */
struct UpdateStats {
    size_t newSignatures{0};        ///< New signatures added
    size_t totalSignatures{0};      ///< Total after update
    size_t downloadedBytes{0};      ///< Bytes downloaded
    bool success{false};            ///< Overall success
    std::string errorMessage;       ///< Error details if failed
};

/// Progress callback: (bytesDownloaded, totalBytes)
using UpdateProgressCallback = std::function<void(size_t, size_t)>;

/**
 * @class SignatureUpdater
 * @brief Downloads and merges malware signatures from public APIs
 * 
 * Uses MalwareBazaar (abuse.ch) API — free, no API key required.
 * All network operations use Windows native WinHTTP (no external deps).
 */
class SignatureUpdater {
public:
    explicit SignatureUpdater(
        std::shared_ptr<ILogger> logger,
        std::filesystem::path signatureDir
    );
    
    ~SignatureUpdater();
    
    /**
     * @brief Download latest signatures from MalwareBazaar
     * @param progressCallback Optional progress reporting
     * @return Update statistics
     */
    UpdateStats UpdateFromMalwareBazaar(
        UpdateProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Set maximum number of hashes to download per update
     */
    void SetMaxDownloadCount(size_t count) { m_maxDownload = count; }

private:
    /// Download data from URL via WinHTTP
    std::string HttpPost(
        const std::string& host,
        const std::string& path,
        const std::string& postData,
        const std::string& contentType
    );
    
    /// Parse MalwareBazaar JSON response and extract SHA256 hashes
    std::vector<std::pair<std::string, std::string>> ParseMalwareBazaarResponse(
        const std::string& json
    );
    
    /// Merge new hashes into the signature file
    size_t MergeSignatures(
        const std::vector<std::pair<std::string, std::string>>& newHashes
    );
    
    /// Load existing hashes to avoid duplicates
    std::unordered_set<std::string> LoadExistingHashes();
    
    std::shared_ptr<ILogger> m_logger;
    std::filesystem::path m_signatureDir;
    size_t m_maxDownload{1000};
};

}  // namespace antivirus
