/**
 * @file ScanCache.hpp
 * @brief Persistent scan cache for skipping unchanged files
 * 
 * Maintains a hash log of previously scanned files.
 * On subsequent scans, checks if files have been modified
 * by comparing timestamps, sizes, and SHA-256 hashes.
 * Dramatically speeds up repeated scans.
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include "antivirus/logging/ILogger.hpp"

#include <unordered_map>
#include <shared_mutex>
#include <filesystem>
#include <chrono>

namespace antivirus {

/**
 * @struct CachedFileEntry
 * @brief Cached metadata + hash for a previously scanned file
 */
struct CachedFileEntry {
    std::string filePath;                  ///< Canonical file path
    uint64_t fileSize{0};                  ///< Size at time of scan
    int64_t lastModifiedEpoch{0};          ///< Last modified time (epoch seconds)
    std::string sha256Hex;                 ///< SHA-256 hash hex string
    int64_t scanTimeEpoch{0};              ///< When this file was scanned
    bool wasClean{true};                   ///< true = clean, false = infected
};

/**
 * @class ScanCache
 * @brief Persistent file scan cache with automatic modification detection
 * 
 * Strategy:
 * 1. Fast check: compare file size + last_modified timestamp
 * 2. If metadata matches → skip (file unchanged since last scan)
 * 3. If metadata differs → re-scan and update cache
 * 4. If file not in cache → scan and add to cache
 * 
 * The cache is persisted to disk between sessions, surviving
 * application restarts and machine reboots.
 * 
 * Thread-safety: All public methods are thread-safe.
 */
class ScanCache {
public:
    /**
     * @brief Create scan cache
     * @param cachePath Path to the cache file on disk
     * @param logger Logger for diagnostics
     */
    ScanCache(const std::filesystem::path& cachePath,
              std::shared_ptr<ILogger> logger);
    
    ~ScanCache();
    
    /**
     * @brief Load cache from disk
     * @return Number of entries loaded
     */
    size_t Load();
    
    /**
     * @brief Save cache to disk
     * @return true if saved successfully
     */
    bool Save() const;
    
    /**
     * @brief Check if a file can be skipped (unchanged since last clean scan)
     * @param path File path
     * @param currentSize Current file size
     * @param currentModTime Current last-modified time
     * @return true if file is unchanged and was clean → safe to skip
     */
    [[nodiscard]] bool CanSkipFile(
        const FilePath& path,
        uint64_t currentSize,
        int64_t currentModTimeEpoch
    ) const;
    
    /**
     * @brief Update cache entry after scanning a file
     * @param path File path
     * @param fileSize File size
     * @param modTimeEpoch Last modified time (epoch)
     * @param sha256Hex SHA-256 hash as hex string
     * @param isClean Whether the file was clean
     */
    void UpdateEntry(
        const FilePath& path,
        uint64_t fileSize,
        int64_t modTimeEpoch,
        const std::string& sha256Hex,
        bool isClean
    );
    
    /**
     * @brief Remove a specific file from cache
     */
    void RemoveEntry(const FilePath& path);
    
    /**
     * @brief Clear entire cache
     */
    void Clear();
    
    /**
     * @brief Get number of cached entries
     */
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    
    /**
     * @brief Get number of files skipped due to cache hits this session
     */
    [[nodiscard]] uint64_t GetCacheHits() const noexcept { return m_cacheHits.load(); }

private:
    [[nodiscard]] std::string NormalizePath(const FilePath& path) const;
    
    std::filesystem::path m_cachePath;
    std::shared_ptr<ILogger> m_logger;
    
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, CachedFileEntry> m_entries;
    
    mutable std::atomic<uint64_t> m_cacheHits{0};
    
    static constexpr uint32_t CACHE_VERSION = 1;
};

}  // namespace antivirus
