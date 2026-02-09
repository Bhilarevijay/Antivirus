/**
 * @file Types.hpp
 * @brief Core type definitions for the antivirus engine
 * 
 * Contains fundamental types, enums, and structures used throughout
 * the antivirus codebase. All types are designed for performance and
 * thread-safety.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <atomic>
#include <functional>

namespace antivirus {

// ============================================================================
// Forward Declarations
// ============================================================================

class IEngine;
class IFileScanner;
class IThreadPool;
class IQuarantineManager;
class ILogger;

// ============================================================================
// Type Aliases
// ============================================================================

using FilePath = std::filesystem::path;
using FileSize = std::uintmax_t;
using Timestamp = std::chrono::system_clock::time_point;
using Duration = std::chrono::milliseconds;
using HashBytes = std::array<uint8_t, 32>;  // SHA-256 size
using MD5Hash = std::array<uint8_t, 16>;
using SHA1Hash = std::array<uint8_t, 20>;
using SHA256Hash = std::array<uint8_t, 32>;

// ============================================================================
// Enumerations
// ============================================================================

/**
 * @enum ScanMode
 * @brief Defines the scanning strategy
 */
enum class ScanMode : uint8_t {
    Quick,      ///< Scan critical system areas and common malware locations
    Full,       ///< Complete system scan of all accessible files
    Custom,     ///< User-defined paths only
    Memory      ///< Scan running processes (future)
};

/**
 * @enum ThreatLevel
 * @brief Severity classification for detected threats
 */
enum class ThreatLevel : uint8_t {
    None = 0,       ///< No threat detected
    Low = 1,        ///< Potentially unwanted program (PUP)
    Medium = 2,     ///< Known adware or suspicious behavior
    High = 3,       ///< Confirmed malware
    Critical = 4    ///< Ransomware, rootkit, or destructive malware
};

/**
 * @enum ScanState
 * @brief Current state of a scan operation
 */
enum class ScanState : uint8_t {
    Idle,           ///< No scan in progress
    Initializing,   ///< Loading signatures and preparing
    Scanning,       ///< Actively scanning files
    Paused,         ///< Scan temporarily suspended
    Completing,     ///< Finishing up, generating report
    Completed,      ///< Scan finished successfully
    Cancelled,      ///< Scan was cancelled by user
    Error           ///< Scan terminated due to error
};

/**
 * @enum HashType
 * @brief Supported hash algorithms
 */
enum class HashType : uint8_t {
    MD5,
    SHA1,
    SHA256
};

/**
 * @enum QuarantineAction
 * @brief Actions that can be taken on quarantined files
 */
enum class QuarantineAction : uint8_t {
    Quarantine,     ///< Move to quarantine folder
    Delete,         ///< Permanently delete
    Restore,        ///< Restore to original location
    Ignore          ///< Take no action
};

// ============================================================================
// Structures
// ============================================================================

/**
 * @struct FileInfo
 * @brief Metadata about a scanned file
 */
struct FileInfo {
    FilePath path;                      ///< Full file path
    FileSize size{0};                   ///< File size in bytes
    Timestamp lastModified;             ///< Last modification time
    bool isSymlink{false};              ///< Is this a symbolic link?
    bool isHidden{false};               ///< Is this a hidden file?
    bool isSystem{false};               ///< Is this a system file?
    bool isReadOnly{false};             ///< Is this read-only?
    
    [[nodiscard]] bool isAccessible() const noexcept {
        return size > 0;  // Simplified check
    }
};

/**
 * @struct ThreatInfo
 * @brief Information about a detected threat
 */
struct ThreatInfo {
    std::string signatureId;            ///< Unique signature identifier
    std::string threatName;             ///< Human-readable threat name
    std::string description;            ///< Threat description
    ThreatLevel level{ThreatLevel::None};
    HashType matchedHashType{HashType::SHA256};
    std::string matchedPattern;         ///< Hex pattern that matched (if any)
    size_t patternOffset{0};            ///< Offset where pattern was found
};

/**
 * @struct ScanResult
 * @brief Result of scanning a single file
 */
struct ScanResult {
    FileInfo fileInfo;                  ///< File metadata
    bool scanned{false};                ///< Was the file successfully scanned?
    bool threatDetected{false};         ///< Was a threat found?
    std::optional<ThreatInfo> threat;   ///< Threat details (if detected)
    Duration scanTime{0};               ///< Time to scan this file
    std::string errorMessage;           ///< Error if scan failed
    
    [[nodiscard]] bool isClean() const noexcept {
        return scanned && !threatDetected;
    }
};

/**
 * @struct ScanStatistics
 * @brief Aggregate statistics for a scan operation
 */
struct ScanStatistics {
    std::atomic<uint64_t> totalFiles{0};        ///< Total files enumerated
    std::atomic<uint64_t> scannedFiles{0};      ///< Files successfully scanned
    std::atomic<uint64_t> skippedFiles{0};      ///< Files skipped (access denied, etc.)
    std::atomic<uint64_t> infectedFiles{0};     ///< Files with detected threats
    std::atomic<uint64_t> quarantinedFiles{0};  ///< Files moved to quarantine
    std::atomic<uint64_t> bytesScanned{0};      ///< Total bytes processed
    std::atomic<uint64_t> errorCount{0};        ///< Number of errors encountered
    
    Timestamp startTime;                        ///< When scan started
    Timestamp endTime;                          ///< When scan ended
    
    [[nodiscard]] Duration elapsed() const noexcept {
        auto end = (endTime == Timestamp{}) 
            ? std::chrono::system_clock::now() 
            : endTime;
        return std::chrono::duration_cast<Duration>(end - startTime);
    }
    
    [[nodiscard]] double scanRate() const noexcept {
        auto ms = elapsed().count();
        return ms > 0 ? static_cast<double>(scannedFiles.load()) / (ms / 1000.0) : 0.0;
    }
};

/**
 * @struct ScanConfig
 * @brief Configuration for a scan operation
 */
struct ScanConfig {
    ScanMode mode{ScanMode::Quick};
    std::vector<FilePath> targetPaths;          ///< Paths to scan
    std::vector<FilePath> excludePaths;         ///< Paths to exclude
    std::vector<std::string> excludeExtensions; ///< Extensions to skip
    FileSize maxFileSize{100 * 1024 * 1024};    ///< Max file size (100MB default)
    bool scanArchives{true};                    ///< Scan inside archives
    bool followSymlinks{false};                 ///< Follow symbolic links
    bool scanHiddenFiles{true};                 ///< Include hidden files
    uint32_t threadCount{0};                    ///< 0 = auto-detect
    bool enableGpu{false};                      ///< Use GPU acceleration
};

/**
 * @struct SignatureEntry
 * @brief A malware signature entry
 */
struct SignatureEntry {
    std::string id;                             ///< Unique identifier
    std::string name;                           ///< Threat name
    ThreatLevel level{ThreatLevel::High};
    HashType hashType{HashType::SHA256};
    std::vector<uint8_t> hash;                  ///< Hash bytes
    std::vector<uint8_t> hexPattern;            ///< Hex pattern bytes
    size_t patternOffset{0};                    ///< Expected offset (0 = any)
};

// ============================================================================
// Callback Types
// ============================================================================

/// Called when a file scan completes
using ScanCallback = std::function<void(const ScanResult&)>;

/// Called when a threat is detected
using ThreatCallback = std::function<void(const FileInfo&, const ThreatInfo&)>;

/// Called periodically with progress updates
using ProgressCallback = std::function<void(const ScanStatistics&)>;

/// Called when scan state changes
using StateCallback = std::function<void(ScanState, ScanState)>;

// ============================================================================
// Constants
// ============================================================================

namespace constants {
    constexpr size_t DEFAULT_CHUNK_SIZE = 64 * 1024;        // 64KB read chunks
    constexpr size_t BLOOM_FILTER_SIZE = 1024 * 1024 * 8;   // 1MB bloom filter
    constexpr size_t MAX_PATH_LENGTH = 32767;               // Windows MAX_PATH extended
    constexpr uint32_t SIGNATURE_DB_VERSION = 1;
    constexpr const char* QUARANTINE_FOLDER = "Quarantine";
    constexpr const char* QUARANTINE_INDEX = "quarantine_index.json";
}

}  // namespace antivirus
