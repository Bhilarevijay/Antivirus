/**
 * @file SignatureDatabase.hpp
 * @brief Malware signature database manager
 * 
 * Manages loading, storing, and querying malware signatures
 * including hash-based and pattern-based signatures.
 */

#pragma once

#include "antivirus/detection/BloomFilter.hpp"
#include "antivirus/detection/PatternMatcher.hpp"
#include "antivirus/core/Types.hpp"
#include "antivirus/logging/ILogger.hpp"

#include <unordered_map>
#include <shared_mutex>
#include <filesystem>

namespace antivirus {

/**
 * @class SignatureDatabase
 * @brief Central malware signature repository
 * 
 * Features:
 * - Hash-based signature lookup (O(1) with bloom filter)
 * - Pattern-based signature matching
 * - Thread-safe concurrent access
 * - Incremental updates supported
 */
class SignatureDatabase {
public:
    /**
     * @brief Create signature database
     * @param logger Logger for diagnostics
     * @param expectedSignatures Expected number of signatures (for bloom filter sizing)
     */
    SignatureDatabase(
        std::shared_ptr<ILogger> logger,
        size_t expectedSignatures = 1000000
    );
    
    ~SignatureDatabase();
    
    /**
     * @brief Load signatures from file
     * @param path Path to signature database file
     * @return true if loaded successfully
     */
    [[nodiscard]] bool Load(const std::filesystem::path& path);
    
    /**
     * @brief Load all .db signature files from a directory
     * @param dirPath Directory containing .db files
     * @return true if at least one file loaded
     */
    [[nodiscard]] bool LoadDirectory(const std::filesystem::path& dirPath);
    
    /**
     * @brief Save signatures to file
     * @param path Path to save to
     * @return true if saved successfully
     */
    [[nodiscard]] bool Save(const std::filesystem::path& path) const;
    
    /**
     * @brief Add a hash-based signature
     */
    void AddHashSignature(const SignatureEntry& entry);
    
    /**
     * @brief Add a pattern-based signature
     */
    void AddPatternSignature(const SignatureEntry& entry);
    
    /**
     * @brief Look up signature by hash
     * @param hash Hash bytes
     * @return Signature entry if found
     */
    [[nodiscard]] std::optional<SignatureEntry> LookupByHash(
        std::span<const uint8_t> hash,
        HashType type
    ) const;
    
    /**
     * @brief Quick check if hash might match (bloom filter)
     */
    [[nodiscard]] bool MayMatchHash(
        std::span<const uint8_t> hash,
        HashType type
    ) const;
    
    /**
     * @brief Scan data for pattern signatures
     * @param data File content
     * @return Vector of matching signatures with offsets
     */
    [[nodiscard]] std::vector<std::pair<SignatureEntry, size_t>> ScanPatterns(
        std::span<const uint8_t> data
    ) const;
    
    /**
     * @brief Get total signature count
     */
    [[nodiscard]] size_t GetSignatureCount() const noexcept;
    
    /**
     * @brief Get hash signature count
     */
    [[nodiscard]] size_t GetHashSignatureCount() const noexcept;
    
    /**
     * @brief Get pattern signature count
     */
    [[nodiscard]] size_t GetPatternSignatureCount() const noexcept;
    
    /**
     * @brief Clear all signatures
     */
    void Clear();
    
    /**
     * @brief Build indexes for efficient searching (call after bulk loading)
     */
    void BuildIndexes();

private:
    /// Internal: load a single file without locking/clearing/building
    [[nodiscard]] size_t LoadFileInternal(const std::filesystem::path& path);
    [[nodiscard]] size_t GetHashSignatureCountInternal() const noexcept;
    [[nodiscard]] size_t GetPatternSignatureCountInternal() const noexcept;

    std::shared_ptr<ILogger> m_logger;
    
    // Thread safety
    mutable std::shared_mutex m_mutex;
    
    // Hash-based signatures with bloom filter
    std::unique_ptr<BloomFilter> m_md5Bloom;
    std::unique_ptr<BloomFilter> m_sha1Bloom;
    std::unique_ptr<BloomFilter> m_sha256Bloom;
    
    std::unordered_map<std::string, SignatureEntry> m_md5Signatures;
    std::unordered_map<std::string, SignatureEntry> m_sha1Signatures;
    std::unordered_map<std::string, SignatureEntry> m_sha256Signatures;
    
    // Pattern-based signatures
    std::unique_ptr<PatternMatcher> m_patternMatcher;
    std::unordered_map<std::string, SignatureEntry> m_patternSignatures;
};

}  // namespace antivirus
