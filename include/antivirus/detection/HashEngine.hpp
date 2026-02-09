/**
 * @file HashEngine.hpp
 * @brief Cryptographic hash computation engine
 * 
 * Provides high-performance hash computation for MD5, SHA-1, and SHA-256
 * with chunked file reading for memory efficiency.
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include <span>
#include <memory>
#include <array>

namespace antivirus {

/**
 * @class HashEngine
 * @brief High-performance hash computation
 * 
 * Features:
 * - MD5, SHA-1, SHA-256 support
 * - Chunked file hashing (memory efficient)
 * - SIMD optimization where available
 * - Optional GPU offloading
 */
class HashEngine {
public:
    HashEngine();
    ~HashEngine();
    
    // Non-copyable
    HashEngine(const HashEngine&) = delete;
    HashEngine& operator=(const HashEngine&) = delete;
    
    /**
     * @brief Compute MD5 hash of data
     */
    [[nodiscard]] MD5Hash ComputeMD5(std::span<const uint8_t> data) const;
    
    /**
     * @brief Compute SHA-1 hash of data
     */
    [[nodiscard]] SHA1Hash ComputeSHA1(std::span<const uint8_t> data) const;
    
    /**
     * @brief Compute SHA-256 hash of data
     */
    [[nodiscard]] SHA256Hash ComputeSHA256(std::span<const uint8_t> data) const;
    
    /**
     * @brief Compute hash of a file
     * @param path Path to file
     * @param type Hash algorithm to use
     * @return Hash bytes (size depends on algorithm)
     */
    [[nodiscard]] std::vector<uint8_t> ComputeFileHash(
        const FilePath& path,
        HashType type
    ) const;
    
    /**
     * @brief Compute all hashes simultaneously (more efficient)
     * @param data Input data
     * @param md5 Output MD5 hash
     * @param sha1 Output SHA-1 hash
     * @param sha256 Output SHA-256 hash
     */
    void ComputeAllHashes(
        std::span<const uint8_t> data,
        MD5Hash& md5,
        SHA1Hash& sha1,
        SHA256Hash& sha256
    ) const;
    
    /**
     * @brief Convert hash bytes to hex string
     */
    [[nodiscard]] static std::string HashToHex(
        std::span<const uint8_t> hash
    );
    
    /**
     * @brief Parse hex string to hash bytes
     */
    [[nodiscard]] static std::vector<uint8_t> HexToHash(
        const std::string& hex
    );
    
    /**
     * @brief Compare two hashes
     */
    [[nodiscard]] static bool HashesEqual(
        std::span<const uint8_t> a,
        std::span<const uint8_t> b
    );

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace antivirus
