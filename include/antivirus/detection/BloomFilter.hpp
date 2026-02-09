/**
 * @file BloomFilter.hpp
 * @brief Bloom filter for fast signature pre-screening
 * 
 * Provides O(1) negative lookups to quickly reject files that
 * definitely don't match any known malware signatures.
 */

#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <cstring>

namespace antivirus {

/**
 * @class BloomFilter
 * @brief Space-efficient probabilistic set membership
 * 
 * Properties:
 * - False positives possible (configurable rate)
 * - False negatives impossible
 * - O(1) insert and lookup
 * - Memory efficient for large signature counts
 */
class BloomFilter {
public:
    /**
     * @brief Create bloom filter with specified parameters
     * @param expectedItems Expected number of items
     * @param falsePositiveRate Target false positive rate (0-1)
     */
    BloomFilter(size_t expectedItems, double falsePositiveRate = 0.01);
    
    /**
     * @brief Create bloom filter with explicit size
     * @param bitCount Number of bits
     * @param hashCount Number of hash functions
     */
    BloomFilter(size_t bitCount, size_t hashCount);
    
    /**
     * @brief Insert item into filter
     * @param data Data bytes to insert
     */
    void Insert(std::span<const uint8_t> data);
    
    /**
     * @brief Insert a hash value directly
     */
    void InsertHash(const std::array<uint8_t, 32>& hash);
    
    /**
     * @brief Check if item might be in the filter
     * @param data Data bytes to check
     * @return true if possibly in set, false if definitely not
     */
    [[nodiscard]] bool MayContain(std::span<const uint8_t> data) const;
    
    /**
     * @brief Check if hash might be in the filter
     */
    [[nodiscard]] bool MayContainHash(const std::array<uint8_t, 32>& hash) const;
    
    /**
     * @brief Clear all entries
     */
    void Clear();
    
    /**
     * @brief Get number of bits set
     */
    [[nodiscard]] size_t GetPopulationCount() const;
    
    /**
     * @brief Get estimated false positive rate
     */
    [[nodiscard]] double GetEstimatedFalsePositiveRate() const;
    
    /**
     * @brief Get memory usage in bytes
     */
    [[nodiscard]] size_t GetMemoryUsage() const noexcept {
        return m_bits.size() / 8;
    }

private:
    /**
     * @brief Calculate hash indices using double hashing
     * @param data Input data
     * @return Array of bit indices
     */
    [[nodiscard]] std::vector<size_t> GetHashIndices(
        std::span<const uint8_t> data
    ) const;
    
    [[nodiscard]] static size_t CalculateBitCount(
        size_t expectedItems, 
        double falsePositiveRate
    );
    
    [[nodiscard]] static size_t CalculateHashCount(
        size_t bitCount, 
        size_t expectedItems
    );
    
    // MurmurHash3-based hash functions
    [[nodiscard]] static uint64_t Hash1(std::span<const uint8_t> data);
    [[nodiscard]] static uint64_t Hash2(std::span<const uint8_t> data);
    
    std::vector<bool> m_bits;
    size_t m_hashCount;
    size_t m_itemCount{0};
};

}  // namespace antivirus
