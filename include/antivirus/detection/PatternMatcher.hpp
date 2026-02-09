/**
 * @file PatternMatcher.hpp
 * @brief High-level pattern matching coordinator
 * 
 * Combines Bloom filter pre-screening with Aho-Corasick matching
 * for optimal performance.
 */

#pragma once

#include "antivirus/detection/AhoCorasick.hpp"
#include "antivirus/detection/BloomFilter.hpp"
#include "antivirus/detection/HashEngine.hpp"
#include "antivirus/core/Types.hpp"

#include <memory>
#include <span>

namespace antivirus {

/**
 * @class PatternMatcher
 * @brief Coordinates pattern matching operations
 * 
 * Strategy:
 * 1. Quick bloom filter check for hash
 * 2. Full Aho-Corasick scan if bloom filter positive
 * 3. SIMD optimization for byte scanning
 */
class PatternMatcher {
public:
    PatternMatcher();
    ~PatternMatcher();
    
    /**
     * @brief Add a hex pattern for matching
     * @param pattern Hex string pattern
     * @param signatureId Associated signature ID
     */
    void AddPattern(
        const std::string& hexPattern,
        const std::string& signatureId
    );
    
    /**
     * @brief Add binary pattern
     */
    void AddPattern(
        std::span<const uint8_t> pattern,
        const std::string& signatureId
    );
    
    /**
     * @brief Build matching automaton (call after adding all patterns)
     */
    void Build();
    
    /**
     * @brief Scan data for pattern matches
     * @param data File content to scan
     * @return Vector of matching signature IDs with offsets
     */
    [[nodiscard]] std::vector<std::pair<std::string, size_t>> Scan(
        std::span<const uint8_t> data
    ) const;
    
    /**
     * @brief Quick check if data contains any patterns
     */
    [[nodiscard]] bool ContainsPattern(
        std::span<const uint8_t> data
    ) const;
    
    /**
     * @brief Get number of loaded patterns
     */
    [[nodiscard]] size_t GetPatternCount() const noexcept;
    
    /**
     * @brief Clear all patterns
     */
    void Clear();

private:
    AhoCorasick m_automaton;
    std::unordered_map<size_t, std::string> m_patternIdToSignature;
    size_t m_nextPatternId{0};
};

}  // namespace antivirus
