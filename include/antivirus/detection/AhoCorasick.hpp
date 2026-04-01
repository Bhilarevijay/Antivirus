/**
 * @file AhoCorasick.hpp
 * @brief Aho-Corasick multi-pattern string matching
 * 
 * Efficient algorithm for matching multiple patterns simultaneously
 * in a single pass through the input data.
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <span>
#include <cstdint>

namespace antivirus {

/**
 * @struct PatternMatch
 * @brief Result of a pattern match
 */
struct PatternMatch {
    size_t patternId;       ///< ID of the matched pattern
    size_t offset;          ///< Byte offset where match starts
    size_t length;          ///< Length of the matched pattern
};

/**
 * @class AhoCorasick
 * @brief Multi-pattern matching using Aho-Corasick algorithm
 * 
 * Time Complexity: O(n + m + z)
 * - n: text length
 * - m: total pattern length
 * - z: number of matches
 * 
 * Space Complexity: O(m * alphabet_size)
 */
class AhoCorasick {
public:
    AhoCorasick();
    ~AhoCorasick();
    
    // Non-copyable, movable
    AhoCorasick(const AhoCorasick&) = delete;
    AhoCorasick& operator=(const AhoCorasick&) = delete;
    AhoCorasick(AhoCorasick&&) noexcept;
    AhoCorasick& operator=(AhoCorasick&&) noexcept;
    
    /**
     * @brief Add a pattern to match
     * @param pattern Pattern bytes
     * @param patternId User-defined pattern identifier
     */
    void AddPattern(std::span<const uint8_t> pattern, size_t patternId);
    
    /**
     * @brief Add a hex string pattern (e.g., "4D5A90" for MZ header)
     * @param hexPattern Pattern as hex string
     * @param patternId User-defined pattern identifier
     */
    void AddHexPattern(const std::string& hexPattern, size_t patternId);
    
    /**
     * @brief Build the automaton (must call after adding all patterns)
     */
    void Build();
    
    /**
     * @brief Search for all patterns in the input
     * @param text Input bytes to search
     * @return Vector of all matches found
     */
    [[nodiscard]] std::vector<PatternMatch> Search(
        std::span<const uint8_t> text
    ) const;
    
    /**
     * @brief Search and call callback for each match
     * @param text Input bytes
     * @param callback Called for each match
     */
    void Search(
        std::span<const uint8_t> text,
        std::function<void(const PatternMatch&)> callback
    ) const;
    
    /**
     * @brief Check if any pattern matches (early exit)
     * @param text Input bytes
     * @return true if any pattern matches
     */
    [[nodiscard]] bool ContainsAny(std::span<const uint8_t> text) const;
    
    /**
     * @brief Get number of patterns
     */
    [[nodiscard]] size_t GetPatternCount() const noexcept;
    
    /**
     * @brief Clear all patterns (requires rebuild)
     */
    void Clear();
    
    /**
     * @brief Check if automaton is built
     */
    [[nodiscard]] bool IsBuilt() const noexcept { return m_built; }

private:
    struct Node {
        std::unordered_map<uint8_t, size_t> children;
        size_t failureLink{0};
        size_t outputLink{0};
        std::vector<size_t> outputs;  // Pattern IDs that end here
    };
    
    void BuildFailureLinks();
    void BuildOutputLinks();
    
    [[nodiscard]] static std::vector<uint8_t> HexStringToBytes(
        const std::string& hex
    );
    
    std::vector<Node> m_nodes;
    std::vector<size_t> m_patternLengths;
    bool m_built{false};
};

}  // namespace antivirus
