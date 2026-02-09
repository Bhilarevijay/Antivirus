/**
 * @file PatternMatcher.cpp
 * @brief Pattern matching coordinator implementation
 */

#include "antivirus/detection/PatternMatcher.hpp"

namespace antivirus {

PatternMatcher::PatternMatcher() = default;
PatternMatcher::~PatternMatcher() = default;

void PatternMatcher::AddPattern(
    const std::string& hexPattern,
    const std::string& signatureId
) {
    m_automaton.AddHexPattern(hexPattern, m_nextPatternId);
    m_patternIdToSignature[m_nextPatternId] = signatureId;
    ++m_nextPatternId;
}

void PatternMatcher::AddPattern(
    std::span<const uint8_t> pattern,
    const std::string& signatureId
) {
    m_automaton.AddPattern(pattern, m_nextPatternId);
    m_patternIdToSignature[m_nextPatternId] = signatureId;
    ++m_nextPatternId;
}

void PatternMatcher::Build() {
    m_automaton.Build();
}

std::vector<std::pair<std::string, size_t>> PatternMatcher::Scan(
    std::span<const uint8_t> data
) const {
    std::vector<std::pair<std::string, size_t>> results;
    
    auto matches = m_automaton.Search(data);
    
    for (const auto& match : matches) {
        auto it = m_patternIdToSignature.find(match.patternId);
        if (it != m_patternIdToSignature.end()) {
            results.emplace_back(it->second, match.offset);
        }
    }
    
    return results;
}

bool PatternMatcher::ContainsPattern(std::span<const uint8_t> data) const {
    return m_automaton.ContainsAny(data);
}

size_t PatternMatcher::GetPatternCount() const noexcept {
    return m_patternIdToSignature.size();
}

void PatternMatcher::Clear() {
    m_automaton.Clear();
    m_patternIdToSignature.clear();
    m_nextPatternId = 0;
}

}  // namespace antivirus
