/**
 * @file AhoCorasick.cpp
 * @brief Aho-Corasick multi-pattern matching implementation
 */

#include "antivirus/detection/AhoCorasick.hpp"
#include <queue>
#include <algorithm>
#include <stdexcept>

namespace antivirus {

AhoCorasick::AhoCorasick() {
    // Initialize with root node
    m_nodes.emplace_back();
}

AhoCorasick::~AhoCorasick() = default;

AhoCorasick::AhoCorasick(AhoCorasick&&) noexcept = default;
AhoCorasick& AhoCorasick::operator=(AhoCorasick&&) noexcept = default;

void AhoCorasick::AddPattern(std::span<const uint8_t> pattern, size_t patternId) {
    if (m_built) {
        throw std::logic_error("Cannot add patterns after building");
    }
    
    if (pattern.empty()) {
        return;
    }
    
    size_t current = 0;  // Start at root
    
    for (uint8_t byte : pattern) {
        // Do NOT hold a reference to m_nodes[current] across emplace_back!
        // emplace_back may reallocate the vector, invalidating all references.
        auto it = m_nodes[current].children.find(byte);
        if (it == m_nodes[current].children.end()) {
            // Create new node
            size_t newNode = m_nodes.size();
            m_nodes.emplace_back();
            // Access m_nodes[current] AFTER emplace_back via index, not reference
            m_nodes[current].children[byte] = newNode;
            current = newNode;
        } else {
            current = it->second;
        }
    }
    
    // Mark end of pattern
    m_nodes[current].outputs.push_back(patternId);
    m_patternLengths.resize(std::max(m_patternLengths.size(), patternId + 1));
    m_patternLengths[patternId] = pattern.size();
}

void AhoCorasick::AddHexPattern(const std::string& hexPattern, size_t patternId) {
    auto bytes = HexStringToBytes(hexPattern);
    AddPattern(bytes, patternId);
}

void AhoCorasick::Build() {
    if (m_built) {
        return;
    }
    
    BuildFailureLinks();
    BuildOutputLinks();
    m_built = true;
}

void AhoCorasick::BuildFailureLinks() {
    std::queue<size_t> queue;
    
    // Initialize depth-1 nodes with failure to root
    for (const auto& [byte, child] : m_nodes[0].children) {
        m_nodes[child].failureLink = 0;
        queue.push(child);
    }
    
    // BFS to build failure links
    while (!queue.empty()) {
        size_t current = queue.front();
        queue.pop();
        
        for (const auto& [byte, child] : m_nodes[current].children) {
            queue.push(child);
            
            // Find failure link for child
            size_t failure = m_nodes[current].failureLink;
            
            while (failure != 0 && 
                   m_nodes[failure].children.find(byte) == m_nodes[failure].children.end()) {
                failure = m_nodes[failure].failureLink;
            }
            
            auto it = m_nodes[failure].children.find(byte);
            if (it != m_nodes[failure].children.end() && it->second != child) {
                m_nodes[child].failureLink = it->second;
            } else {
                m_nodes[child].failureLink = 0;
            }
        }
    }
}

void AhoCorasick::BuildOutputLinks() {
    std::queue<size_t> queue;
    
    // BFS to build output links
    for (const auto& [byte, child] : m_nodes[0].children) {
        queue.push(child);
    }
    
    while (!queue.empty()) {
        size_t current = queue.front();
        queue.pop();
        
        // Output link points to nearest ancestor with output
        size_t failure = m_nodes[current].failureLink;
        
        if (!m_nodes[failure].outputs.empty()) {
            m_nodes[current].outputLink = failure;
        } else {
            m_nodes[current].outputLink = m_nodes[failure].outputLink;
        }
        
        for (const auto& [byte, child] : m_nodes[current].children) {
            queue.push(child);
        }
    }
}

std::vector<PatternMatch> AhoCorasick::Search(std::span<const uint8_t> text) const {
    std::vector<PatternMatch> matches;
    
    Search(text, [&matches](const PatternMatch& match) {
        matches.push_back(match);
    });
    
    return matches;
}

void AhoCorasick::Search(
    std::span<const uint8_t> text,
    std::function<void(const PatternMatch&)> callback
) const {
    if (!m_built || text.empty()) {
        return;
    }
    
    size_t current = 0;
    
    for (size_t i = 0; i < text.size(); ++i) {
        uint8_t byte = text[i];
        
        // Follow failure links until we find a match or reach root
        while (current != 0 && 
               m_nodes[current].children.find(byte) == m_nodes[current].children.end()) {
            current = m_nodes[current].failureLink;
        }
        
        auto it = m_nodes[current].children.find(byte);
        if (it != m_nodes[current].children.end()) {
            current = it->second;
        }
        
        // Report all patterns ending here
        size_t temp = current;
        while (temp != 0) {
            for (size_t patternId : m_nodes[temp].outputs) {
                PatternMatch match;
                match.patternId = patternId;
                match.length = m_patternLengths[patternId];
                match.offset = i + 1 - match.length;
                callback(match);
            }
            temp = m_nodes[temp].outputLink;
        }
    }
}

bool AhoCorasick::ContainsAny(std::span<const uint8_t> text) const {
    if (!m_built || text.empty()) {
        return false;
    }
    
    size_t current = 0;
    
    for (size_t i = 0; i < text.size(); ++i) {
        uint8_t byte = text[i];
        
        while (current != 0 && 
               m_nodes[current].children.find(byte) == m_nodes[current].children.end()) {
            current = m_nodes[current].failureLink;
        }
        
        auto it = m_nodes[current].children.find(byte);
        if (it != m_nodes[current].children.end()) {
            current = it->second;
        }
        
        // Check for any match
        size_t temp = current;
        while (temp != 0) {
            if (!m_nodes[temp].outputs.empty()) {
                return true;
            }
            temp = m_nodes[temp].outputLink;
        }
    }
    
    return false;
}

size_t AhoCorasick::GetPatternCount() const noexcept {
    size_t count = 0;
    for (const auto& node : m_nodes) {
        count += node.outputs.size();
    }
    return count;
}

void AhoCorasick::Clear() {
    m_nodes.clear();
    m_nodes.emplace_back();  // Root node
    m_patternLengths.clear();
    m_built = false;
}

std::vector<uint8_t> AhoCorasick::HexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto parseNibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        
        uint8_t byte = (parseNibble(hex[i]) << 4) | parseNibble(hex[i + 1]);
        bytes.push_back(byte);
    }
    
    return bytes;
}

}  // namespace antivirus
