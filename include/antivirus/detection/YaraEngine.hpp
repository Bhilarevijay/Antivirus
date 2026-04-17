/**
 * @file YaraEngine.hpp
 * @brief YARA rule engine integration
 * 
 * Wraps libyara for advanced pattern matching using YARA rules.
 * YARA provides flexible rule-based malware detection with support
 * for regex, hex patterns, string matching, and condition logic.
 */

#pragma once

#ifdef HAS_YARA

#include "antivirus/core/Types.hpp"
#include "antivirus/logging/ILogger.hpp"

#include <memory>
#include <vector>
#include <string>
#include <filesystem>
#include <shared_mutex>
#include <span>

namespace antivirus {

/**
 * @struct YaraMatch
 * @brief Result of a YARA rule match
 */
struct YaraMatch {
    std::string ruleName;       ///< Name of the matching rule
    std::string ruleNamespace;  ///< Namespace/tag of the rule
    std::string description;    ///< Rule metadata description (if set)
    std::string author;         ///< Rule metadata author (if set)
    ThreatLevel level{ThreatLevel::High};
    std::vector<std::pair<std::string, size_t>> matchedStrings; ///< (string_id, offset)
};

/**
 * @class YaraEngine
 * @brief YARA rule compilation and scanning (PIMPL pattern)
 * 
 * Uses PIMPL to hide all libyara types from the header,
 * preventing macro/type conflicts with other headers.
 */
class YaraEngine {
public:
    explicit YaraEngine(std::shared_ptr<ILogger> logger);
    ~YaraEngine();
    
    // Non-copyable
    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;
    
    [[nodiscard]] bool Initialize();
    void Finalize();
    
    [[nodiscard]] bool LoadRuleFile(const std::filesystem::path& rulePath);
    size_t LoadRulesFromDirectory(const std::filesystem::path& dirPath);
    [[nodiscard]] bool CompileRules();
    
    [[nodiscard]] std::vector<YaraMatch> ScanBuffer(
        std::span<const uint8_t> data
    ) const;
    
    [[nodiscard]] std::vector<YaraMatch> ScanFile(
        const std::filesystem::path& filePath
    ) const;
    
    [[nodiscard]] bool IsReady() const noexcept;
    [[nodiscard]] size_t GetRuleCount() const noexcept;

private:
    // PIMPL hides all libyara types
    class Impl;
    std::unique_ptr<Impl> m_impl;
    std::shared_ptr<ILogger> m_logger;
};

}  // namespace antivirus

#endif // HAS_YARA
