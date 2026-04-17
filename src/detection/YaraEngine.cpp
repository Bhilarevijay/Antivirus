/**
 * @file YaraEngine.cpp
 * @brief YARA rule engine implementation
 * 
 * Integrates libyara for advanced rule-based malware detection.
 * All libyara types are isolated inside the Impl class (PIMPL).
 */

#ifdef HAS_YARA

// yara.h MUST come before any std header that uses <span>
#include <yara.h>

#include "antivirus/detection/YaraEngine.hpp"
#include <fstream>
#include <algorithm>

namespace antivirus {

// ============================================================================
// YARA Callbacks
// ============================================================================

struct YaraScanContext {
    std::vector<YaraMatch>* matches;
};

static int YaraScanCallback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* messageData,
    void* userData
) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* ctx = static_cast<YaraScanContext*>(userData);
        auto* rule = static_cast<YR_RULE*>(messageData);
        
        YaraMatch match;
        match.ruleName = rule->identifier;
        match.ruleNamespace = rule->ns->name ? rule->ns->name : "";
        
        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            std::string key = meta->identifier;
            if (key == "description" && meta->type == META_TYPE_STRING) {
                match.description = meta->string;
            } else if (key == "author" && meta->type == META_TYPE_STRING) {
                match.author = meta->string;
            } else if (key == "threat_level" && meta->type == META_TYPE_INTEGER) {
                int level = static_cast<int>(meta->integer);
                if (level >= 1 && level <= 4) {
                    match.level = static_cast<ThreatLevel>(level);
                }
            }
        }
        
        YR_STRING* str;
        yr_rule_strings_foreach(rule, str) {
            YR_MATCH* m;
            yr_string_matches_foreach(context, str, m) {
                match.matchedStrings.emplace_back(
                    str->identifier ? str->identifier : "",
                    static_cast<size_t>(m->offset)
                );
            }
        }
        
        ctx->matches->push_back(std::move(match));
    }
    
    return CALLBACK_CONTINUE;
}

// ============================================================================
// PIMPL Implementation (holds all libyara state)
// ============================================================================

class YaraEngine::Impl {
public:
    YR_COMPILER* compiler{nullptr};
    YR_RULES* rules{nullptr};
    
    bool initialized{false};
    bool compiled{false};
    size_t ruleCount{0};
    size_t ruleFilesLoaded{0};
    
    std::vector<std::string> ruleSourcePaths;
    mutable std::shared_mutex scanMutex;
    
    ~Impl() {
        if (rules) yr_rules_destroy(rules);
        if (compiler) yr_compiler_destroy(compiler);
        if (initialized) yr_finalize();
    }
};

// ============================================================================
// YaraEngine Public Methods
// ============================================================================

YaraEngine::YaraEngine(std::shared_ptr<ILogger> logger)
    : m_impl(std::make_unique<Impl>())
    , m_logger(std::move(logger))
{
}

YaraEngine::~YaraEngine() {
    Finalize();
}

bool YaraEngine::Initialize() {
    if (m_impl->initialized) return true;
    
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        m_logger->Error("YARA: Failed to initialize (error {})", result);
        return false;
    }
    
    m_impl->initialized = true;
    m_logger->Info("YARA: Engine initialized (libyara {}.{}.{})",
        YR_MAJOR_VERSION, YR_MINOR_VERSION, YR_MICRO_VERSION);
    
    return true;
}

void YaraEngine::Finalize() {
    if (!m_impl) return;
    
    if (m_impl->rules) {
        yr_rules_destroy(m_impl->rules);
        m_impl->rules = nullptr;
    }
    if (m_impl->compiler) {
        yr_compiler_destroy(m_impl->compiler);
        m_impl->compiler = nullptr;
    }
    if (m_impl->initialized) {
        yr_finalize();
        m_impl->initialized = false;
    }
    m_impl->compiled = false;
    m_impl->ruleCount = 0;
}

bool YaraEngine::LoadRuleFile(const std::filesystem::path& rulePath) {
    if (!m_impl->initialized) {
        m_logger->Error("YARA: Not initialized");
        return false;
    }
    
    if (!std::filesystem::exists(rulePath)) {
        m_logger->Warn("YARA: Rule file not found: {}", rulePath.string());
        return false;
    }
    
    if (!m_impl->compiler) {
        int result = yr_compiler_create(&m_impl->compiler);
        if (result != ERROR_SUCCESS) {
            m_logger->Error("YARA: Failed to create compiler");
            return false;
        }
    }
    
    std::ifstream file(rulePath, std::ios::binary);
    if (!file.is_open()) {
        m_logger->Warn("YARA: Cannot open rule file: {}", rulePath.string());
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();
    
    auto ns = rulePath.stem().string();
    int errors = yr_compiler_add_string(m_impl->compiler, content.c_str(), ns.c_str());
    
    if (errors > 0) {
        m_logger->Warn("YARA: {} errors in rule file: {}", errors, rulePath.string());
        return false;
    }
    
    m_impl->ruleSourcePaths.push_back(rulePath.string());
    m_impl->ruleFilesLoaded++;
    m_logger->Info("YARA: Loaded rule file: {}", rulePath.filename().string());
    
    if (m_impl->rules) {
        yr_rules_destroy(m_impl->rules);
        m_impl->rules = nullptr;
        m_impl->compiled = false;
    }
    
    return true;
}

size_t YaraEngine::LoadRulesFromDirectory(const std::filesystem::path& dirPath) {
    if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath)) {
        m_logger->Info("YARA: Rules directory not found: {}", dirPath.string());
        return 0;
    }
    
    size_t loaded = 0;
    
    for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        
        auto ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        if (ext == ".yar" || ext == ".yara") {
            if (LoadRuleFile(entry.path())) {
                loaded++;
            }
        }
    }
    
    m_logger->Info("YARA: Loaded {} rule files from {}", loaded, dirPath.string());
    return loaded;
}

bool YaraEngine::CompileRules() {
    if (!m_impl->compiler) {
        m_logger->Warn("YARA: No rules loaded to compile");
        return false;
    }
    
    if (m_impl->rules) {
        yr_rules_destroy(m_impl->rules);
        m_impl->rules = nullptr;
    }
    
    int result = yr_compiler_get_rules(m_impl->compiler, &m_impl->rules);
    if (result != ERROR_SUCCESS) {
        m_logger->Error("YARA: Failed to compile rules (error {})", result);
        return false;
    }
    
    m_impl->ruleCount = 0;
    YR_RULE* rule;
    yr_rules_foreach(m_impl->rules, rule) {
        m_impl->ruleCount++;
    }
    
    m_impl->compiled = true;
    
    yr_compiler_destroy(m_impl->compiler);
    m_impl->compiler = nullptr;
    
    m_logger->Info("YARA: Compiled {} rules from {} files", 
        m_impl->ruleCount, m_impl->ruleFilesLoaded);
    
    return true;
}

std::vector<YaraMatch> YaraEngine::ScanBuffer(
    std::span<const uint8_t> data
) const {
    std::vector<YaraMatch> matches;
    
    if (!m_impl->compiled || !m_impl->rules || data.empty()) {
        return matches;
    }
    
    std::shared_lock lock(m_impl->scanMutex);
    
    YaraScanContext ctx{&matches};
    
    yr_rules_scan_mem(
        m_impl->rules,
        data.data(),
        data.size(),
        0,
        YaraScanCallback,
        &ctx,
        0
    );
    
    return matches;
}

std::vector<YaraMatch> YaraEngine::ScanFile(
    const std::filesystem::path& filePath
) const {
    std::vector<YaraMatch> matches;
    
    if (!m_impl->compiled || !m_impl->rules) {
        return matches;
    }
    
    std::shared_lock lock(m_impl->scanMutex);
    
    YaraScanContext ctx{&matches};
    
    yr_rules_scan_file(
        m_impl->rules,
        filePath.string().c_str(),
        0,
        YaraScanCallback,
        &ctx,
        0
    );
    
    return matches;
}

bool YaraEngine::IsReady() const noexcept {
    return m_impl && m_impl->compiled;
}

size_t YaraEngine::GetRuleCount() const noexcept {
    return m_impl ? m_impl->ruleCount : 0;
}

}  // namespace antivirus

#endif // HAS_YARA
