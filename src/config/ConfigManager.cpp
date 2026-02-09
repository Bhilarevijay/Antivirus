/**
 * @file ConfigManager.cpp
 * @brief JSON configuration manager implementation
 */

#include "antivirus/config/ConfigManager.hpp"
#include <fstream>
#include <sstream>

namespace antivirus {

ConfigManager::ConfigManager(const std::filesystem::path& configPath)
    : m_configPath(configPath)
{
    ResetToDefaults();
    Load();
}

bool ConfigManager::Load() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ifstream file(m_configPath);
    if (!file) {
        return false;  // Use defaults
    }
    
    // Simple JSON parsing (production should use a library)
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json = buffer.str();
    
    // Parse thread count
    auto parseNumber = [&json](const std::string& key) -> int64_t {
        size_t pos = json.find("\"" + key + "\":");
        if (pos == std::string::npos) return -1;
        pos += key.length() + 3;
        return std::stoll(json.substr(pos));
    };
    
    auto parseString = [&json](const std::string& key) -> std::string {
        size_t start = json.find("\"" + key + "\":\"");
        if (start == std::string::npos) return "";
        start += key.length() + 4;
        size_t end = json.find("\"", start);
        if (end == std::string::npos) return "";
        return json.substr(start, end - start);
    };
    
    auto parseBool = [&json](const std::string& key) -> bool {
        size_t pos = json.find("\"" + key + "\":");
        if (pos == std::string::npos) return false;
        return json.find("true", pos) == pos + key.length() + 3;
    };
    
    int64_t tc = parseNumber("threadCount");
    if (tc >= 0) m_threadCount = static_cast<uint32_t>(tc);
    
    int64_t mfs = parseNumber("maxFileSize");
    if (mfs > 0) m_maxFileSize = static_cast<FileSize>(mfs);
    
    m_gpuEnabled = parseBool("gpuEnabled");
    
    std::string qp = parseString("quarantinePath");
    if (!qp.empty()) m_quarantinePath = qp;
    
    std::string sp = parseString("signaturePath");
    if (!sp.empty()) m_signaturePath = sp;
    
    std::string lp = parseString("logPath");
    if (!lp.empty()) m_logPath = lp;
    
    return true;
}

bool ConfigManager::Save() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ofstream file(m_configPath);
    if (!file) {
        return false;
    }
    
    file << "{\n"
         << "  \"threadCount\": " << m_threadCount << ",\n"
         << "  \"maxFileSize\": " << m_maxFileSize << ",\n"
         << "  \"gpuEnabled\": " << (m_gpuEnabled ? "true" : "false") << ",\n"
         << "  \"quarantinePath\": \"" << m_quarantinePath.string() << "\",\n"
         << "  \"signaturePath\": \"" << m_signaturePath.string() << "\",\n"
         << "  \"logPath\": \"" << m_logPath.string() << "\"\n"
         << "}\n";
    
    return true;
}

void ConfigManager::ResetToDefaults() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_threadCount = 0;  // Auto-detect
    m_maxFileSize = 100 * 1024 * 1024;  // 100MB
    m_gpuEnabled = false;
    m_quarantinePath = "Quarantine";
    m_signaturePath = "signatures/malware_signatures.db";
    m_logPath = "logs/antivirus.log";
    m_excludedPaths.clear();
    m_excludedExtensions.clear();
    
    m_defaultScanConfig = ScanConfig{};
}

ScanConfig ConfigManager::GetDefaultScanConfig() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_defaultScanConfig;
}

void ConfigManager::SetDefaultScanConfig(const ScanConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_defaultScanConfig = config;
}

uint32_t ConfigManager::GetThreadCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_threadCount;
}

void ConfigManager::SetThreadCount(uint32_t count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_threadCount = count;
}

FilePath ConfigManager::GetQuarantinePath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_quarantinePath;
}

void ConfigManager::SetQuarantinePath(const FilePath& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_quarantinePath = path;
}

FilePath ConfigManager::GetSignaturePath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_signaturePath;
}

void ConfigManager::SetSignaturePath(const FilePath& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_signaturePath = path;
}

FilePath ConfigManager::GetLogPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_logPath;
}

void ConfigManager::SetLogPath(const FilePath& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logPath = path;
}

std::vector<FilePath> ConfigManager::GetExcludedPaths() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_excludedPaths;
}

void ConfigManager::AddExcludedPath(const FilePath& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedPaths.push_back(path);
}

void ConfigManager::RemoveExcludedPath(const FilePath& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedPaths.erase(
        std::remove(m_excludedPaths.begin(), m_excludedPaths.end(), path),
        m_excludedPaths.end()
    );
}

std::vector<std::string> ConfigManager::GetExcludedExtensions() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_excludedExtensions;
}

void ConfigManager::AddExcludedExtension(const std::string& ext) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedExtensions.push_back(ext);
}

void ConfigManager::RemoveExcludedExtension(const std::string& ext) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedExtensions.erase(
        std::remove(m_excludedExtensions.begin(), m_excludedExtensions.end(), ext),
        m_excludedExtensions.end()
    );
}

bool ConfigManager::IsGpuEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_gpuEnabled;
}

void ConfigManager::SetGpuEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_gpuEnabled = enabled;
}

FileSize ConfigManager::GetMaxFileSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_maxFileSize;
}

void ConfigManager::SetMaxFileSize(FileSize size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxFileSize = size;
}

}  // namespace antivirus
