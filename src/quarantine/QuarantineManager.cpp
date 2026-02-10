/**
 * @file QuarantineManager.cpp
 * @brief Quarantine manager implementation with Windows ACL
 */

#include "antivirus/quarantine/QuarantineManager.hpp"
#include <fstream>
#include <random>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
    #include <Windows.h>
    #include <AclAPI.h>
    #include <sddl.h>
#endif

namespace antivirus {

QuarantineManager::QuarantineManager(
    const FilePath& quarantinePath,
    std::shared_ptr<ILogger> logger
)
    : m_quarantinePath(quarantinePath)
    , m_indexPath(quarantinePath / constants::QUARANTINE_INDEX)
    , m_logger(std::move(logger))
{
    (void)Initialize();
}

QuarantineManager::~QuarantineManager() {
    (void)SaveIndex();
}

bool QuarantineManager::Initialize() {
    if (m_initialized) {
        return true;
    }
    
    std::error_code ec;
    
    // Create quarantine folder if needed
    if (!std::filesystem::exists(m_quarantinePath, ec)) {
        std::filesystem::create_directories(m_quarantinePath, ec);
        if (ec) {
            m_logger->Error("Failed to create quarantine folder: {}", ec.message());
            return false;
        }
    }
    
#ifdef _WIN32
    // Set restrictive ACL on quarantine folder
    if (!SetQuarantineAcl()) {
        m_logger->Warn("Failed to set ACL on quarantine folder");
    }
#endif
    
    // Load existing index
    (void)LoadIndex();
    
    m_initialized = true;
    m_logger->Info("Quarantine initialized: {}", m_quarantinePath.string());
    return true;
}

std::optional<QuarantineEntry> QuarantineManager::Quarantine(
    const FilePath& path,
    const ThreatInfo& threat
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        m_logger->Error("Quarantine not initialized");
        return std::nullopt;
    }
    
    // Check if file exists
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        m_logger->Error("File not found: {}", path.string());
        return std::nullopt;
    }
    
    // Create entry
    QuarantineEntry entry;
    entry.id = GenerateEntryId();
    entry.originalPath = path;
    entry.quarantinePath = GenerateQuarantinePath(entry.id);
    entry.threatName = threat.threatName;
    entry.signatureId = threat.signatureId;
    entry.threatLevel = threat.level;
    entry.originalSize = std::filesystem::file_size(path, ec);
    entry.quarantineTime = std::chrono::system_clock::now();
    
    // Move file to quarantine
    std::filesystem::rename(path, entry.quarantinePath, ec);
    if (ec) {
        // Try copy + delete if rename fails (cross-filesystem)
        std::filesystem::copy(path, entry.quarantinePath, ec);
        if (ec) {
            m_logger->Error("Failed to quarantine file: {}", ec.message());
            return std::nullopt;
        }
        (void)std::filesystem::remove(path, ec);
    }
    
#ifdef _WIN32
    // Apply restrictive permissions
    (void)ApplySecurityPermissions(entry.quarantinePath);
#endif
    
    // Add to index
    m_entries[entry.id] = entry;
    (void)SaveIndex();
    
    m_logger->Info("Quarantined: {} -> {}", 
        path.string(), entry.quarantinePath.string());
    
    return entry;
}

bool QuarantineManager::Restore(
    const std::string& entryId,
    const FilePath& restorePath
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_entries.find(entryId);
    if (it == m_entries.end()) {
        m_logger->Error("Quarantine entry not found: {}", entryId);
        return false;
    }
    
    const auto& entry = it->second;
    FilePath target = restorePath.empty() ? entry.originalPath : restorePath;
    
    std::error_code ec;
    
    // Create parent directories if needed
    (void)std::filesystem::create_directories(target.parent_path(), ec);
    
    // Move file back
    std::filesystem::rename(entry.quarantinePath, target, ec);
    if (ec) {
        std::filesystem::copy(entry.quarantinePath, target, ec);
        if (ec) {
            m_logger->Error("Failed to restore file: {}", ec.message());
            return false;
        }
        (void)std::filesystem::remove(entry.quarantinePath, ec);
    }
    
    // Remove from index
    m_entries.erase(it);
    (void)SaveIndex();
    
    m_logger->Info("Restored: {} -> {}", entryId, target.string());
    return true;
}

bool QuarantineManager::Delete(const std::string& entryId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_entries.find(entryId);
    if (it == m_entries.end()) {
        m_logger->Error("Quarantine entry not found: {}", entryId);
        return false;
    }
    
    std::error_code ec;
    std::filesystem::remove(it->second.quarantinePath, ec);
    if (ec) {
        m_logger->Error("Failed to delete quarantined file: {}", ec.message());
        return false;
    }
    
    m_entries.erase(it);
    (void)SaveIndex();
    
    m_logger->Info("Deleted quarantined file: {}", entryId);
    return true;
}

std::vector<QuarantineEntry> QuarantineManager::GetEntries() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<QuarantineEntry> entries;
    entries.reserve(m_entries.size());
    
    for (const auto& [id, entry] : m_entries) {
        entries.push_back(entry);
    }
    
    return entries;
}

std::optional<QuarantineEntry> QuarantineManager::GetEntry(
    const std::string& entryId
) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_entries.find(entryId);
    if (it != m_entries.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

size_t QuarantineManager::Cleanup(uint32_t maxAgeDays) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto maxAge = std::chrono::hours(maxAgeDays * 24);
    
    std::vector<std::string> toRemove;
    
    for (const auto& [id, entry] : m_entries) {
        if (now - entry.quarantineTime > maxAge) {
            std::error_code ec;
            std::filesystem::remove(entry.quarantinePath, ec);
            toRemove.push_back(id);
        }
    }
    
    for (const auto& id : toRemove) {
        m_entries.erase(id);
    }
    
    if (!toRemove.empty()) {
        (void)SaveIndex();
        m_logger->Info("Cleaned up {} old quarantine entries", toRemove.size());
    }
    
    return toRemove.size();
}

FilePath QuarantineManager::GetQuarantinePath() const {
    return m_quarantinePath;
}

FileSize QuarantineManager::GetTotalSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    FileSize total = 0;
    for (const auto& [id, entry] : m_entries) {
        total += entry.originalSize;
    }
    
    return total;
}

size_t QuarantineManager::GetEntryCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

bool QuarantineManager::LoadIndex() {
    std::ifstream file(m_indexPath);
    if (!file) {
        return false;  // No existing index
    }
    
    // Simple line-based format for now
    // TODO: Proper JSON parsing
    std::string line;
    while (std::getline(file, line)) {
        auto entry = QuarantineEntry::FromJson(line);
        if (entry) {
            m_entries[entry->id] = *entry;
        }
    }
    
    m_logger->Debug("Loaded {} quarantine entries", m_entries.size());
    return true;
}

bool QuarantineManager::SaveIndex() {
    std::ofstream file(m_indexPath);
    if (!file) {
        m_logger->Error("Failed to save quarantine index");
        return false;
    }
    
    for (const auto& [id, entry] : m_entries) {
        file << entry.ToJson() << '\n';
    }
    
    return true;
}

std::string QuarantineManager::GenerateEntryId() const {
    // Generate UUID-like identifier
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dist;
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << dist(gen)
        << std::setw(16) << dist(gen);
    
    return oss.str();
}

FilePath QuarantineManager::GenerateQuarantinePath(const std::string& entryId) const {
    return m_quarantinePath / (entryId + ".quarantine");
}

#ifdef _WIN32
bool QuarantineManager::SetQuarantineAcl() {
    // Create restrictive ACL: deny execute for everyone
    PACL pAcl = nullptr;
    PSECURITY_DESCRIPTOR pSd = nullptr;
    (void)pSd;  // Unused but kept for future ACL expansion
    
    EXPLICIT_ACCESSW ea[2] = {};
    
    // Deny execute
    ea[0].grfAccessPermissions = FILE_EXECUTE;
    ea[0].grfAccessMode = DENY_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = const_cast<LPWSTR>(L"Everyone");
    
    // Allow read for administrators
    ea[1].grfAccessPermissions = GENERIC_READ;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = const_cast<LPWSTR>(L"Administrators");
    
    DWORD result = SetEntriesInAclW(2, ea, nullptr, &pAcl);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    result = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(m_quarantinePath.wstring().c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        pAcl,
        nullptr
    );
    
    LocalFree(pAcl);
    
    return result == ERROR_SUCCESS;
}

bool QuarantineManager::ApplySecurityPermissions(const FilePath& path) {
    // Remove execute permission
    DWORD attrs = GetFileAttributesW(path.wstring().c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    
    // Set read-only
    SetFileAttributesW(path.wstring().c_str(), 
        attrs | FILE_ATTRIBUTE_READONLY);
    
    return true;
}
#endif

// QuarantineEntry JSON methods
std::string QuarantineEntry::ToJson() const {
    std::ostringstream oss;
    oss << "{\"id\":\"" << id << "\""
        << ",\"originalPath\":\"" << originalPath.string() << "\""
        << ",\"quarantinePath\":\"" << quarantinePath.string() << "\""
        << ",\"threatName\":\"" << threatName << "\""
        << ",\"signatureId\":\"" << signatureId << "\""
        << ",\"threatLevel\":" << static_cast<int>(threatLevel)
        << ",\"originalSize\":" << originalSize
        << "}";
    return oss.str();
}

std::optional<QuarantineEntry> QuarantineEntry::FromJson(const std::string& json) {
    // Simple parser - in production use a real JSON library
    QuarantineEntry entry;
    
    auto extractString = [&json](const std::string& key) -> std::string {
        size_t start = json.find("\"" + key + "\":\"");
        if (start == std::string::npos) return "";
        start += key.length() + 4;
        size_t end = json.find("\"", start);
        if (end == std::string::npos) return "";
        return json.substr(start, end - start);
    };
    
    entry.id = extractString("id");
    if (entry.id.empty()) return std::nullopt;
    
    entry.originalPath = extractString("originalPath");
    entry.quarantinePath = extractString("quarantinePath");
    entry.threatName = extractString("threatName");
    entry.signatureId = extractString("signatureId");
    
    return entry;
}

}  // namespace antivirus
