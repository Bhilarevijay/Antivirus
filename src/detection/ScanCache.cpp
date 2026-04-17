/**
 * @file ScanCache.cpp
 * @brief Persistent scan cache implementation
 * 
 * Stores file metadata + SHA-256 hashes to skip unchanged files
 * on subsequent scans. Persists across application restarts.
 */

#include "antivirus/detection/ScanCache.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace antivirus {

ScanCache::ScanCache(const std::filesystem::path& cachePath,
                     std::shared_ptr<ILogger> logger)
    : m_cachePath(cachePath)
    , m_logger(std::move(logger))
{
}

ScanCache::~ScanCache() {
    try {
        Save();
    } catch (...) {}
}

size_t ScanCache::Load() {
    std::unique_lock lock(m_mutex);
    m_entries.clear();
    
    if (!std::filesystem::exists(m_cachePath)) {
        m_logger->Info("ScanCache: No cache file found, starting fresh");
        return 0;
    }
    
    std::ifstream file(m_cachePath);
    if (!file.is_open()) {
        m_logger->Warn("ScanCache: Failed to open cache file: {}", m_cachePath.string());
        return 0;
    }
    
    std::string line;
    size_t loaded = 0;
    size_t lineNum = 0;
    
    while (std::getline(file, line)) {
        lineNum++;
        
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;
        
        // Parse: PATH\tSIZE\tMTIME\tSHA256\tSCAN_TIME\tRESULT
        std::istringstream iss(line);
        std::string path, sizeStr, mtimeStr, sha256, scanTimeStr, resultStr;
        
        if (!std::getline(iss, path, '\t')) continue;
        if (!std::getline(iss, sizeStr, '\t')) continue;
        if (!std::getline(iss, mtimeStr, '\t')) continue;
        if (!std::getline(iss, sha256, '\t')) continue;
        if (!std::getline(iss, scanTimeStr, '\t')) continue;
        if (!std::getline(iss, resultStr, '\t')) continue;
        
        try {
            CachedFileEntry entry;
            entry.filePath = path;
            entry.fileSize = std::stoull(sizeStr);
            entry.lastModifiedEpoch = std::stoll(mtimeStr);
            entry.sha256Hex = sha256;
            entry.scanTimeEpoch = std::stoll(scanTimeStr);
            entry.wasClean = (resultStr == "CLEAN");
            
            m_entries[path] = std::move(entry);
            loaded++;
        } catch (const std::exception&) {
            // Skip malformed lines
        }
    }
    
    m_logger->Info("ScanCache: Loaded {} entries from cache", loaded);
    return loaded;
}

bool ScanCache::Save() const {
    std::shared_lock lock(m_mutex);
    
    try {
        // Ensure parent directory exists
        auto parent = m_cachePath.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::filesystem::create_directories(parent);
        }
        
        std::ofstream file(m_cachePath, std::ios::trunc);
        if (!file.is_open()) {
            m_logger->Warn("ScanCache: Failed to save cache to: {}", m_cachePath.string());
            return false;
        }
        
        // Header
        file << "# Sentinel Scan Cache v" << CACHE_VERSION << "\n";
        file << "# PATH\\tSIZE\\tMTIME\\tSHA256\\tSCAN_TIME\\tRESULT\n";
        
        // Entries
        for (const auto& [key, entry] : m_entries) {
            file << entry.filePath << "\t"
                 << entry.fileSize << "\t"
                 << entry.lastModifiedEpoch << "\t"
                 << entry.sha256Hex << "\t"
                 << entry.scanTimeEpoch << "\t"
                 << (entry.wasClean ? "CLEAN" : "INFECTED") << "\n";
        }
        
        file.flush();
        m_logger->Info("ScanCache: Saved {} entries to cache", m_entries.size());
        return true;
    } catch (const std::exception& e) {
        m_logger->Warn("ScanCache: Save failed: {}", e.what());
        return false;
    }
}

bool ScanCache::CanSkipFile(
    const FilePath& path,
    uint64_t currentSize,
    int64_t currentModTimeEpoch
) const {
    std::shared_lock lock(m_mutex);
    
    auto normalPath = NormalizePath(path);
    auto it = m_entries.find(normalPath);
    
    if (it == m_entries.end()) {
        return false;  // Not in cache → must scan
    }
    
    const auto& entry = it->second;
    
    // If the file was infected last time, always re-scan
    if (!entry.wasClean) {
        return false;
    }
    
    // Fast metadata check: size + mtime
    if (entry.fileSize == currentSize && entry.lastModifiedEpoch == currentModTimeEpoch) {
        m_cacheHits.fetch_add(1, std::memory_order_relaxed);
        return true;  // File unchanged → skip
    }
    
    // Metadata differs → file was modified → must re-scan
    return false;
}

void ScanCache::UpdateEntry(
    const FilePath& path,
    uint64_t fileSize,
    int64_t modTimeEpoch,
    const std::string& sha256Hex,
    bool isClean
) {
    std::unique_lock lock(m_mutex);
    
    auto normalPath = NormalizePath(path);
    
    CachedFileEntry entry;
    entry.filePath = normalPath;
    entry.fileSize = fileSize;
    entry.lastModifiedEpoch = modTimeEpoch;
    entry.sha256Hex = sha256Hex;
    entry.scanTimeEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    entry.wasClean = isClean;
    
    m_entries[normalPath] = std::move(entry);
}

void ScanCache::RemoveEntry(const FilePath& path) {
    std::unique_lock lock(m_mutex);
    m_entries.erase(NormalizePath(path));
}

void ScanCache::Clear() {
    std::unique_lock lock(m_mutex);
    m_entries.clear();
    m_cacheHits.store(0);
}

size_t ScanCache::GetEntryCount() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_entries.size();
}

std::string ScanCache::NormalizePath(const FilePath& path) const {
    try {
        // Use canonical path for consistent comparison
        if (std::filesystem::exists(path)) {
            return std::filesystem::canonical(path).string();
        }
    } catch (...) {}
    
    // Fallback: lowercase the path for case-insensitive Windows matching
    auto str = path.string();
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

}  // namespace antivirus
