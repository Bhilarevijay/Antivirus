/**
 * @file FileScanner.cpp
 * @brief File scanner implementation with Windows native API support
 */

#include "antivirus/scanner/FileScanner.hpp"
#include <fstream>

#ifdef _WIN32
    #include <Windows.h>
    #include <AclAPI.h>
#endif

namespace antivirus {

FileScanner::FileScanner(std::shared_ptr<ILogger> logger)
    : m_logger(std::move(logger))
{
}

void FileScanner::EnumerateFiles(
    const FilePath& path,
    FileEnumerationCallback callback,
    const ScanConfig& config
) {
    if (!std::filesystem::exists(path)) {
        m_logger->Warn("Path does not exist: {}", path.string());
        return;
    }
    
    std::unordered_set<std::wstring> visited;
    
#ifdef _WIN32
    EnumerateDirectoryNative(path, callback, config, visited);
#else
    EnumerateDirectory(path, callback, config, visited);
#endif
}

void FileScanner::EnumerateDirectory(
    const FilePath& path,
    FileEnumerationCallback& callback,
    const ScanConfig& config,
    std::unordered_set<std::wstring>& visited
) {
    if (m_cancelled && m_cancelled->load()) {
        return;
    }
    
    try {
        // Check for loops via visited set
        auto normalPath = NormalizePath(path);
        auto pathStr = normalPath.wstring();
        if (visited.count(pathStr)) {
            return;
        }
        visited.insert(pathStr);
        
        // Check exclusions
        if (IsExcludedPath(path, config)) {
            return;
        }
        
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(path, ec)) {
            if (m_cancelled && m_cancelled->load()) {
                return;
            }
            
            try {
                if (entry.is_directory(ec)) {
                    // Skip symlinks if configured
                    if (entry.is_symlink() && !config.followSymlinks) {
                        continue;
                    }
                    
                    EnumerateDirectory(entry.path(), callback, config, visited);
                    
                } else if (entry.is_regular_file(ec)) {
                    auto fileInfo = GetFileInfo(entry.path());
                    if (fileInfo && !ShouldSkipFile(*fileInfo, config)) {
                        callback(*fileInfo);
                    }
                }
            } catch (const std::filesystem::filesystem_error& e) {
                m_logger->Debug("Error accessing {}: {}", 
                    entry.path().string(), e.what());
            }
        }
        
    } catch (const std::filesystem::filesystem_error& e) {
        m_logger->Debug("Error enumerating {}: {}", path.string(), e.what());
    }
}

#ifdef _WIN32
void FileScanner::EnumerateDirectoryNative(
    const FilePath& path,
    FileEnumerationCallback& callback,
    const ScanConfig& config,
    std::unordered_set<std::wstring>& visited
) {
    if (m_cancelled && m_cancelled->load()) {
        return;
    }
    
    // Normalize and add \\?\ prefix for long path support
    std::wstring searchPath = L"\\\\?\\" + path.wstring();
    if (searchPath.back() != L'\\') {
        searchPath += L'\\';
    }
    searchPath += L'*';
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileExW(
        searchPath.c_str(),
        FindExInfoBasic,
        &findData,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH
    );
    
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_ACCESS_DENIED) {
            m_logger->Debug("FindFirstFileEx failed for {}: error {}", 
                path.string(), error);
        }
        return;
    }
    
    // Check for loops
    auto normalPath = NormalizePath(path);
    auto pathStr = normalPath.wstring();
    if (visited.count(pathStr)) {
        FindClose(hFind);
        return;
    }
    visited.insert(pathStr);
    
    do {
        if (m_cancelled && m_cancelled->load()) {
            break;
        }
        
        // Skip . and ..
        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        
        FilePath entryPath = path / findData.cFileName;
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Skip reparse points (junctions, symlinks) unless configured
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                !config.followSymlinks) {
                continue;
            }
            
            // Recurse into subdirectory
            EnumerateDirectoryNative(entryPath, callback, config, visited);
            
        } else {
            // Regular file
            auto fileInfo = WIN32FindDataToFileInfo(path, findData);
            
            if (!ShouldSkipFile(fileInfo, config)) {
                callback(fileInfo);
            }
        }
        
    } while (FindNextFileW(hFind, &findData));
    
    FindClose(hFind);
}

FileInfo FileScanner::WIN32FindDataToFileInfo(
    const FilePath& directory,
    const WIN32_FIND_DATAW& findData
) const {
    FileInfo info;
    info.path = directory / findData.cFileName;
    
    // Calculate size from high and low parts
    ULARGE_INTEGER size;
    size.HighPart = findData.nFileSizeHigh;
    size.LowPart = findData.nFileSizeLow;
    info.size = size.QuadPart;
    
    // Convert FILETIME to Timestamp
    ULARGE_INTEGER time;
    time.HighPart = findData.ftLastWriteTime.dwHighDateTime;
    time.LowPart = findData.ftLastWriteTime.dwLowDateTime;
    
    // Convert Windows FILETIME (100ns intervals since 1601) to Unix time
    constexpr uint64_t WINDOWS_TICK = 10000000;
    constexpr uint64_t SEC_TO_UNIX_EPOCH = 11644473600LL;
    
    auto unixSeconds = (time.QuadPart / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;
    info.lastModified = std::chrono::system_clock::from_time_t(
        static_cast<time_t>(unixSeconds)
    );
    
    // File attributes
    info.isSymlink = (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    info.isHidden = (findData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
    info.isSystem = (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0;
    info.isReadOnly = (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
    
    return info;
}
#endif

std::optional<FileInfo> FileScanner::GetFileInfo(const FilePath& path) {
    try {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            return std::nullopt;
        }
        
        FileInfo info;
        info.path = path;
        info.size = std::filesystem::file_size(path, ec);
        info.lastModified = std::chrono::file_clock::to_sys(
            std::filesystem::last_write_time(path, ec)
        );
        info.isSymlink = std::filesystem::is_symlink(path, ec);
        
#ifdef _WIN32
        DWORD attrs = GetFileAttributesW(path.wstring().c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            info.isHidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
            info.isSystem = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;
            info.isReadOnly = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
        }
#endif
        
        return info;
        
    } catch (const std::filesystem::filesystem_error&) {
        return std::nullopt;
    }
}

size_t FileScanner::ReadFile(
    const FilePath& path,
    std::span<uint8_t> buffer,
    size_t offset
) {
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return 0;
        }
        
        if (offset > 0) {
            file.seekg(static_cast<std::streamoff>(offset));
        }
        
        file.read(reinterpret_cast<char*>(buffer.data()), 
            static_cast<std::streamsize>(buffer.size()));
        
        return static_cast<size_t>(file.gcount());
        
    } catch (const std::exception&) {
        return 0;
    }
}

void FileScanner::SetCancellationToken(std::atomic<bool>* cancelled) {
    m_cancelled = cancelled;
}

bool FileScanner::ShouldSkipFile(
    const FileInfo& info,
    const ScanConfig& config
) const {
    // Size check
    if (info.size > config.maxFileSize) {
        return true;
    }
    
    // Hidden files
    if (!config.scanHiddenFiles && info.isHidden) {
        return true;
    }
    
    // Extension check
    if (ShouldSkipExtension(info.path, config)) {
        return true;
    }
    
    return false;
}

bool FileScanner::ShouldSkipExtension(
    const FilePath& path,
    const ScanConfig& config
) const {
    auto ext = path.extension().string();
    if (ext.empty()) {
        return false;
    }
    
    // Remove leading dot and convert to lowercase
    if (ext[0] == '.') {
        ext = ext.substr(1);
    }
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    for (const auto& excluded : config.excludeExtensions) {
        if (ext == excluded) {
            return true;
        }
    }
    
    return false;
}

bool FileScanner::IsExcludedPath(
    const FilePath& path,
    const ScanConfig& config
) const {
    auto normalPath = NormalizePath(path);
    
    for (const auto& excluded : config.excludePaths) {
        auto normalExcluded = NormalizePath(excluded);
        
        // Check if path starts with excluded path
        auto pathStr = normalPath.string();
        auto excludedStr = normalExcluded.string();
        
        if (pathStr.find(excludedStr) == 0) {
            return true;
        }
    }
    
    return false;
}

FilePath FileScanner::NormalizePath(const FilePath& path) const {
    try {
        std::error_code ec;
        auto canonical = std::filesystem::canonical(path, ec);
        if (!ec) {
            return canonical;
        }
    } catch (...) {}
    
    return path;
}

}  // namespace antivirus
