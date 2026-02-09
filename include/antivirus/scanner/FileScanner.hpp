/**
 * @file FileScanner.hpp
 * @brief High-performance file scanner for Windows
 * 
 * Uses std::filesystem with Windows native API fallbacks for
 * maximum performance and edge case handling.
 */

#pragma once

#include "antivirus/scanner/IFileScanner.hpp"
#include "antivirus/logging/ILogger.hpp"

#include <memory>
#include <unordered_set>

#ifdef _WIN32
    #include <Windows.h>
#endif

namespace antivirus {

/**
 * @class FileScanner
 * @brief Production file scanner implementation
 * 
 * Features:
 * - Recursive directory enumeration
 * - Long path support (\\?\ prefix on Windows)
 * - Symbolic link handling
 * - Access denied graceful handling
 * - NTFS junction point detection
 */
class FileScanner final : public IFileScanner {
public:
    /**
     * @brief Create file scanner with logger
     */
    explicit FileScanner(std::shared_ptr<ILogger> logger);
    
    ~FileScanner() override = default;
    
    void EnumerateFiles(
        const FilePath& path,
        FileEnumerationCallback callback,
        const ScanConfig& config
    ) override;
    
    [[nodiscard]] std::optional<FileInfo> GetFileInfo(
        const FilePath& path
    ) override;
    
    [[nodiscard]] size_t ReadFile(
        const FilePath& path,
        std::span<uint8_t> buffer,
        size_t offset = 0
    ) override;
    
    void SetCancellationToken(std::atomic<bool>* cancelled) override;

private:
    void EnumerateDirectory(
        const FilePath& path,
        FileEnumerationCallback& callback,
        const ScanConfig& config,
        std::unordered_set<std::wstring>& visited
    );
    
    [[nodiscard]] bool ShouldSkipFile(
        const FileInfo& info,
        const ScanConfig& config
    ) const;
    
    [[nodiscard]] bool ShouldSkipExtension(
        const FilePath& path,
        const ScanConfig& config
    ) const;
    
    [[nodiscard]] bool IsExcludedPath(
        const FilePath& path,
        const ScanConfig& config
    ) const;
    
    [[nodiscard]] FilePath NormalizePath(const FilePath& path) const;
    
#ifdef _WIN32
    void EnumerateDirectoryNative(
        const FilePath& path,
        FileEnumerationCallback& callback,
        const ScanConfig& config,
        std::unordered_set<std::wstring>& visited
    );
    
    [[nodiscard]] FileInfo WIN32FindDataToFileInfo(
        const FilePath& directory,
        const WIN32_FIND_DATAW& findData
    ) const;
#endif
    
    std::shared_ptr<ILogger> m_logger;
    std::atomic<bool>* m_cancelled{nullptr};
};

}  // namespace antivirus
