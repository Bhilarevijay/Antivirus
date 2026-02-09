/**
 * @file IFileScanner.hpp
 * @brief File scanner interface
 */

#pragma once

#include "antivirus/core/Types.hpp"
#include <memory>
#include <functional>

namespace antivirus {

/**
 * @brief Callback for enumerated files
 */
using FileEnumerationCallback = std::function<void(const FileInfo&)>;

/**
 * @interface IFileScanner
 * @brief Interface for file system enumeration
 */
class IFileScanner {
public:
    virtual ~IFileScanner() = default;
    
    /**
     * @brief Enumerate files in a directory recursively
     * @param path Root path to scan
     * @param callback Called for each discovered file
     * @param config Scan configuration for filtering
     */
    virtual void EnumerateFiles(
        const FilePath& path,
        FileEnumerationCallback callback,
        const ScanConfig& config
    ) = 0;
    
    /**
     * @brief Get file information
     * @param path Path to file
     * @return File info, or nullopt if file doesn't exist
     */
    [[nodiscard]] virtual std::optional<FileInfo> GetFileInfo(
        const FilePath& path
    ) = 0;
    
    /**
     * @brief Read file contents into buffer
     * @param path Path to file
     * @param buffer Output buffer
     * @param offset Starting offset
     * @param size Number of bytes to read
     * @return Actual bytes read
     */
    [[nodiscard]] virtual size_t ReadFile(
        const FilePath& path,
        std::span<uint8_t> buffer,
        size_t offset = 0
    ) = 0;
    
    /**
     * @brief Check if scan should be cancelled
     */
    virtual void SetCancellationToken(std::atomic<bool>* cancelled) = 0;

protected:
    IFileScanner() = default;
};

using IFileScannerPtr = std::shared_ptr<IFileScanner>;

}  // namespace antivirus
