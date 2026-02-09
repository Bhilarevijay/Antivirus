/**
 * @file Logger.hpp
 * @brief Async logging implementation
 * 
 * Lock-free async logger that minimizes impact on scanning performance.
 */

#pragma once

#include "antivirus/logging/ILogger.hpp"
#include "antivirus/utils/LockFreeQueue.hpp"

#include <fstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <filesystem>

namespace antivirus {

/**
 * @struct LogEntry
 * @brief Internal log entry for async processing
 */
struct LogEntry {
    LogLevel level;
    std::string message;
    std::string filename;
    uint32_t line;
    std::chrono::system_clock::time_point timestamp;
};

/**
 * @class Logger
 * @brief Production async logger implementation
 * 
 * Features:
 * - Lock-free queue for non-blocking log calls
 * - Dedicated background thread for I/O
 * - Automatic file rotation (future)
 * - Console and file output
 */
class Logger final : public ILogger {
public:
    /**
     * @brief Create logger with output file path
     * @param logFile Path to log file
     * @param consoleOutput Also write to console
     */
    explicit Logger(
        const std::filesystem::path& logFile,
        bool consoleOutput = true
    );
    
    ~Logger() override;
    
    // Prevent copying
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    void Log(
        LogLevel level,
        std::string_view message,
        const std::source_location& location = std::source_location::current()
    ) override;
    
    void SetLevel(LogLevel level) override;
    [[nodiscard]] LogLevel GetLevel() const noexcept override;
    void Flush() override;
    
private:
    void ProcessingLoop();
    void WriteEntry(const LogEntry& entry);
    [[nodiscard]] std::string FormatEntry(const LogEntry& entry) const;
    
    std::filesystem::path m_logFile;
    std::ofstream m_fileStream;
    bool m_consoleOutput;
    
    std::atomic<LogLevel> m_level{LogLevel::Info};
    std::atomic<bool> m_running{true};
    
    LockFreeQueue<LogEntry> m_queue;
    std::thread m_processingThread;
};

/**
 * @brief Create a console-only logger (no file output)
 */
[[nodiscard]] std::shared_ptr<Logger> CreateConsoleLogger();

/**
 * @brief Create a file logger
 */
[[nodiscard]] std::shared_ptr<Logger> CreateFileLogger(
    const std::filesystem::path& path
);

}  // namespace antivirus
