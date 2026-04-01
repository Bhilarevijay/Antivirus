/**
 * @file Logger.cpp
 * @brief Async logger implementation
 */

#include "antivirus/logging/Logger.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>

namespace antivirus {

Logger::Logger(
    const std::filesystem::path& logFile,
    bool consoleOutput
)
    : m_logFile(logFile)
    , m_consoleOutput(consoleOutput)
    , m_queue(8192)
{
    // Open log file
    if (!logFile.empty()) {
        auto parentPath = logFile.parent_path();
        if (!parentPath.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(parentPath, ec);
        }
        m_fileStream.open(logFile, std::ios::app);
    }
    
    // Start processing thread
    m_processingThread = std::thread(&Logger::ProcessingLoop, this);
}

Logger::~Logger() {
    m_running.store(false);
    
    if (m_processingThread.joinable()) {
        m_processingThread.join();
    }
    
    // Flush remaining entries
    while (auto entry = m_queue.TryPop()) {
        WriteEntry(*entry);
    }
    
    if (m_fileStream.is_open()) {
        m_fileStream.close();
    }
}

void Logger::Log(
    LogLevel level,
    std::string_view message,
    const std::source_location& location
) {
    if (level < m_level.load()) {
        return;  // Below minimum level
    }
    
    LogEntry entry;
    entry.level = level;
    entry.message = std::string(message);
    entry.filename = location.file_name();
    entry.line = location.line();
    entry.timestamp = std::chrono::system_clock::now();
    
    // Try to queue (drop if full to avoid blocking)
    m_queue.TryPush(std::move(entry));
}

void Logger::SetLevel(LogLevel level) {
    m_level.store(level);
}

LogLevel Logger::GetLevel() const noexcept {
    return m_level.load();
}

void Logger::Flush() {
    // Wait for queue to empty
    while (!m_queue.IsEmpty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    if (m_fileStream.is_open()) {
        m_fileStream.flush();
    }
}

void Logger::ProcessingLoop() {
    while (m_running.load()) {
        auto entry = m_queue.TryPop();
        if (entry) {
            WriteEntry(*entry);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void Logger::WriteEntry(const LogEntry& entry) {
    std::string formatted = FormatEntry(entry);
    
    if (m_consoleOutput) {
        // Color output for console
        const char* color = "";
        const char* reset = "\033[0m";
        
        switch (entry.level) {
            case LogLevel::Trace:
            case LogLevel::Debug:
                color = "\033[90m";  // Gray
                break;
            case LogLevel::Info:
                color = "\033[32m";  // Green
                break;
            case LogLevel::Warning:
                color = "\033[33m";  // Yellow
                break;
            case LogLevel::Error:
            case LogLevel::Fatal:
                color = "\033[31m";  // Red
                break;
        }
        
        std::cout << color << formatted << reset << std::endl;
    }
    
    if (m_fileStream.is_open()) {
        m_fileStream << formatted << '\n';
    }
}

std::string Logger::FormatEntry(const LogEntry& entry) const {
    auto time = std::chrono::system_clock::to_time_t(entry.timestamp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        entry.timestamp.time_since_epoch()
    ).count() % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms
        << " [" << LogLevelToString(entry.level) << "] "
        << entry.message;
    
    if (entry.level >= LogLevel::Warning) {
        oss << " (" << entry.filename << ":" << entry.line << ")";
    }
    
    return oss.str();
}

std::shared_ptr<Logger> CreateConsoleLogger() {
    return std::make_shared<Logger>(std::filesystem::path{}, true);
}

std::shared_ptr<Logger> CreateFileLogger(const std::filesystem::path& path) {
    return std::make_shared<Logger>(path, true);
}

}  // namespace antivirus
