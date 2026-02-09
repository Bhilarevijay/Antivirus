/**
 * @file ILogger.hpp
 * @brief Abstract interface for logging
 */

#pragma once

#include "antivirus/logging/LogLevel.hpp"
#include <string>
#include <string_view>
#include <format>
#include <source_location>
#include <memory>

namespace antivirus {

/**
 * @interface ILogger
 * @brief Thread-safe logging interface
 * 
 * All implementations must be thread-safe. Logging operations
 * should be non-blocking (async logging preferred).
 */
class ILogger {
public:
    virtual ~ILogger() = default;
    
    /**
     * @brief Log a message at the specified level
     * @param level Log severity level
     * @param message Message to log
     * @param location Source location (auto-captured)
     */
    virtual void Log(
        LogLevel level,
        std::string_view message,
        const std::source_location& location = std::source_location::current()
    ) = 0;
    
    /**
     * @brief Set minimum log level (messages below this are filtered)
     */
    virtual void SetLevel(LogLevel level) = 0;
    
    /**
     * @brief Get current minimum log level
     */
    [[nodiscard]] virtual LogLevel GetLevel() const noexcept = 0;
    
    /**
     * @brief Flush all pending log messages
     */
    virtual void Flush() = 0;
    
    // Convenience methods for each log level
    template<typename... Args>
    void Trace(std::format_string<Args...> fmt, Args&&... args) {
        Log(LogLevel::Trace, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void Debug(std::format_string<Args...> fmt, Args&&... args) {
        Log(LogLevel::Debug, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void Info(std::format_string<Args...> fmt, Args&&... args) {
        Log(LogLevel::Info, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void Warn(std::format_string<Args...> fmt, Args&&... args) {
        Log(LogLevel::Warning, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void Error(std::format_string<Args...> fmt, Args&&... args) {
        Log(LogLevel::Error, std::format(fmt, std::forward<Args>(args)...));
    }
    
    template<typename... Args>
    void Fatal(std::format_string<Args...> fmt, Args&&... args) {
        Log(LogLevel::Fatal, std::format(fmt, std::forward<Args>(args)...));
    }

protected:
    ILogger() = default;
};

using ILoggerPtr = std::shared_ptr<ILogger>;

}  // namespace antivirus
