/**
 * @file LogLevel.hpp
 * @brief Log level definitions
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace antivirus {

/**
 * @enum LogLevel
 * @brief Severity levels for logging
 */
enum class LogLevel : uint8_t {
    Trace = 0,      ///< Very detailed debugging information
    Debug = 1,      ///< Debugging information
    Info = 2,       ///< General information
    Warning = 3,    ///< Warning conditions
    Error = 4,      ///< Error conditions
    Fatal = 5       ///< Fatal errors (application may terminate)
};

/**
 * @brief Convert log level to string
 */
[[nodiscard]] constexpr std::string_view LogLevelToString(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Trace:   return "TRACE";
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error:   return "ERROR";
        case LogLevel::Fatal:   return "FATAL";
        default:                return "UNKNOWN";
    }
}

}  // namespace antivirus
