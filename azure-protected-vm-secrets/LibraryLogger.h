// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>
#include <sstream>
#include <array>
#include <type_traits>

namespace SecretsLogger {

    enum LogLevel {
        Debug = 0,
        Info,
        Warning,
        Error
    };

    using LogFunction = void (*) (const char* file,
        const char* function,
        const int line,
        LogLevel logLevel,
        const char* eventName,
        const char* fmt,
        ...);

    extern LogFunction __logger;
    void SetLogger(LogFunction f);

    // Forward declaration for internal implementation
    void __internal_logger(const char *file, const char *function, const int line,
                           LogLevel logLevel, const char *eventName, const std::string &userMessage);

    // Modern C++17 safe string conversion
    template<typename T>
    std::string to_string_safe(T&& value) noexcept {
        try {
            if constexpr (std::is_arithmetic_v<std::decay_t<T>>) {
                return std::to_string(std::forward<T>(value));
            } else if constexpr (std::is_convertible_v<T, std::string>) {
                return std::string(std::forward<T>(value));
            } else if constexpr (std::is_same_v<std::decay_t<T>, const char*> || std::is_same_v<std::decay_t<T>, char*>) {
                return std::string(value ? value : "[null]");
            } else {
                std::ostringstream oss;
                oss << std::forward<T>(value);
                return oss.str();
            }
        } catch (...) {
            return "[conversion_error]";
        }
    }

    // Safe formatting with {} placeholder replacement
    template<typename... Args>
    std::string format_safe(const std::string& format, Args&&... args) noexcept {
        try {
            if constexpr (sizeof...(args) == 0) {
                return format;
            } else {
                std::array<std::string, sizeof...(args)> arg_strings = {
                    to_string_safe(std::forward<Args>(args))...
                };
                
                std::ostringstream result;
                size_t arg_index = 0;
                size_t pos = 0;
                
                while (pos < format.length() && arg_index < arg_strings.size()) {
                    size_t placeholder = format.find("{}", pos);
                    if (placeholder == std::string::npos) break;
                    
                    result << format.substr(pos, placeholder - pos);
                    result << arg_strings[arg_index++];
                    pos = placeholder + 2;
                }
                
                result << format.substr(pos); // Append remainder
                return result.str();
            }
        } catch (...) {
            return "[formatting_error]: " + format;
        }
    }

    // Lightweight template implementation - keep it simple!
    template<typename... Args>
    void __modern_logger(const char* file, const char* function, const int line,
                        LogLevel logLevel, const char* eventName, 
                        const std::string& format, Args&&... args) noexcept {
        try {
            static_assert(sizeof...(args) <= 8, "Too many log arguments - consider restructuring");
            
            std::string message = format_safe(format, std::forward<Args>(args)...);
            __internal_logger(file, function, line, logLevel, eventName, message);
        } catch (...) {
            // Fallback logging if everything fails
            __internal_logger(file, function, line, LogLevel::Error, "Log Error", 
                             "Failed to format log message");
        }
    }

    // Helper function implemented in .cpp file
    template<typename... Args>
    std::string __format_modern(const std::string& format, Args&&... args);
};

#define LIBSECRETS_LOG(logLevel, eventName, ...) \
    SecretsLogger::__logger(__FILE__, __FUNCTION__, __LINE__, logLevel, eventName, __VA_ARGS__)
// New modern macro (uses {} formatting)
#define LIBSECRETS_LOG_MODERN(logLevel, eventName, format, ...) \
    SecretsLogger::__modern_logger(__FILE__, __FUNCTION__, __LINE__, logLevel, eventName, format, __VA_ARGS__)