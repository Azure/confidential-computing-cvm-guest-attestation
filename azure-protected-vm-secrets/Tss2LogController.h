// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <string>

#ifdef PLATFORM_UNIX
#include <cstdlib>
#else
#include <Windows.h>
#endif

// Log level values for TSS2 libraries
enum class Tss2LogLevel {
    None,       // No logging
    Error,      // Only errors
    Warning,    // Warnings and errors
    Info,       // Info, warnings, and errors
    Debug,      // Debug and all above
    Trace       // Most verbose
};

// Class for TSS2 log control
class Tss2LogController {
private:
    const char* prev_log_value = nullptr;
    
    #ifdef _WIN32
    bool needs_free = false;
    #endif

    // Convert log level enum to string
    std::string LogLevelToString(Tss2LogLevel level) const {
        switch (level) {
            case Tss2LogLevel::None:    return "NONE";
            case Tss2LogLevel::Error:   return "ERROR";
            case Tss2LogLevel::Warning: return "WARNING";
            case Tss2LogLevel::Info:    return "INFO";
            case Tss2LogLevel::Debug:   return "DEBUG";
            case Tss2LogLevel::Trace:   return "TRACE";
            default:                    return "NONE";
        }
    }

public:
    // Constructor - set log level for all modules
    Tss2LogController(Tss2LogLevel level) {
        std::string level_str = LogLevelToString(level);
        std::string value = "all+" + level_str;
        
    #ifdef PLATFORM_UNIX
        // Linux: Save and set
        prev_log_value = getenv("TSS2_LOG");
        setenv("TSS2_LOG", value.c_str(), 1);
    #else
        // Windows: Save and set
        char buffer[1024] = {0};
        size_t len = 0;
        
        getenv_s(&len, buffer, sizeof(buffer), "TSS2_LOG");
        if (len > 0) {
            prev_log_value = _strdup(buffer);
            needs_free = true;
        }
        
        _putenv_s("TSS2_LOG", value.c_str());
    #endif
    }
    
    // Constructor - set custom log spec
    Tss2LogController(const std::string& log_spec) {
    #ifdef PLATFORM_UNIX
        prev_log_value = getenv("TSS2_LOG");
        setenv("TSS2_LOG", log_spec.c_str(), 1);
    #else
        char buffer[1024] = {0};
        size_t len = 0;
        
        getenv_s(&len, buffer, sizeof(buffer), "TSS2_LOG");
        if (len > 0) {
            prev_log_value = _strdup(buffer);
            needs_free = true;
        }
        
        _putenv_s("TSS2_LOG", log_spec.c_str());
    #endif
    }

    // Convenience constructors
    static Tss2LogController SuppressAllLogs() {
        return Tss2LogController(Tss2LogLevel::None);
    }
    
    static Tss2LogController ErrorsPlus() {
        return Tss2LogController(Tss2LogLevel::Error);
    }
    
    // Constructor for fine-grained control of different modules
    static Tss2LogController CustomModuleLevels(const std::string& spec) {
        return Tss2LogController(spec);
    }
    
    // Destructor - restore original log level
    ~Tss2LogController() {
    #ifdef PLATFORM_UNIX
        if (prev_log_value)
            setenv("TSS2_LOG", prev_log_value, 1);
        else
            unsetenv("TSS2_LOG");
    #else
        if (prev_log_value) {
            _putenv_s("TSS2_LOG", prev_log_value);
            if (needs_free)
                free((void*)prev_log_value);
        } else {
            _putenv_s("TSS2_LOG", "");
        }
    #endif
    }
    
    // No copying or moving
    Tss2LogController(const Tss2LogController&) = delete;
    Tss2LogController& operator=(const Tss2LogController&) = delete;
    Tss2LogController(Tss2LogController&&) = delete;
    Tss2LogController& operator=(Tss2LogController&&) = delete;
};
