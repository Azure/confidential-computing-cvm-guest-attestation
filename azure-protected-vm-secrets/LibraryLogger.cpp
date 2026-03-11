// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <stdarg.h>
#include <stdio.h>
#include <cstring> // Add this include for strrchr
#include <iostream>
#include <sstream>
#include <string>
#include <array>
#include <type_traits>
#ifdef PLATFORM_UNIX
#include <systemd/sd-journal.h>
#include <syslog.h>
#else
#include <windows.h>
#endif
#include "LibraryLogger.h"

#define MAX_MESSAGE_SIZE 1024
#define PROVIDER_NAME "Microsoft.Azure.ProtectedVMSecrets"

#ifdef PLATFORM_UNIX
#define DELIMITER '\/'
#else
#define DELIMITER '\\'
#endif

namespace SecretsLogger {

#ifndef PLATFORM_UNIX
// Event ID determination based on context
static DWORD GetEventId(LogLevel logLevel, const char* eventName) {
    // Priority-ordered categories - first match wins
    static const struct { const char* keyword; DWORD baseId; } categories[] = {
        {"Security", 1000}, {"Auth", 1000}, {"Access", 1000},        // Security: 1001, 1010, 1020
        {"Crypto", 1100}, {"Encrypt", 1100}, {"Decrypt", 1100},      // Crypto: 1101, 1110, 1120
        {"Policy", 1200},                                            // Policy: 1201, 1210, 1220
        {"JWT", 1300}, {"Token", 1300},                             // JWT: 1301, 1310, 1320
        {"Parse", 1400},                                            // Parse: 1401, 1410, 1420
        {nullptr, 1500} // Default: 1501, 1510, 1520
    };
    
    DWORD baseId = 1500; // Default
    if (eventName != nullptr) {
        // Find the first matching category
        for (int i = 0; categories[i].keyword; i++) {
            if (strstr(eventName, categories[i].keyword)) {
                baseId = categories[i].baseId;
                break;
            }
        }
    }
    
    switch (logLevel) {
        case LogLevel::Error: return baseId + 1;
        case LogLevel::Warning: return baseId + 10;
        default: return baseId + 20;
    }
}
#endif

// Internal implementation that does the actual system logging
void __internal_logger(const char* file,
                      const char* function,
                      const int line,
                      LogLevel logLevel,
                      const char* eventName,
                      const std::string& userMessage) {
    
#ifdef PLATFORM_UNIX
    int priority = LOG_INFO;
#else
    WORD wType = EVENTLOG_INFORMATION_TYPE;
    DWORD eventId = 1020;
#endif

    const char* lvl = "";
    switch (logLevel) {
        case LogLevel::Debug:
#if (defined _DEBUG) || (defined DEBUG)
            lvl = "[DEBUG]";
#ifdef PLATFORM_UNIX
            priority = LOG_DEBUG;
#endif
#else
            return;
#endif
            break;
        case LogLevel::Info:
            lvl = "[INFO]";
            break;
        case LogLevel::Warning:
            lvl = "[WARNING]";
#ifdef PLATFORM_UNIX
            priority = LOG_WARNING;
#else
            wType = EVENTLOG_WARNING_TYPE;
#endif
            break;
        case LogLevel::Error:
            lvl = "[ERROR]";
#ifdef PLATFORM_UNIX
            priority = LOG_ERR;
#else
            wType = EVENTLOG_ERROR_TYPE;
#endif
            break;
        default: break;
    }

    // Remove the path prefix from the source filename
    const char* p = std::strrchr(file, DELIMITER);
    if (p != nullptr) file = p + 1;

#ifndef PLATFORM_UNIX
    eventId = GetEventId(logLevel, eventName);
#endif

    // Build console message (keep existing format for compatibility)
    // TODO remove output to console in future versions
    std::ostringstream consoleStream;
    consoleStream << "[" << lvl << "] - File=" << file 
                  << ",Function=" << function 
                  << ",Line=" << line 
                  << " : " << eventName << "\n";
    if (!userMessage.empty()) {
        consoleStream << userMessage;
    }
    
    std::string consoleMessage = consoleStream.str();
    
    // Console output
    // Use stderr for CLI (DYNAMIC_SAMPLE) to keep stdout clean for piping.
    // Use stdout for static sample dev/debug builds.
#ifdef DYNAMIC_SAMPLE
    std::cerr << consoleMessage;
#else
    std::cout << consoleMessage;
#endif

#ifdef PLATFORM_UNIX
    // Log to systemd journal with structured data
    sd_journal_send(
        "PRIORITY=%i", priority,
        "SYSLOG_IDENTIFIER=%s", PROVIDER_NAME,
        "CODE_FILE=%s", file,
        "CODE_FUNC=%s", function,
        "CODE_LINE=%d", line,
        "EVENT_NAME=%s", eventName,
        "MESSAGE=%s", userMessage.c_str(),
        NULL);
#else
    // Enhanced Windows Event Log
    std::ostringstream structuredStream;
    structuredStream << "Event: " << eventName << "\n"
                    << "File: " << file << "\n"
                    << "Function: " << function << "\n"
                    << "Line: " << line << "\n"
                    << "Level: " << lvl << "\n"
                    << "Details: " << userMessage;
    
    std::string structuredMessage = structuredStream.str();
    
    
    HANDLE hEventSource = RegisterEventSourceA(nullptr, PROVIDER_NAME);
    if (hEventSource != nullptr) {
        const char* eventStrings[2] = {
            eventName,
            structuredMessage.c_str()
        };
        ReportEventA(
            hEventSource,
            wType,
            1,
            eventId,              // Event ID
            nullptr,
            2,                    // Number of strings
            0,                    // Binary data size
            eventStrings,         // Array of strings
            nullptr                  // Binary data
        );
        DeregisterEventSource(hEventSource);
    }
#endif
}

void __default_logger(const char *file,
                      const char *function,
                      const int line,
                      LogLevel logLevel,
                      const char *eventName,
                      const char *fmt,
                      ...)
{

    try
    {
        std::string userMessage;
        if (fmt && strlen(fmt) > 0)
        {
            va_list args;
            va_start(args, fmt);

            int size = vsnprintf(nullptr, 0, fmt, args);
            va_end(args);

            if (size > 0)
            {
                std::string buffer(size, '\0');
                va_start(args, fmt);
                vsnprintf(&buffer[0], size + 1, fmt, args);
                va_end(args);
                userMessage = buffer;
            }
        }

        __internal_logger(file, function, line, logLevel, eventName, userMessage);
    }
    catch (...)
    {
        __internal_logger(file, function, line, LogLevel::Error, "Log Error",
                          "Failed to format log message");
    }
    }

    LogFunction __logger = __default_logger;

    void SetLogger(LogFunction f)
    {
        __logger = f;
    }
}

