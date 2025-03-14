#include "pch.h"
#include <stdarg.h>
#include <cstring> // Add this include for strrchr
#include <iostream>
#ifdef PLATFORM_UNIX
#include <systemd/sd-journal.h>
#include <syslog.h>
#else
#include <windows.h>
#endif
#include "LibraryLogger.h"

#define MAX_MESSAGE_SIZE 1024
#define PROVIDER_NAME "Azure-SSPP-Library"
#define LOG_FMT "[%s] - File=%s,Function=%s,Line=%d : %s\n"

#ifdef PLATFORM_UNIX
#define DELIMITER '\/'
#else
#define DELIMITER '\\'
#endif

namespace SecretsLogger {
        
    void __default_logger(const char* file,
        const char* function,
        const int line,
        LogLevel logLevel,
        const char* eventName,
        const char* fmt,
        ...)
    {
#ifdef PLATFORM_UNIX
        int priority = LOG_INFO;
#else
        WORD wType = EVENTLOG_INFORMATION_TYPE;
#endif
        char message[MAX_MESSAGE_SIZE];

        const char* lvl = "";
        switch (logLevel)
        {
        case LogLevel::Debug:
#if (defined _DEBUG) || (defined DEBUG)
            lvl = "[DEBUG]";
#ifdef PLATFORM_UNIX
            priority = LOG_DEBUG;
#endif
#else
            return;
#endif // DEBUG
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
        // Take everything after the last slash
        const char* p = strrchr(file, DELIMITER);
        if (p != NULL)
            file = p + 1;

#ifndef PLATFORM_UNIX
        HANDLE hApplication = OpenEventLogA(NULL, PROVIDER_NAME);
        if (hApplication == NULL)
        {
            fprintf(stderr, "Failed to open event log. error: %d\n", GetLastError());
            return;
        }
#endif
        // Format the message
        va_list args;
        va_list args_copy;
        va_start(args, fmt);
        va_copy(args_copy, args);

        int written = snprintf(
            message,
            MAX_MESSAGE_SIZE,
            LOG_FMT,
            lvl,
            file,
            function,
            line,
            eventName);

        if (written > 0 && written < MAX_MESSAGE_SIZE) {
            vsnprintf(message + written, MAX_MESSAGE_SIZE - written, fmt, args);
        }
        va_end(args_copy);
        va_end(args);

        fprintf(stdout, "%s", message);
        
#ifdef PLATFORM_UNIX
        // Log to systemd journal
        sd_journal_send(
            "PRIORITY=%i", priority,
            "SYSLOG_IDENTIFIER=%s", PROVIDER_NAME,
            "CODE_FILE=%s", file,
            "CODE_FUNC=%s", function,
            "CODE_LINE=%d", line,
            "MESSAGE=%s", message,
            NULL);
#else
        // Log to Windows Event Log
        const char* msg = message;
        ReportEventA(
            hApplication,
            wType,
            0,
            0,
            NULL,
            1,
            0,
            &msg,
            NULL
        );
        CloseEventLog(hApplication);
#endif
    }

    LogFunction __logger = __default_logger;

    void SetLogger(LogFunction f)
    {
        LogFunction __logger = f;
    }
}