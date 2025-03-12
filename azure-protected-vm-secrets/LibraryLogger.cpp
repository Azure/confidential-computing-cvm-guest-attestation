#include "pch.h"
#include <stdarg.h>
#include <cstring> // Add this include for strrchr
#include <iostream>
#ifndef PLATFORM_UNIX
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
#ifndef PLATFORM_UNIX
        WORD wType = EVENTLOG_INFORMATION_TYPE;
#endif
        char message[MAX_MESSAGE_SIZE];

        const char* lvl = "";
        switch (logLevel)
        {
        case LogLevel::Debug:
#if (defined _DEBUG) || (defined DEBUG)
            lvl = "[DEBUG]";
#else
            return;
#endif // DEBUG
            break;
        case LogLevel::Info:
            lvl = "[INFO]";
            break;
        case LogLevel::Warning:
            lvl = "[WARNING]";
#ifndef PLATFORM_UNIX
            wType = EVENTLOG_WARNING_TYPE;
#endif
            break;
        case LogLevel::Error:
            lvl = "[ERROR]";
#ifndef PLATFORM_UNIX
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
        va_list args; va_start(args, fmt);
        fprintf(
            stdout,
            LOG_FMT,
            lvl,
            file,
            function,
            line,
            eventName);
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\n");
        
#ifndef PLATFORM_UNIX
        int written = snprintf(
            message,
            MAX_MESSAGE_SIZE, LOG_FMT,
            lvl,
            file,
            function,
            line,
            eventName);

        if (written > 0 && written < MAX_MESSAGE_SIZE) {
            vsnprintf(message + written, MAX_MESSAGE_SIZE - written, fmt, args);
        }
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