#include <string.h>

#include "Tpm2Logger.h"

namespace Tpm2Logger {
    void __default_logger(const char* file,
        const char* function,
        const int line,
        LogLevel logLevel,
        const char* eventName,
        const char* fmt,
        ...)
    {
        const char* lvl = "";
        switch (logLevel) 
        {
            case LogLevel::Info:
                lvl = "INFO";
                break;
            case LogLevel::Warn:
                lvl = "WARN";
                break;
            case LogLevel::Error:
                lvl = "ERROR";
                break;
            default: break;
        }

        // Remove the path prefix from the source filename
        // Take everything after the last slash
        const char *p = strrchr(file, '/');
        if (p != NULL)
            file = p + 1;

        va_list args; va_start(args, fmt);
        fprintf(stdout, "%s : File=%s,Function=%s,Line=%d : %s : ",
            lvl,
            file,
            function,
            line,
            eventName);
        vfprintf(stdout, fmt, args);
        fprintf(stdout, "\n");
    }

    LogFunction __logger = __default_logger;

    void SetLogger(LogFunction f)
    {
        LogFunction __logger = f;
    }
}
