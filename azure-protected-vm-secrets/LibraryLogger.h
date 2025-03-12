#pragma once

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

};

#define LIBSECRETS_LOG(logLevel, eventName, ...) \
    SecretsLogger::__logger(__FILE__, __FUNCTION__, __LINE__, logLevel, eventName, __VA_ARGS__)