/**
 * A simple logging framework to easily swap in different loggers, depending on where 
 * the code is being run.
 */
#pragma once

#include <stdarg.h>
#include <stdio.h>

namespace Tpm2Logger
{
    enum LogLevel
    {
        Info,
        Warn,
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

#define LIBTPM2_LOG(logLevel, eventName, ...) \
    Tpm2Logger::__logger(__FILE__, __FUNCTION__, __LINE__, logLevel, eventName, __VA_ARGS__)

