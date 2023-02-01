//-------------------------------------------------------------------------------------------------
// <copyright file="AttestationLogger.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once
#include <string>

namespace attest {

    class AttestationLogger {
    public:
        enum LogLevel {
            Error,
            Warn,
            Info,
            Debug
        };

        virtual void Log(const char* log_tag,
                         LogLevel level,
                         const char* function,
                         const int line,
                         const char* fmt,
                         ...) = 0;

        std::string LogLevelStrings[4] = { "Error", "Warn", "Info", "Debug"}; 
    };
} // attest
