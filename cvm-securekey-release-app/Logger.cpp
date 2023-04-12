//-------------------------------------------------------------------------------------------------
// <copyright file="Logger.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <iostream>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <AttestationClient.h>
#include "Logger.h"

void Logger::Log(const char *log_tag,
                 attest::AttestationLogger::LogLevel level,
                 const char *function,
                 const int line,
                 const char *fmt,
                 ...)
{

    // uncomment the below statement and rebuild if details debug logs are needed
    /*
    va_list args;
    va_start(args, fmt);
    size_t len = std::vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    std::vector<char> str(len + 1);

    va_start(args, fmt);
    std::vsnprintf(&str[0], len + 1, fmt, args);
    va_end(args);

    printf("Level: %s Tag: %s %s:%d:%s\n", attest::AttestationLogger::LogLevelStrings[level].c_str(), log_tag, function, line, &str[0]);
    */
}
