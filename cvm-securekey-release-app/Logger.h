//-------------------------------------------------------------------------------------------------
// <copyright file="Logger.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <stdarg.h>
#include <AttestationClient.h>

using namespace attest;

class Logger : public AttestationLogger
{
private:
    bool isTraceOn = false;
public:
    Logger() = default;

    Logger(bool isTraceOn){
        this->isTraceOn = isTraceOn;
    }
    
    void Log(const char *log_tag,
             AttestationLogger::LogLevel level,
             const char *function,
             const int line,
             const char *fmt,
             ...);
};
