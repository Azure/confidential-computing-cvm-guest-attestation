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
public:
    void Log(const char *log_tag,
             AttestationLogger::LogLevel level,
             const char *function,
             const int line,
             const char *fmt,
             ...);
};
