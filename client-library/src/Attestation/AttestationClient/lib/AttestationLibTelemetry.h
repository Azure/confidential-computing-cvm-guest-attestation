//-------------------------------------------------------------------------------------------------
// <copyright file="TelemetryReportingBase.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <stdio.h>
#include <stdarg.h>
#include <memory>
#include "TelemetryReportingBase.h"
namespace attest {
    extern std::shared_ptr<TelemetryReportingBase> telemetry_reporting;
}