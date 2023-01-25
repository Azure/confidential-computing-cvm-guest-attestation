//-------------------------------------------------------------------------------------------------
// <copyright file="Logging.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include "Logging.h"

namespace attest {

std::shared_ptr<AttestationLogger> logger;

void SetLogger(const std::shared_ptr<AttestationLogger>& logger) {
    if(attest::logger.get() == nullptr) {
        attest::logger = logger;
    }
}
} // attest
