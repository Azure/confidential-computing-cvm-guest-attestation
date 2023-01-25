//-------------------------------------------------------------------------------------------------
// <copyright file="HclReportParser.h" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#pragma once

#include <stdio.h>
#include "Logging.h"
#include "AttestationLibTypes.h"
#include "AttestationParameters.h"
#include "AttestationClient.h"

class HclReportParser {
public:
    /**
     * @brief This function will be used to extract the SNP report
     * and runtime metadata from the HCL report
     * @param[in] hcl_report The HCL report
     * @param[out] snp_report The SNP report
     * @param[out] runtime_data The runtime metadata
     * @return In case of success, AttestationResult object with error code
     * ErrorCode::Success will be returned.
     * In case of failure, an appropriate ErrorCode will be set in the
     * AttestationResult object and error description will be provided.
     */
    AttestationResult ExtractSnpReportAndRuntimeDataFromHclReport(const attest::Buffer& hcl_report,
                                                     attest::Buffer& snp_report,
                                                     attest::Buffer& runtime_data);
};