//-------------------------------------------------------------------------------------------------
// <copyright file="HclReportParser.cpp" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

#include <iostream>
#include "Logging.h"
#include <stdio.h>
#include "AttestationLibTypes.h"
#include "AttestationParameters.h"
#include "AttestationClient.h"
#include "HclReportParser.h"
#include "VbsVmCrypto.h"

AttestationResult HclReportParser::ExtractSnpReportAndRuntimeDataFromHclReport(const attest::Buffer& hcl_report,
                                                                  attest::Buffer& snp_report,
                                                                  attest::Buffer& runtime_data) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    if (hcl_report.empty()) {
        CLIENT_LOG_ERROR("Empty HCL report");
        result.code_ = AttestationResult::ErrorCode::ERROR_HCL_REPORT_EMPTY;
        result.description_ = std::string("Empty HCL report");
        return result;
    }
    try {
        ATTESTATION_REPORT* attestation_report = (ATTESTATION_REPORT*)hcl_report.data();
        auto const snp_rpt_ptr = reinterpret_cast<unsigned char*>(&attestation_report->HwReport.Report.SnpReport);
        Buffer snp_rpt(snp_rpt_ptr, snp_rpt_ptr + sizeof attestation_report->HwReport.Report.SnpReport);
        snp_report = snp_rpt;

        auto const variable_data_ptr = reinterpret_cast<unsigned char*>(&attestation_report->HclData.VariableData);
        Buffer variable_data(variable_data_ptr, variable_data_ptr + attestation_report->HclData.VariableDataSize);
        runtime_data = variable_data;
    }
    catch (...) {
        result.code_ = AttestationResult::ErrorCode::ERROR_HCL_REPORT_PARSING_FAILURE;
        result.description_ = std::string("Failed to parse SNP report or variable data from the HCL report");
    }
    return result;
}
