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
#include "AttestationLibTelemetry.h"

AttestationResult HclReportParser::ExtractSnpReportAndRuntimeDataFromHclReport(const attest::Buffer& hcl_report,
                                                                  attest::Buffer& snp_report,
                                                                  attest::Buffer& runtime_data) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    if (hcl_report.empty()) {
        CLIENT_LOG_ERROR("Empty HCL report");
        result.code_ = AttestationResult::ErrorCode::ERROR_HCL_REPORT_EMPTY;
        result.description_ = std::string("Empty HCL report");
        if (telemetry_reporting.get() != nullptr) {
            telemetry_reporting->UpdateEvent("HCL Report parsing", 
                                                result.description_, 
                                                attest::TelemetryReportingBase::EventLevel::SNP_REPORT_STATUS);
        }
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
        
        if (telemetry_reporting.get() != nullptr) {
            telemetry_reporting->UpdateEvent("HCL Report parsing", 
                                                result.description_, 
                                                attest::TelemetryReportingBase::EventLevel::SNP_REPORT_STATUS);
        }

    }
    return result;
}

AttestationResult HclReportParser::ExtractTdxReportAndRuntimeDataFromHclReport(const attest::Buffer &hcl_report,
                                                                               attest::Buffer &tdx_report,
                                                                               attest::Buffer &runtime_data) {
    AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    if (hcl_report.empty()) {
        CLIENT_LOG_ERROR("Empty HCL report");
        result.code_ = AttestationResult::ErrorCode::ERROR_HCL_REPORT_EMPTY;
        result.description_ = std::string("Empty HCL report");
        return result;
    }
    try {
        ATTESTATION_REPORT *attestation_report = (ATTESTATION_REPORT *)hcl_report.data();
        if (attestation_report == nullptr) {
            result.code_ = AttestationResult::ErrorCode::ERROR_HCL_REPORT_PARSING_FAILURE;
            result.description_ = std::string("Failed to parse TDX report or variable data from the HCL report");
        }

        // Extract tdx report
        auto const tdx_rpt_ptr = reinterpret_cast<unsigned char *>(&attestation_report->HwReport.Report.TdxReport);
        Buffer tdx_rpt(tdx_rpt_ptr, tdx_rpt_ptr + sizeof attestation_report->HwReport.Report.TdxReport);
        tdx_report = tdx_rpt;

        // extract runtime data
        auto const variable_data_ptr = reinterpret_cast<unsigned char *>(&attestation_report->HclData.VariableData);
        Buffer variable_data(variable_data_ptr, variable_data_ptr + attestation_report->HclData.VariableDataSize);
        runtime_data = variable_data;
    }
    catch (...) {
        result.code_ = AttestationResult::ErrorCode::ERROR_HCL_REPORT_PARSING_FAILURE;
        result.description_ = std::string("Failed to parse TDX report or variable data from the HCL report");
    }
    return result;
}

ReportType HclReportParser::GetReportType(const attest::Buffer &hcl_report) {
    if (hcl_report.empty()) {
        CLIENT_LOG_ERROR("Empty HCL report");
        return ReportType::UNDEFINED;
    }
    else {
        ATTESTATION_REPORT *attestation_report = (ATTESTATION_REPORT *)hcl_report.data();
        if (attestation_report == nullptr) {
            CLIENT_LOG_ERROR("Failed to parse report type from HCL report");
            CLIENT_LOG_INFO(std::string(hcl_report.begin(), hcl_report.end()).c_str());

            return ReportType::UNDEFINED;
        }

        if (attestation_report->HclData.ReportType == TdxVmReport) {
            return ReportType::TDX;
        }
        else if (attestation_report->HclData.ReportType == SnpVmReport) {
            return ReportType::SNP;
        }
        else {
            return ReportType::UNDEFINED;
        }
    }

    return ReportType::UNDEFINED;
}