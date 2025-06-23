// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifdef PLATFORM_UNIX
#include "Linux/OsslHKDF.h"
#else
#include <windows.h>
#include "Windows/BcryptHKDF.h"
#endif
#include "HwVmReport.h"
#include "HclReportParser.h"
#include "LibraryLogger.h"
#include "DebugInfo.h"
#include <vector>

using namespace SecretsLogger;

bool HclReportParser::IsValidHclReport(const std::vector<unsigned char>& hclReport) const {
    // Check if the HCL report is valid
    try {
        ATTESTATION_REPORT* attestation_report = (ATTESTATION_REPORT*)hclReport.data();
        std::vector<unsigned char> rpt_data;
		unsigned char* rpt_data_ptr = nullptr;
        switch (attestation_report->HclData.ReportType) {
        case IGVM_REPORT_TYPE::TdxVmReport:
            rpt_data_ptr = reinterpret_cast<unsigned char*>(&attestation_report->HwReport.Report.TdxReport.TdxReportMac.ReportData);
            rpt_data = std::vector<unsigned char>(rpt_data_ptr, rpt_data_ptr + sizeof(attestation_report->HwReport.Report.TdxReport.TdxReportMac.ReportData));
            break;
        case IGVM_REPORT_TYPE::SnpVmReport:
            rpt_data_ptr = reinterpret_cast<unsigned char*>(&attestation_report->HwReport.Report.SnpReport.SnpReportData);
            rpt_data = std::vector<unsigned char>(rpt_data_ptr, rpt_data_ptr + sizeof(attestation_report->HwReport.Report.SnpReport.SnpReportData));
            break;
        default:
            LIBSECRETS_LOG(
                LogLevel::Error,
                "HCL Report Parser",
                "HCL Report hash type is not supported: %d",
                attestation_report->HclData.ReportType
            );
            return false;
        }

        auto const variable_data_ptr = reinterpret_cast<unsigned char*>(&attestation_report->HclData.VariableData);
        std::vector<unsigned char> variable_data(variable_data_ptr, variable_data_ptr + static_cast<size_t>(attestation_report->HclData.VariableDataSize));
        // Check if the report data is the equivalent of the hash of the HCL data
        LIBSECRETS_LOG(
            LogLevel::Debug,
            "HCL Report Parser",
            "HCL Report comparing hash of HCL data with report data: %s, size: %d",
            formatHexBuffer(rpt_data.data(), rpt_data.size()).c_str(),
            rpt_data.size()
        );
        size_t hash_size = 0;
        switch (attestation_report->HclData.ReportDataHashType) {
            case IGVM_HASH_TYPE::Sha256Hash:
                hash_size = SHA256_HASH_SIZE;
                break;
            case IGVM_HASH_TYPE::Sha384Hash:
                hash_size = SHA384_HASH_SIZE;
                break;
            case IGVM_HASH_TYPE::Sha512Hash:
                hash_size = SHA512_HASH_SIZE;
                break;
            default:
                LIBSECRETS_LOG(
                    LogLevel::Error,
                    "HCL Report Parser",
                    "HCL Report hash type is not supported: %d",
                    attestation_report->HclData.ReportDataHashType
                );
                return false;
        }
        std::vector<unsigned char> reportedHash(rpt_data.begin(), rpt_data.begin() + hash_size);
#ifdef PLATFORM_UNIX
        std::vector<unsigned char> report_hash = OsslSha(variable_data, hash_size);
#else
        std::vector<unsigned char> report_hash = BcryptSha(variable_data, hash_size);
#endif
        return (report_hash == reportedHash);
    }
    catch (...) {
        // Handle parsing failure
        return false;
    }
    return true;
}